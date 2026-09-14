#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
cudy-install.py — install the Linux 6.6 / OpenWrt 24.10 firmware on a
Cudy WR3600 (BCM6764) from your computer, over the network, without UART,
TFTP recovery or the bootloader.

What it does, step by step:

  1. logs into the stock web interface (you give it the admin password);
  2. turns on root SSH on the stock firmware. The stock firmware has no SSH
     switch, but its OpenVPN client runs a "user_up" script as root when a
     tunnel comes up. The script uploads a throw-away OpenVPN profile whose
     user_up installs a fresh SSH key and starts dropbear on port 2222.
     Nothing is flashed at this point and the profile is removed again by
     the reboot at the end;
  3. copies bootfs-release.itb and rootfs.sq to the router;
  4. writes them into slot 1 (UBI volumes bootfs1 / rootfs1) with the stock
     ubiupdatevol and verifies the readback checksum;
  5. makes slot 1 the boot slot (bcm_bootstate +1) and reboots.

Slot 2 (the factory firmware), the bootloader (loader, u-boot) and the board
data (bdinfo) are never written. Rollback: from the stock system
"bcm_bootstate +2 && reboot", or wait for the watchdog fuse, see docs.

Requirements on your computer: Python 3.8+, OpenSSH client (ssh, scp,
ssh-keygen). Linux, macOS and Windows (with OpenSSH installed) work.

Usage:
    python3 cudy-install.py --router 192.168.10.1 --password 'WebUiPassword' \\
        bootfs-release.itb rootfs.sq

    python3 cudy-install.py --router 192.168.10.1 --password ... --ssh-only
        (only turn on root SSH, then stop; e.g. to look around first)

    python3 cudy-install.py ... --slot 2
        (write slot 2 instead — only if you know why)

    python3 cudy-install.py ... --no-commit
        (boot the new firmware ONCE for a trial; the next reboot returns to
        the factory slot. Use this for the very first try.)
"""
import argparse
import hashlib
import http.cookiejar
import os
import re
import secrets
import socket
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "cudy-install/1.0"
SSH_PORT = 2222
SLOT_VOLUMES = {1: ("/dev/ubi0_3", "/dev/ubi0_4"),   # bootfs1, rootfs1
                2: ("/dev/ubi0_5", "/dev/ubi0_6")}   # bootfs2, rootfs2

# Minimal static-key OpenVPN profile. Two hard limits found on hardware:
#   * the stock's OpenVPN rejects option lines longer than 256 characters;
#   * the stock's web UI truncates this value at the first ';', so the hook must
#     chain everything with '&&' only.
# Keep the user_up line under 256 characters (checked below). "remote 127.0.0.1 9" never connects,
# but with a static key the tun device comes up immediately and OpenVPN runs
# the "user_up" hook as root — that is the only thing we need from it.
OVPN_TEMPLATE = """dev tun
proto udp
remote 127.0.0.1 9
ifconfig 10.254.246.1 10.254.246.2
nobind
persist-key
persist-tun
cipher AES-256-CBC
auth SHA256
verb 3
setenv "kk" "{pubkey}"
setenv "user_up" "umask 077&&mkdir -p /etc/dropbear&&echo $kk>/etc/dropbear/authorized_keys&&(test -s /etc/dropbear/h||dropbearkey -t ed25519 -f /etc/dropbear/h)&&dropbear -r /etc/dropbear/h -s -j -k -p {lan_ip}:{port}"
<secret>
-----BEGIN OpenVPN Static key V1-----
{static_key}
-----END OpenVPN Static key V1-----
</secret>
"""


def say(msg):
    print("==> " + msg, flush=True)


def die(msg, code=1):
    print("ERROR: " + msg, file=sys.stderr, flush=True)
    sys.exit(code)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def port_open(host, port, timeout=3):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


# --------------------------------------------------------------------------
# stock web interface (LuCI-based, custom login hashing)
# --------------------------------------------------------------------------
class StockWeb:
    def __init__(self, base, password):
        self.base = base.rstrip("/")
        self.password = password
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def fetch(self, path, data=None, headers=None, timeout=40):
        h = {"User-Agent": UA, "Referer": self.base + "/cgi-bin/luci/"}
        if headers:
            h.update(headers)
        req = urllib.request.Request(self.base + path, data=data, headers=h)
        try:
            with self.op.open(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (urllib.error.URLError, socket.timeout) as e:
            # the "apply" requests can time out while the router reconfigures
            return 0, str(e).encode()

    @staticmethod
    def grab(name, body):
        m = re.search(r'name="%s"[^>]*value="([^"]*)"' % re.escape(name), body)
        return m.group(1) if m else ""

    def login(self):
        st, html = self.fetch("/cgi-bin/luci/")
        if st == 0:
            die("web interface at %s is not reachable" % self.base)
        html = html.decode("utf-8", "replace")
        if "Create an administrator password" in html:
            die("the router is in the first-run wizard: open %s in a browser, "
                "set an admin password, then run this again" % self.base)
        csrf = self.grab("_csrf", html)
        salt = self.grab("salt", html)
        token = self.grab("token", html)
        if not salt:
            die("no login form found — is %s the stock web interface?" % self.base)
        h = hashlib.sha256((self.password + salt).encode()).hexdigest()
        h2 = hashlib.sha256((h + token).encode()).hexdigest()
        data = urllib.parse.urlencode({
            "_csrf": csrf, "salt": salt, "token": token,
            "zonename": "UTC", "timeclock": str(int(time.time())),
            "luci_username": "admin", "luci_password": h2,
        }).encode()
        st, body = self.fetch("/cgi-bin/luci/admin/wizard", data=data,
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
        # The session cookie is the truth. The response body is not: a
        # successful login can be a 302, or a 200 with the setup wizard page
        # (seen on 2.3.16 after the stock config was reset), and that page
        # happens to contain the string "luci_password" too.
        logged_in = any("sysauth" in c.name for c in self.jar)
        if not logged_in:
            # some builds only set the cookie on the redirect; do a sanity GET
            st, body = self.fetch("/cgi-bin/luci/admin/network/vpn/openvpn")
            logged_in = (b'name="salt"' not in body and
                         b"luci_password2" not in body and st == 200)
        if not logged_in:
            die("web login failed — wrong password?")
        say("web login ok")

    @staticmethod
    def multipart(fields, files):
        b = "----CudyInstall" + secrets.token_hex(8)
        out = []
        for k, v in fields.items():
            out += [("--%s\r\n" % b).encode(),
                    ('Content-Disposition: form-data; name="%s"\r\n\r\n' % k).encode(),
                    str(v).encode() + b"\r\n"]
        for k, (fn, content) in files.items():
            out += [("--%s\r\n" % b).encode(),
                    ('Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
                     % (k, fn)).encode(),
                    b"Content-Type: application/octet-stream\r\n\r\n", content, b"\r\n"]
        out.append(("--%s--\r\n" % b).encode())
        return b"".join(out), "multipart/form-data; boundary=" + b

    def run_command(self, command):
        """Run one shell command as root on the stock firmware.

        Documented method (github.com/AkihaZhang/cudy-tr3000-ssh-root, the
        Cudy TR3000 guide; the 4PDA thread points at the same trick): when the
        OpenVPN page regenerates its config it interpolates the profile's
        `remote` value into a shell command, so a value like
        1.2.3.4';<cmd>;# executes <cmd> as root on apply. Unlike the user_up
        hook this does NOT need the stock's VPN client to start - which is the
        failure mode that left the bench unit unreachable (client "not
        connected", hook never fired). Verified on hardware: this is what
        brought the board back.
        """
        packed = command.replace(" ", "${IFS}")   # the generator eats spaces
        ovpn = ("client\ndev tun\nproto udp\nremote 1.2.3.4';%s;# 1194\nverb 3\n"
                % packed).encode()
        st, page = self.fetch("/cgi-bin/luci/admin/network/vpn/openvpn")
        token = self.grab("token", page.decode("utf-8", "replace"))
        form, ctype = self.multipart(
            {"token": token, "cbid.openvpn.client.ovpn.upload": "true"},
            {"cbid.openvpn.client.ovpn": ("payload.ovpn", ovpn)})
        st, _ = self.fetch("/cgi-bin/luci/admin/network/vpn/openvpn", data=form,
                           headers={"Content-Type": ctype})
        if st != 200:
            die("profile upload failed (HTTP %s)" % st)
        st, page = self.fetch("/cgi-bin/luci/admin/network/vpn/openvpn")
        token = self.grab("token", page.decode("utf-8", "replace"))
        data = {"token": token, "timeclock": "", "cbi.submit": "1", "cbi.apply": "1",
                "cbi.rlf.client.ovpn": "", "cbid.openvpn.client.enabled": "0"}
        try:
            self.fetch("/cgi-bin/luci/admin/network/vpn/openvpn",
                       data=urllib.parse.urlencode(data).encode(),
                       headers={"Content-Type": "application/x-www-form-urlencoded"})
        except Exception:
            pass          # long commands can make uhttpd answer 502 after running

    def enable_root_ssh(self, ovpn_bytes):
        # 1. upload the profile
        st, page = self.fetch("/cgi-bin/luci/admin/network/vpn/openvpn")
        token = self.grab("token", page.decode("utf-8", "replace"))
        form, ctype = self.multipart(
            {"token": token, "timeclock": str(int(time.time())), "cbi.submit": "1",
             "cbid.openvpn.client.ovpn.upload": "true"},
            {"cbid.openvpn.client.ovpn": ("cudy-install.ovpn", ovpn_bytes)})
        st, _ = self.fetch("/cgi-bin/luci/admin/network/vpn/openvpn", data=form,
                           headers={"Content-Type": ctype})
        if st not in (200, 302):
            die("profile upload failed (HTTP %s)" % st)
        # 2. enable the VPN client
        st, cfg = self.fetch("/cgi-bin/luci/admin/network/vpn/config?nomodal=")
        token = self.grab("token", cfg.decode("utf-8", "replace"))
        fields = {
            "token": token, "timeclock": str(int(time.time())), "cbi.submit": "1",
            "cbi.apply": "1", "cbi.cbe.vpn.config.enabled": "1",
            "cbid.vpn.config.enabled": "1", "cbid.vpn.config._proto": "openvpn",
            "cbid.vpn.config.policy": "none", "cbid.vpn.config.filter": "allow",
            "cbid.vpn.config.access": "lanwan", "cbid.vpn.config.s2s": "0",
            "cbid.vpn.config.subnet": "", "cbid.vpn.config.domain": "",
            "cbid.vpn.config._dns1": "", "cbid.vpn.config._dns2": "",
        }
        st, resp = self.fetch("/cgi-bin/luci/admin/network/vpn/config?nomodal=",
                              data=urllib.parse.urlencode(fields).encode(),
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
        # 3. (re)start the service — without this the profile is saved but the
        #    tunnel, and therefore user_up, never runs
        m = re.search(r"servicectl/restart/([^'\"]+)", resp.decode("utf-8", "replace"))
        svc = m.group(1) if m else "openvpn,firewall"
        self.fetch("/cgi-bin/luci/admin/servicectl/restart/" + svc,
                   data=urllib.parse.urlencode({"token": token}).encode(),
                   headers={"Content-Type": "application/x-www-form-urlencoded"})


# --------------------------------------------------------------------------
# ssh helpers
# --------------------------------------------------------------------------
class Ssh:
    def __init__(self, host, port, key):
        self.host, self.port, self.key = host, port, key
        self.base = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=" + os.devnull,
                     "-o", "ConnectTimeout=8", "-i", key]

    def run(self, cmd, check=True, timeout=600):
        r = subprocess.run(["ssh"] + self.base + ["-p", str(self.port),
                           "root@" + self.host, cmd],
                           capture_output=True, text=True, timeout=timeout)
        if check and r.returncode != 0:
            die("ssh command failed (%d): %s\n%s" % (r.returncode, cmd, r.stderr.strip()))
        return r

    def scp(self, local, remote):
        # -O: the router's dropbear only speaks the legacy scp protocol
        r = subprocess.run(["scp", "-O"] + self.base + ["-P", str(self.port),
                           local, "root@%s:%s" % (self.host, remote)],
                           capture_output=True, text=True, timeout=1800)
        if r.returncode != 0:
            die("scp failed: %s" % r.stderr.strip())


def to_stock(a):
    """Switch back to the factory firmware from OUR firmware (root SSH on port
    22, password auth). Uses /usr/bin/cudy-update on the router when present
    (2026-09-12+), otherwise writes the slot metadata itself."""
    which_or_die("ssh")
    if not port_open(a.router, 22):
        die("%s:22 does not answer - is the router running this firmware? "
            "(on the factory firmware there is nothing to switch)" % a.router)
    base = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no", "-p", "22", "root@" + a.router]
    if shutil.which("sshpass"):
        cmd = ["sshpass", "-p", a.root_password, "ssh"] + base
    else:
        say("no sshpass on this computer: type the router's root password when asked")
        cmd = ["ssh"] + base
    force = "--force" if a.force else ""
    remote = r"""
if [ -x /usr/bin/cudy-update ]; then exec /usr/bin/cudy-update to-stock %s; fi
dev=$(cat /tmp/.cudy-rootdev 2>/dev/null); [ -n "$dev" ] || dev=$(awk '$2=="/rom"{print $1}' /proc/mounts)
case "$dev" in *ubiblock0_4*) run=1;; *ubiblock0_6*) run=2;; *) echo "cannot tell the running slot"; exit 1;; esac
other=$((3-run)); [ $other = 1 ] && blk=/dev/ubiblock0_4 || blk=/dev/ubiblock0_6
mkdir -p /tmp/ts; mount -t squashfs -o ro $blk /tmp/ts 2>/dev/null || { echo "slot $other is empty"; exit 1; }
if [ -f /tmp/ts/etc/cudy-release ] && [ -z "%s" ]; then umount /tmp/ts; echo "slot $other is not the factory firmware (--force to boot it anyway)"; exit 1; fi
umount /tmp/ts
ubiwrite /dev/ubi0_1 /usr/share/cudy/meta-committed$other.bin >/dev/null && ubiwrite /dev/ubi0_2 /usr/share/cudy/meta-committed$other.bin >/dev/null || { echo "metadata write failed"; exit 1; }
sync; echo "slot $other is now the boot slot, rebooting"; ( sleep 2; reboot ) >/dev/null 2>&1 &
""" % (force, force)
    r = subprocess.run(cmd + [remote], capture_output=True, text=True, timeout=120)
    out = (r.stdout + r.stderr).strip()
    if r.returncode != 0:
        die("router said: " + out)
    say(out)
    say("in about two minutes the factory firmware answers at 192.168.10.1")
    return 0


GROW_SH = r"""
v=%(vol)d; need=%(need)d
d=/sys/class/ubi/ubi0_$v
[ -d "$d" ] || { echo "NODEV"; exit 1; }
leb=$(cat $d/usable_eb_size); ebs=$(cat $d/reserved_ebs)
cap=$((leb * ebs))
if [ "$cap" -ge "$need" ]; then echo "OK $cap"; exit 0; fi
want=$(( (need + leb - 1) / leb ))
add=$((want - ebs))
avail=$(cat /sys/class/ubi/ubi0/avail_eraseblocks 2>/dev/null || echo 0)
if [ "$avail" -lt "$add" ]; then
	echo "NOSPACE $cap $need $add $avail"; exit 1
fi
command -v ubirsvol >/dev/null || { echo "NORSVOL"; exit 1; }
ubirsvol /dev/ubi0 -n $v -S $want || { echo "RSVOLFAIL"; exit 1; }
cap2=$(( $(cat $d/usable_eb_size) * $(cat $d/reserved_ebs) ))
[ "$cap2" -ge "$need" ] || { echo "TOOSMALL $cap2"; exit 1; }
echo "GREW $cap $cap2"
"""


def grow_volume(ssh, vol, need):
    """Grow the UBI volume behind /dev/ubi0_N so `need` bytes fit."""
    vid = int(vol.rsplit("_", 1)[1])
    r = ssh.run(GROW_SH % {"vol": vid, "need": need}, check=False)
    out = (r.stdout + r.stderr).strip()
    first = out.split("\n")[0].split() if out else [""]

    if first[0] == "OK":
        return
    if first[0] == "GREW":
        say("%s grown from %s to %s bytes (our image needs %d)"
            % (vol, first[1], first[2], need))
        return
    if first[0] == "NORSVOL":
        die("%s is too small for our image and this firmware has no ubirsvol to "
            "grow it. Nothing was written." % vol)
    if first[0] == "NOSPACE":
        die("%s holds %s bytes, our image needs %s, and UBI has only %s free "
            "eraseblocks (%s more are required).\n"
            "     Nothing was written. This router's flash layout leaves no room; "
            "please report it in the thread with the output of 'ubinfo -a'."
            % (vol, first[1], first[2], first[4], first[3]))
    die("could not resize %s: %s" % (vol, out))


def which_or_die(prog):
    from shutil import which
    if not which(prog):
        die("'%s' not found — install the OpenSSH client" % prog)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__)
    ap.add_argument("bootfs", nargs="?", help="bootfs-release.itb")
    ap.add_argument("rootfs", nargs="?", help="rootfs.sq")
    ap.add_argument("--router", default="192.168.10.1", help="stock LAN address (default 192.168.10.1)")
    ap.add_argument("--password", help="stock web UI admin password (asked if omitted)")
    ap.add_argument("--slot", type=int, choices=(1, 2), default=1, help="slot to write (default 1)")
    ap.add_argument("--no-commit", action="store_true",
                    help="boot the new slot once (trial); next reboot returns to the other slot")
    ap.add_argument("--ssh-only", action="store_true", help="only enable root SSH and exit")
    ap.add_argument("--key", help="use this private key instead of generating one")
    ap.add_argument("--skip-ssh-setup", action="store_true",
                    help="root SSH on port 2222 is already up (with --key)")
    ap.add_argument("--to-stock", action="store_true",
                    help="the router runs THIS firmware: make the factory slot the boot slot and reboot")
    ap.add_argument("--root-password", default="12345678",
                    help="root password of this firmware for --to-stock (default 12345678)")
    ap.add_argument("--force", action="store_true",
                    help="with --to-stock: boot the other slot even if it is not the factory firmware")
    a = ap.parse_args()

    if a.to_stock:
        return to_stock(a)

    for p in ("ssh", "scp", "ssh-keygen"):
        which_or_die(p)

    if not a.ssh_only:
        if not a.bootfs or not a.rootfs:
            ap.error("bootfs and rootfs files are required (or use --ssh-only)")
        for p in (a.bootfs, a.rootfs):
            if not os.path.isfile(p):
                die("no such file: " + p)
        boot_sha, root_sha = sha256_file(a.bootfs), sha256_file(a.rootfs)
        say("bootfs %s  sha256 %s" % (os.path.basename(a.bootfs), boot_sha[:16]))
        say("rootfs %s  sha256 %s" % (os.path.basename(a.rootfs), root_sha[:16]))
        boot_size = os.path.getsize(a.bootfs)
        if boot_size > 27 * 126976:
            die("bootfs is %d bytes; anything over 27 LEB (%d) does not boot on this board"
                % (boot_size, 27 * 126976))

    # ---- keys -----------------------------------------------------------
    if a.key:
        key = a.key
    else:
        kdir = os.path.join(os.path.expanduser("~"), ".cudy-install")
        os.makedirs(kdir, mode=0o700, exist_ok=True)
        key = os.path.join(kdir, "id_ed25519")
        if not os.path.exists(key):
            subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q",
                            "-C", "cudy-install", "-f", key], check=True)
            say("generated SSH key " + key)
    with open(key + ".pub") as f:
        pubkey = f.read().strip()

    # ---- 1+2: web login, root ssh -----------------------------------------
    if not a.skip_ssh_setup:
        pw = a.password
        if pw is None:
            import getpass
            pw = getpass.getpass("stock web UI admin password: ")
        web = StockWeb("http://" + a.router, pw)
        web.login()
        # SSH may already be up with somebody else's key (a bench unit, or a
        # user who set it up before). Never assume: try our own key first and
        # fall back to installing it through the user_up hook, otherwise the
        # command below fails with "Permission denied (publickey)" - which is
        # exactly what happened on the bench (verified).
        need_bootstrap = True
        if port_open(a.router, SSH_PORT):
            say("root SSH already answers on %s:%d - checking our key"
                % (a.router, SSH_PORT))
            if Ssh(a.router, SSH_PORT, key).run("true", check=False).returncode == 0:
                say("our key is already authorised")
                need_bootstrap = False
        if need_bootstrap:
            static_key = "\n".join(secrets.token_hex(16) for _ in range(16))
            ovpn = OVPN_TEMPLATE.format(pubkey=pubkey, lan_ip=a.router,
                                        port=SSH_PORT, static_key=static_key).encode()
            # Preferred path: the OpenVPN CBI injection (documented Cudy
            # method). It runs the command while the page regenerates its
            # config, so it works even when the VPN client itself refuses to
            # start - the failure that used to make this script unusable.
            # Spaces in the payload become ${IFS} (the generator splits on
            # whitespace, so the value must stay space-free); do NOT use a tab
            # for the key - a tab is a field separator too and truncates the
            # command (verified on hardware).
            key_line = pubkey.replace("'", "")
            # Absolute paths: the injected command runs in the web server's
            # shell, whose PATH is not the login one (the original guide uses
            # absolute paths for the same reason).
            cmd = ("umask 077;/bin/mkdir -p /etc/dropbear;echo %s >/etc/dropbear/authorized_keys;"
                   "/bin/mkdir -p /tmp/cudy-ssh;"
                   "test -s /tmp/cudy-ssh/h||/usr/bin/dropbearkey -t ed25519 -f /tmp/cudy-ssh/h >/dev/null 2>&1;"
                   "/usr/sbin/dropbear -r /tmp/cudy-ssh/h -p %d" % (key_line, SSH_PORT))
            say("installing our key through the OpenVPN config injection")
            web.run_command(cmd)
            probe = Ssh(a.router, SSH_PORT, key)
            for i in range(40):
                if probe.run("true", check=False).returncode == 0:
                    break
                time.sleep(3)
            else:
                die("root SSH did not accept our key on %s:%d.\n"
                    "The OpenVPN config injection is the documented way in, so if it\n"
                    "failed the web UI probably rejected the profile (check the VPN\n"
                    "page) or the dropbear start command did not run. Re-flash the\n"
                    "stock firmware, then run --ssh-only again. (The web password and\n"
                    "the stock firmware itself are fine if the login above succeeded.)"
                    % (a.router, SSH_PORT))
            say("root SSH accepted our key (took ~%d s)" % (i * 3))

    ssh = Ssh(a.router, SSH_PORT, key)
    r = ssh.run("cat /proc/device-tree/model 2>/dev/null; echo; uname -r; "
                "which ubiupdatevol bcm_bootstate; bcm_bootstate 2>&1 | grep -m1 committed",
                check=False)
    out = r.stdout.strip()
    if r.returncode != 0 or "ubiupdatevol" not in out:
        die("cannot run commands over SSH, or ubiupdatevol is missing:\n" + out + "\n" + r.stderr)
    say("router: " + " | ".join(l for l in out.splitlines() if l))
    if "BCM96764" not in out and "6764" not in out:
        die("this does not look like a BCM6764 board (model: %s)" % out.splitlines()[0])
    if a.ssh_only:
        say("done. Connect with: ssh -p %d -i %s root@%s" % (SSH_PORT, key, a.router))
        return

    # ---- 3: copy ----------------------------------------------------------
    say("copying images to /tmp on the router (rootfs is ~24 MB, be patient)")
    ssh.scp(a.bootfs, "/tmp/bootfs.itb")
    ssh.scp(a.rootfs, "/tmp/rootfs.sq")
    r = ssh.run("sha256sum /tmp/bootfs.itb /tmp/rootfs.sq")
    got = dict((l.split()[1], l.split()[0]) for l in r.stdout.splitlines() if l.strip())
    if got.get("/tmp/bootfs.itb") != boot_sha or got.get("/tmp/rootfs.sq") != root_sha:
        die("checksum mismatch after copy:\n" + r.stdout)
    say("copied, checksums match")

    # ---- 4: make sure the volumes are big enough ---------------------------
    # The factory rootfs1 is 184 LEB (23 363 584 bytes) and our rootfs is
    # larger, so a fresh router refuses the write with
    #   "will not fit volume /dev/ubi0_4".
    # UBI can grow a volume in place, and the stock firmware ships ubirsvol,
    # so do that first - before anything is written, so a router that has no
    # free eraseblocks is left exactly as it was.
    bvol, rvol = SLOT_VOLUMES[a.slot]
    for vol, path in ((bvol, a.bootfs), (rvol, a.rootfs)):
        grow_volume(ssh, vol, os.path.getsize(path))

    # ---- 5: write the slot -------------------------------------------------
    say("writing slot %d: %s <- bootfs, %s <- rootfs" % (a.slot, bvol, rvol))
    ssh.run("ubiupdatevol %s /tmp/bootfs.itb && ubiupdatevol %s /tmp/rootfs.sq && sync"
            % (bvol, rvol), timeout=900)
    r = ssh.run("head -c %d %s | sha256sum; head -c %d %s | sha256sum"
                % (boot_size, bvol, os.path.getsize(a.rootfs), rvol), timeout=900)
    back = [l.split()[0] for l in r.stdout.splitlines() if l.strip()]
    if back != [boot_sha, root_sha]:
        die("readback checksum mismatch — NOT switching the boot slot:\n" + r.stdout)
    say("written and verified")

    # ---- 6: boot slot ------------------------------------------------------
    if a.no_commit:
        # ACTIVATE: the next reset boots the non-committed slot exactly once
        ssh.run("bcm_bootstate +%d >/dev/null 2>&1; echo 1 > /proc/bootstate/reset_reason" % a.slot,
                check=False)
        say("slot %d will boot ONCE; the following reboot returns to the committed slot" % a.slot)
    else:
        ssh.run("bcm_bootstate +%d" % a.slot)
        say("slot %d committed as the boot slot" % a.slot)
    r = ssh.run("bcm_bootstate 2>&1 | grep -m1 committed", check=False)
    say("bootstate: " + r.stdout.strip())
    ssh.run("sync; (sleep 1; reboot) >/dev/null 2>&1 &", check=False)
    say("rebooting. In about two minutes the router comes up as Wi-Fi 'CudyWR3600' "
        "(password 12345678), address 192.168.10.1 over Wi-Fi.\n"
        "    Plug your internet cable into the WAN port; LAN1-4 and Wi-Fi are the\n"
        "    home network (192.168.10.1/24). Settings, Wi-Fi and updates: LuCI at\n"
        "    http://192.168.10.1 (root / 12345678 - change it).")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        die("interrupted", 130)

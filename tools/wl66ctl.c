// SPDX-License-Identifier: GPL-2.0-only
/*
 * wl66ctl - talk to the stock Broadcom wl.ko driver's private ioctl interface
 * (the one the vendor "wl" CLI uses) from a small static GPL tool.
 *
 * Why: the blob's cfg80211 wiphy advertises no HT/VHT/HE capabilities, so
 * hostapd/cfg80211 can only bring the AP up at 20 MHz. The factory firmware
 * sets channel width, 11ax and 11be with driver iovars (bw_cap, chanspec, he,
 * eht) through SIOCDEVPRIVATE; this tool speaks exactly that protocol. The
 * numbers below were recovered from the stock CLI/driver, see
 * triaging/wifi-width/WL_IOCTL_SPEC.md. Nothing here is vendor code.
 *
 *   wl66ctl <ifname> ver | magic | up | down | isup | bssid | ssid
 *   wl66ctl <ifname> chanspec [<spec>]          e.g. 36/80, 36/160, 6/40u, 1
 *   wl66ctl <ifname> bw_cap <2g|5g|6g> [<mask>] 0x1=20 0x3=40 0x7=80 0xf=160
 *   wl66ctl <ifname> he|eht <subcmd> [<value>]  enab, features, bssaxmode, ...
 *   wl66ctl <ifname> <int-iovar> [<value>]      nmode, vhtmode, obss_coex, ...
 *   wl66ctl <ifname> getint|setint <iovar> [<value>]
 *   wl66ctl spec <spec>                          encode only, no ioctl (tests)
 *
 * Needs CAP_NET_ADMIN (the driver checks it for every command).
 */
#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SIOCDEVPRIVATE_WL	0x89F0
#define WLC_GET_MAGIC		0
#define WLC_GET_VERSION		1
#define WLC_UP			2
#define WLC_DOWN		3
#define WLC_GET_BSSID		23
#define WLC_GET_SSID		25
#define WLC_GET_UP		162
#define WLC_GET_VAR		262
#define WLC_SET_VAR		263
#define WLC_IOCTL_MAXLEN	16384
#define WLC_IOCTL_SMLEN		256
#define WLC_IOCTL_MAGIC		0x14e46c77u

struct wl_ioctl {
	uint32_t cmd;
	void *buf;
	uint32_t len;
	uint8_t set;
	uint32_t used;
	uint32_t needed;
};

/* chanspec, classic 16-bit layout (this firmware; no "v2" band bits) */
#define WL_CS_CHAN_MASK		0x00ffu
#define WL_CS_SB_SHIFT		8
#define WL_CS_SB_MASK		0x0700u
#define WL_CS_BW_MASK		0x3800u
#define WL_CS_BW_20		0x1000u
#define WL_CS_BW_40		0x1800u
#define WL_CS_BW_80		0x2000u
#define WL_CS_BW_160		0x2800u
#define WL_CS_BW_8080_320	0x3000u
#define WL_CS_BAND_MASK		0xc000u
#define WL_CS_BAND_2G		0x0000u
#define WL_CS_BAND_6G		0x4000u
#define WL_CS_BAND_5G		0xc000u

/* bw_cap band codes */
#define WLC_BAND_5G		1
#define WLC_BAND_2G		2
#define WLC_BAND_6G		4

static const char *ifname;
static int sock = -1;

static int wl_ioctl(uint32_t cmd, void *buf, uint32_t len, int set)
{
	struct ifreq ifr;
	struct wl_ioctl ioc;

	if (sock < 0) {
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock < 0) {
			perror("wl66ctl: socket");
			return -1;
		}
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	memset(&ioc, 0, sizeof(ioc));
	ioc.cmd = cmd;
	ioc.buf = buf;
	ioc.len = len;
	ioc.set = set ? 1 : 0;
	ifr.ifr_data = (void *)&ioc;
	if (ioctl(sock, SIOCDEVPRIVATE_WL, &ifr) < 0) {
		fprintf(stderr, "wl66ctl: %s: ioctl cmd %u: %s\n", ifname, cmd,
			strerror(errno));
		return -1;
	}
	return 0;
}

/* iovar helpers: buf = "name\0" || payload */
static int iovar_set(const char *name, const void *param, size_t plen)
{
	size_t nlen = strlen(name) + 1;
	uint8_t *buf;
	int ret;

	buf = calloc(1, nlen + plen);
	if (!buf)
		return -1;
	memcpy(buf, name, nlen);
	if (plen)
		memcpy(buf + nlen, param, plen);
	ret = wl_ioctl(WLC_SET_VAR, buf, nlen + plen, 1);
	free(buf);
	return ret;
}

/* result lands at buf[0]; *out must hold at least blen bytes */
static int iovar_get(const char *name, const void *param, size_t plen,
		     void *out, size_t outlen, size_t blen)
{
	size_t nlen = strlen(name) + 1;
	uint8_t *buf;
	int ret;

	if (blen < nlen + plen)
		blen = nlen + plen;
	buf = calloc(1, blen);
	if (!buf)
		return -1;
	memcpy(buf, name, nlen);
	if (plen)
		memcpy(buf + nlen, param, plen);
	ret = wl_ioctl(WLC_GET_VAR, buf, blen, 0);
	if (!ret)
		memcpy(out, buf, outlen);
	free(buf);
	return ret;
}

static int iovar_getint(const char *name, uint32_t *v)
{
	return iovar_get(name, NULL, 0, v, sizeof(*v), WLC_IOCTL_SMLEN);
}

static int iovar_setint(const char *name, uint32_t v)
{
	return iovar_set(name, &v, sizeof(v));
}

/* ------------------------------------------------------------------ */
/* chanspec string <-> value                                           */

static const uint8_t c5g40[] = { 38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175 };
static const uint8_t c5g80[] = { 42, 58, 106, 122, 138, 155, 171 };
static const uint8_t c5g160[] = { 50, 114, 163 };

static int sb_of(int center, int prim, int bw)
{
	int low = center - ((bw / 2) - 10) / 5;	/* 40:2 80:6 160:14 */
	int d = prim - low;

	if (d < 0 || d % 4)
		return -1;
	d /= 4;
	return d < bw / 20 ? d : -1;
}

static int parse_uint(const char *s, int *v)
{
	char *e;
	long l = strtol(s, &e, 0);

	if (e == s || l < 0 || l > 0xffff)
		return -1;
	*v = (int)l;
	return (int)(e - s);
}

/*
 * [2g|5g|6g]<primary>[/20 | /40[u|l] | u | l | /80 | /160 | /320[-1|-2]]
 * band defaults to 2G for primary <= 14, else 5G. Returns 0 or -1.
 */
static int chspec_aton(const char *s, uint32_t *out)
{
	uint32_t band = 0, bandset = 0;
	int prim, n, bw = 20, sb = -1, scheme = 1;
	char sbc = 0;

	if (!strncmp(s, "2g", 2)) { band = WL_CS_BAND_2G; bandset = 1; s += 2; }
	else if (!strncmp(s, "5g", 2)) { band = WL_CS_BAND_5G; bandset = 1; s += 2; }
	else if (!strncmp(s, "6g", 2)) { band = WL_CS_BAND_6G; bandset = 1; s += 2; }
	n = parse_uint(s, &prim);
	if (n < 0 || prim == 0 || prim > 255)
		return -1;
	s += n;
	if (!bandset)
		band = prim <= 14 ? WL_CS_BAND_2G : WL_CS_BAND_5G;
	if (*s == 'u' || *s == 'l') {
		bw = 40; sbc = *s++;
	} else if (*s == '/') {
		s++;
		n = parse_uint(s, &bw);
		if (n < 0)
			return -1;
		s += n;
		if (bw == 40 && (*s == 'u' || *s == 'l'))
			sbc = *s++;
		if (bw == 320 && *s == '-') {
			s++;
			n = parse_uint(s, &scheme);
			if (n < 0 || (scheme != 1 && scheme != 2))
				return -1;
			s += n;
		}
	}
	if (*s)
		return -1;

	switch (bw) {
	case 20:
		*out = band | WL_CS_BW_20 | prim;
		return 0;
	case 40: {
		int center;

		if (sbc == 'u') { center = prim - 2; sb = 1; }
		else if (sbc == 'l') { center = prim + 2; sb = 0; }
		else if (band == WL_CS_BAND_5G) {
			size_t i;
			for (i = 0, center = -1; i < sizeof(c5g40); i++)
				if ((sb = sb_of(c5g40[i], prim, 40)) >= 0) { center = c5g40[i]; break; }
			if (center < 0) return -1;
		} else if (band == WL_CS_BAND_6G) {
			center = ((prim - 3) / 8) * 8 + 3;	/* 3 + 8k */
			if ((sb = sb_of(center, prim, 40)) < 0) return -1;
		} else
			return -1;	/* 2G needs u/l */
		if (center < 1 || center > 255) return -1;
		*out = band | WL_CS_BW_40 | ((uint32_t)sb << WL_CS_SB_SHIFT) | center;
		return 0;
	}
	case 80:
	case 160: {
		const uint8_t *tab = bw == 80 ? c5g80 : c5g160;
		size_t ntab = bw == 80 ? sizeof(c5g80) : sizeof(c5g160), i;
		int center = -1;
		uint32_t bwc = bw == 80 ? WL_CS_BW_80 : WL_CS_BW_160;

		if (band == WL_CS_BAND_5G) {
			for (i = 0; i < ntab; i++)
				if ((sb = sb_of(tab[i], prim, bw)) >= 0) { center = tab[i]; break; }
		} else if (band == WL_CS_BAND_6G) {
			int step = bw == 80 ? 16 : 32, base = bw == 80 ? 7 : 15;
			center = ((prim - base) / step) * step + base;
			sb = sb_of(center, prim, bw);
		}
		if (center < 0 || sb < 0) return -1;
		*out = band | bwc | ((uint32_t)sb << WL_CS_SB_SHIFT) | center;
		return 0;
	}
	case 320: {
		int k, c = -1;

		if (band != WL_CS_BAND_6G) return -1;
		for (k = (scheme == 1 ? 0 : 1); k < 6; k += 2) {
			int cc = 31 + 32 * k;
			if (prim >= cc - 30 && prim <= cc + 30) { c = cc; break; }
		}
		if (c < 0) return -1;
		sb = (prim - (c - 30)) / 4;
		if ((prim - (c - 30)) % 4 || sb > 15) return -1;
		*out = WL_CS_BAND_6G | WL_CS_BW_8080_320 | ((uint32_t)sb << 6) | (uint32_t)((c - 31) / 32);
		return 0;
	}
	default:
		return -1;
	}
}

static void chspec_ntoa(uint32_t cs, char *out, size_t n)
{
	uint32_t band = cs & WL_CS_BAND_MASK, bw = cs & WL_CS_BW_MASK;
	int chan = cs & WL_CS_CHAN_MASK, sb = (cs & WL_CS_SB_MASK) >> WL_CS_SB_SHIFT;
	const char *bp = band == WL_CS_BAND_6G ? "6g" : band == WL_CS_BAND_2G ? "2g" : "5g";

	switch (bw) {
	case WL_CS_BW_20:
		snprintf(out, n, "%s%d", bp, chan);
		break;
	case WL_CS_BW_40:
		snprintf(out, n, "%s%d/40%c", bp, chan - 2 + 4 * sb, sb ? 'u' : 'l');
		break;
	case WL_CS_BW_80:
		snprintf(out, n, "%s%d/80", bp, chan - 6 + 4 * sb);
		break;
	case WL_CS_BW_160:
		snprintf(out, n, "%s%d/160", bp, chan - 14 + 4 * sb);
		break;
	case WL_CS_BW_8080_320:
		if (band == WL_CS_BAND_6G) {
			int c = 31 + 32 * (cs & 0x3f), s = (cs >> 6) & 0x1f;
			snprintf(out, n, "6g%d/320", c - 30 + 4 * s);
		} else
			snprintf(out, n, "5g80+80(0x%04x)", cs & 0xffff);
		break;
	default:
		snprintf(out, n, "0x%04x", cs & 0xffff);
	}
}

/* ------------------------------------------------------------------ */
/* he / eht xtlv subcommands                                           */

struct xcmd { const char *name; uint16_t id; uint8_t size; };

static const struct xcmd he_cmds[] = {
	{ "enab", 0x0000, 1 }, { "features", 0x0001, 4 }, { "testbed", 0x0003, 1 },
	{ "bsr", 0x0004, 1 }, { "cap", 0x0007, 1 }, { "range_ext", 0x0009, 1 },
	{ "rtsdurthresh", 0x000a, 2 }, { "peduration", 0x000b, 1 },
	{ "dynfrag", 0x000d, 1 }, { "htc", 0x000f, 4 }, { "bssaxmode", 0x0010, 1 },
	{ "fragtx", 0x0011, 1 }, { "color_collision", 0x0013, 1 },
	{ "bssmudis", 0x001a, 1 }, { NULL, 0, 0 }
};
static const struct xcmd eht_cmds[] = {
	{ "enab", 0x0000, 1 }, { "dbg", 0x1000, 4 }, { "features", 0x0002, 4 },
	{ "bssehtmode", 0x0005, 1 }, { "testbed", 0x0007, 1 },
	{ "epcs_enab", 0x0009, 1 }, { "bssmudis", 0x000d, 1 }, { NULL, 0, 0 }
};

static int xtlv_cmd(const char *iov, const struct xcmd *tab, int argc, char **argv)
{
	const struct xcmd *c;
	uint8_t buf[16];

	if (argc < 1) {
		fprintf(stderr, "wl66ctl: %s: subcommand missing\n", iov);
		return 2;
	}
	for (c = tab; c->name; c++)
		if (!strcmp(c->name, argv[0]))
			break;
	if (!c->name) {
		fprintf(stderr, "wl66ctl: %s: unknown subcommand %s\n", iov, argv[0]);
		return 2;
	}
	if (argc >= 2) {	/* set: u16 id | u16 len | data | pad to 4 */
		long v = strtol(argv[1], NULL, 0);
		size_t plen = 4 + ((c->size + 3) & ~3u);

		memset(buf, 0, sizeof(buf));
		buf[0] = c->id & 0xff; buf[1] = c->id >> 8;
		buf[2] = c->size; buf[3] = 0;
		memcpy(buf + 4, &v, c->size);	/* little-endian host */
		return iovar_set(iov, buf, plen) ? 1 : 0;
	} else {		/* get: u16 id | 4 zero bytes; raw value at buf[0] */
		uint8_t param[6] = { c->id & 0xff, c->id >> 8, 0, 0, 0, 0 };
		uint32_t v = 0;

		if (iovar_get(iov, param, sizeof(param), &v, c->size, WLC_IOCTL_SMLEN))
			return 1;
		printf("%u\n", v);
		return 0;
	}
}

/* ------------------------------------------------------------------ */

static int band_code(const char *s)
{
	if (!strcmp(s, "2g") || !strcmp(s, "2") || !strcmp(s, "b")) return WLC_BAND_2G;
	if (!strcmp(s, "5g") || !strcmp(s, "5") || !strcmp(s, "a")) return WLC_BAND_5G;
	if (!strcmp(s, "6g") || !strcmp(s, "6")) return WLC_BAND_6G;
	return -1;
}

static int usage(void)
{
	fprintf(stderr,
		"usage: wl66ctl <ifname> ver|magic|up|down|isup|bssid|ssid\n"
		"       wl66ctl <ifname> chanspec [<spec>]      36/80 36/160 6/40u 1\n"
		"       wl66ctl <ifname> bw_cap <2g|5g|6g> [<mask>]\n"
		"       wl66ctl <ifname> he|eht <subcmd> [<value>]\n"
		"       wl66ctl <ifname> getint <iovar> | setint <iovar> <value>\n"
		"       wl66ctl <ifname> <int-iovar> [<value>]  (nmode vhtmode obss_coex ...)\n"
		"       wl66ctl spec <spec>                     encode only\n");
	return 2;
}

int main(int argc, char **argv)
{
	const char *cmd;
	char str[32];
	uint32_t v;

	if (argc >= 3 && !strcmp(argv[1], "spec")) {
		if (chspec_aton(argv[2], &v)) {
			fprintf(stderr, "wl66ctl: bad chanspec %s\n", argv[2]);
			return 1;
		}
		chspec_ntoa(v, str, sizeof(str));
		printf("0x%04x %s\n", v & 0xffff, str);
		return 0;
	}
	if (argc < 3)
		return usage();
	ifname = argv[1];
	cmd = argv[2];
	argc -= 3;
	argv += 3;

	if (!strcmp(cmd, "magic")) {
		if (wl_ioctl(WLC_GET_MAGIC, &v, sizeof(v), 0)) return 1;
		printf("magic 0x%08x%s\n", v, v == WLC_IOCTL_MAGIC ? " ok" : " MISMATCH");
		if (wl_ioctl(WLC_GET_VERSION, &v, sizeof(v), 0)) return 1;
		printf("ioctl version %u\n", v);
		return 0;
	}
	if (!strcmp(cmd, "ver")) {
		char buf[WLC_IOCTL_SMLEN];
		if (iovar_get("ver", NULL, 0, buf, sizeof(buf), sizeof(buf))) return 1;
		buf[sizeof(buf) - 1] = 0;
		printf("%s\n", buf);
		return 0;
	}
	if (!strcmp(cmd, "up"))
		return wl_ioctl(WLC_UP, NULL, 0, 1) ? 1 : 0;
	if (!strcmp(cmd, "down"))
		return wl_ioctl(WLC_DOWN, NULL, 0, 1) ? 1 : 0;
	if (!strcmp(cmd, "isup")) {
		if (wl_ioctl(WLC_GET_UP, &v, sizeof(v), 0)) return 1;
		printf("%u\n", v);
		return 0;
	}
	if (!strcmp(cmd, "bssid")) {
		uint8_t m[6];
		if (wl_ioctl(WLC_GET_BSSID, m, sizeof(m), 0)) return 1;
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);
		return 0;
	}
	if (!strcmp(cmd, "ssid")) {
		struct { uint32_t len; char ssid[32]; } s;
		if (wl_ioctl(WLC_GET_SSID, &s, sizeof(s), 0)) return 1;
		if (s.len > 32) s.len = 32;
		printf("%.*s\n", (int)s.len, s.ssid);
		return 0;
	}
	if (!strcmp(cmd, "chanspec")) {
		if (argc >= 1) {
			if (chspec_aton(argv[0], &v)) {
				fprintf(stderr, "wl66ctl: bad chanspec %s\n", argv[0]);
				return 1;
			}
			return iovar_setint("chanspec", v) ? 1 : 0;
		}
		if (iovar_getint("chanspec", &v)) return 1;
		chspec_ntoa(v, str, sizeof(str));
		printf("%s (0x%04x)\n", str, v & 0xffff);
		return 0;
	}
	if (!strcmp(cmd, "bw_cap")) {
		struct { uint32_t band; uint32_t cap; } p;
		int b;

		if (argc < 1 || (b = band_code(argv[0])) < 0) return usage();
		p.band = (uint32_t)b;
		if (argc >= 2) {
			p.cap = (uint32_t)strtoul(argv[1], NULL, 0);
			return iovar_set("bw_cap", &p, sizeof(p)) ? 1 : 0;
		}
		p.cap = 0;
		if (iovar_get("bw_cap", &p, sizeof(p), &v, sizeof(v), WLC_IOCTL_SMLEN)) return 1;
		printf("0x%x\n", v);
		return 0;
	}
	if (!strcmp(cmd, "he"))
		return xtlv_cmd("he", he_cmds, argc, argv);
	if (!strcmp(cmd, "eht"))
		return xtlv_cmd("eht", eht_cmds, argc, argv);
	if (!strcmp(cmd, "getint") || !strcmp(cmd, "setint")) {
		if (argc < 1) return usage();
		cmd = argv[0];
		argc--; argv++;
	}
	/* plain u32 iovar: nmode, vhtmode, obss_coex, maxassoc, ... */
	if (argc >= 1)
		return iovar_setint(cmd, (uint32_t)strtol(argv[0], NULL, 0)) ? 1 : 0;
	if (iovar_getint(cmd, &v)) return 1;
	printf("%u\n", v);
	return 0;
}

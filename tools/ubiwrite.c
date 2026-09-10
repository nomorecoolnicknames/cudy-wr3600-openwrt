// SPDX-License-Identifier: GPL-2.0
/*
 * ubiwrite - minimal ubiupdatevol: replace a UBI volume's content from a file.
 *
 *   ubiwrite <volume-device> <file>        e.g. ubiwrite /dev/ubi0_3 bootfs.itb
 *
 * The OpenWrt release image ships no ubi-utils, so flashing a slot from a
 * running 6.6 system needs this. Only the volume-update ioctl and a plain
 * write are used (UBI_IOCVOLUP takes a pointer to __s64 = image size).
 *
 * Build (static ARM):
 *   arm-buildroot-linux-gnueabi-gcc -static -Os -s -o ubiwrite tools/ubiwrite.c
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Volume ioctls use a different magic than the control-device ioctls:
 * uapi/mtd/ubi-user.h has UBI_IOC_MAGIC 'o' for /dev/ubi_ctrl and
 * UBI_VOL_IOC_MAGIC 'O' for /dev/ubiX_Y. */
#define UBI_VOL_IOC_MAGIC 'O'
#define UBI_IOCVOLUP _IOW(UBI_VOL_IOC_MAGIC, 0, int64_t)

#define CHUNK (1024 * 1024)

int main(int argc, char **argv)
{
	const char *dev, *path;
	struct stat st;
	int64_t bytes;
	int fdin, fdout;
	char *buf;
	ssize_t n;
	int64_t total;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <volume-device> <file>\n", argv[0]);
		return 2;
	}
	dev = argv[1];
	path = argv[2];

	if (stat(path, &st) || !S_ISREG(st.st_mode)) {
		fprintf(stderr, "ubiwrite: %s: not a regular file\n", path);
		return 1;
	}
	bytes = st.st_size;
	if (bytes <= 0) {
		fprintf(stderr, "ubiwrite: %s: empty\n", path);
		return 1;
	}

	fdin = open(path, O_RDONLY);
	if (fdin < 0) {
		perror("ubiwrite: open file");
		return 1;
	}
	fdout = open(dev, O_RDWR);
	if (fdout < 0) {
		perror("ubiwrite: open volume");
		return 1;
	}
	if (ioctl(fdout, UBI_IOCVOLUP, &bytes) < 0) {
		fprintf(stderr, "ubiwrite: %s: UBI_IOCVOLUP(%lld): %s\n",
			dev, (long long)bytes, strerror(errno));
		return 1;
	}

	buf = malloc(CHUNK);
	if (!buf) {
		fprintf(stderr, "ubiwrite: out of memory\n");
		return 1;
	}
	total = 0;
	while ((n = read(fdin, buf, CHUNK)) > 0) {
		ssize_t off = 0;

		while (off < n) {
			ssize_t w = write(fdout, buf + off, n - off);

			if (w < 0) {
				fprintf(stderr, "ubiwrite: write: %s\n", strerror(errno));
				return 1;
			}
			off += w;
		}
		total += n;
	}
	if (n < 0) {
		fprintf(stderr, "ubiwrite: read: %s\n", strerror(errno));
		return 1;
	}
	if (total != bytes) {
		fprintf(stderr, "ubiwrite: short write: %lld of %lld bytes\n",
			(long long)total, (long long)bytes);
		return 1;
	}
	/* The UBI volume-update ioctl completes on close(), so flush first and
	 * only then report success - a full volume used to look like a pass
	 * (review S2-13). */
	if (fsync(fdout) && errno != EINVAL) {
		fprintf(stderr, "ubiwrite: fsync: %s\n", strerror(errno));
		return 1;
	}
	if (close(fdout)) {
		fprintf(stderr, "ubiwrite: close: %s\n", strerror(errno));
		return 1;
	}
	if (close(fdin)) {
		fprintf(stderr, "ubiwrite: close input: %s\n", strerror(errno));
		return 1;
	}
	printf("ubiwrite: %s <- %s (%lld bytes) ok\n", dev, path, (long long)bytes);
	return 0;
}

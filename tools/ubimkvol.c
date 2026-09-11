// SPDX-License-Identifier: GPL-2.0-only
/*
 * ubimkvol - create (or grow) a dynamic UBI volume; see tools/ubiwrite.c.
 *
 * The release keeps its persistent settings in a UBI volume of its own
 * ("cudy66_data") which the preinit mounts as UBIFS; the kernel formats an
 * empty volume on the first mount, so creating it is all that is needed.
 * The stock firmware's rootfs_data volume belongs to the factory system and is
 * deliberately never touched.
 *
 *   ubimkvol <ubiN> <name> <bytes>       e.g. ubimkvol ubi0 cudy66_data 4194304
 *
 * Prints the volume id. Existing volume: left alone if big enough, grown
 * otherwise.
 */
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/*
 * The UBI ABI, spelled out here on purpose: pulling in the kernel uapi headers
 * needs a generated include tree, and tools/ubiwrite.c already does the same.
 */
#define UBI_CTRL_IOC_MAGIC 'o'
#define UBI_IOCMKVOL _IOW(UBI_CTRL_IOC_MAGIC, 0, struct ubi_mkvol_req)
#define UBI_IOCRSVOL _IOW(UBI_CTRL_IOC_MAGIC, 2, struct ubi_rsvol_req)
#define UBI_MAX_VOLUME_NAME 127
#define UBI_VOL_NUM_AUTO (-1)
#define UBI_DYNAMIC_VOLUME 3

struct ubi_mkvol_req {
	int32_t vol_id;
	int32_t alignment;
	int64_t bytes;
	int8_t vol_type;
	uint8_t flags;
	int16_t name_len;
	int8_t padding2[4];
	char name[UBI_MAX_VOLUME_NAME + 1];
} __attribute__((packed));

struct ubi_rsvol_req {
	int64_t bytes;
	int32_t vol_id;
} __attribute__((packed));

static int read_attr(const char *ubiname, int id, const char *attr, char *buf, size_t len)
{
	char path[128];
	FILE *f;
	size_t n;

	snprintf(path, sizeof(path), "/sys/class/ubi/%s_%d/%s", ubiname, id, attr);
	f = fopen(path, "r");
	if (!f)
		return -1;
	if (!fgets(buf, len, f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	n = strlen(buf);
	if (n && buf[n - 1] == '\n')
		buf[n - 1] = 0;
	return 0;
}

int main(int argc, char **argv)
{
	struct ubi_mkvol_req req;
	const char *ubiname, *name;
	unsigned long long bytes;
	char path[64], dev[64];
	char volname[UBI_MAX_VOLUME_NAME + 2];
	int id, fd, ctl;

	if (argc != 4) {
		fprintf(stderr, "usage: %s <ubiN> <name> <bytes>\n", argv[0]);
		return 2;
	}
	ubiname = argv[1];
	name = argv[2];
	bytes = strtoull(argv[3], NULL, 0);
	if (strncmp(ubiname, "ubi", 3) || !bytes ||
	    strlen(name) >= UBI_MAX_VOLUME_NAME) {
		fprintf(stderr, "ubimkvol: bad arguments\n");
		return 2;
	}
	snprintf(dev, sizeof(dev), "/dev/%s", ubiname);

	/* existing volume? */
	for (id = 0; id < 128; id++) {
		unsigned long long cur;
		char sz[32];

		snprintf(path, sizeof(path), "/sys/class/ubi/%s_%d", ubiname, id);
		if (access(path, F_OK))
			continue;
		snprintf(volname, sizeof(volname), "%s_%d", ubiname, id);
		snprintf(path, sizeof(path), "/sys/class/ubi/%s_%d/name", ubiname, id);
		{
			FILE *f = fopen(path, "r");
			if (!f)
				continue;
			if (!fgets(volname, sizeof(volname), f)) {
				fclose(f);
				continue;
			}
			fclose(f);
			volname[strcspn(volname, "\n")] = 0;
		}
		if (strcmp(volname, name))
			continue;
		if (read_attr(ubiname, id, "data_bytes", sz, sizeof(sz))) {
			/* fall back: assume it is fine */
			printf("%d\n", id);
			return 0;
		}
		cur = strtoull(sz, NULL, 0);
		if (cur >= bytes) {
			printf("%d\n", id);
			return 0;
		}
		/* UBI_IOCRSVOL is a UBI-device ioctl (/dev/ubiN), not a volume one */
		fd = open(dev, O_RDWR);
		if (fd < 0) {
			fprintf(stderr, "ubimkvol: open %s: %s\n", dev, strerror(errno));
			return 1;
		}
		{
			struct ubi_rsvol_req rs = { .bytes = bytes, .vol_id = id };
			if (ioctl(fd, UBI_IOCRSVOL, &rs) < 0) {
				fprintf(stderr, "ubimkvol: resize %s vol %d to %llu: %s\n",
					dev, id, bytes, strerror(errno));
				close(fd);
				return 1;
			}
		}
		close(fd);
		printf("%d\n", id);
		return 0;
	}

	ctl = open(dev, O_RDWR);
	if (ctl < 0) {
		fprintf(stderr, "ubimkvol: open %s: %s\n", dev, strerror(errno));
		return 1;
	}
	memset(&req, 0, sizeof(req));
	req.vol_type = UBI_DYNAMIC_VOLUME;
	req.vol_id = UBI_VOL_NUM_AUTO;
	req.alignment = 1;
	req.bytes = bytes;
	snprintf(req.name, sizeof(req.name), "%s", name);
	/* the kernel checks strnlen(name, name_len + 1) == name_len */
	req.name_len = strlen(name);
	if (ioctl(ctl, UBI_IOCMKVOL, &req) < 0) {
		fprintf(stderr, "ubimkvol: create %s: %s\n", name, strerror(errno));
		close(ctl);
		return 1;
	}
	printf("%d\n", req.vol_id);
	close(ctl);
	return 0;
}

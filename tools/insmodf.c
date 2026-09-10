// SPDX-License-Identifier: GPL-2.0
/*
 * insmodf - insmod that can force-load a module, for the router.
 *
 * Needed because busybox insmod (all we have on the OpenWrt image) has no -f,
 * and the stock BCA blobs are built without CONFIG_MODVERSIONS while our 6.6
 * kernel has it on: without MODULE_INIT_IGNORE_MODVERSIONS the loader rejects
 * them with "no symbol version for ...". The kernel honours these flags only
 * with CONFIG_MODULE_FORCE_LOAD=y, which this kernel has.
 *
 *   insmodf <module.ko> [module params...]
 *
 * Build (static, so libc on the router does not matter):
 *   arm-buildroot-linux-gnueabi-gcc -static -Os -o insmodf tools/insmodf.c
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

#ifndef MODULE_INIT_IGNORE_MODVERSIONS
#define MODULE_INIT_IGNORE_MODVERSIONS	1
#endif
#ifndef MODULE_INIT_IGNORE_VERMAGIC
#define MODULE_INIT_IGNORE_VERMAGIC	2
#endif

int main(int argc, char **argv)
{
	char args[1024] = "";
	int fd, i;

	if (argc < 2) {
		fprintf(stderr, "usage: insmodf <module.ko> [params...]\n");
		return 2;
	}

	for (i = 2; i < argc; i++) {
		if (args[0])
			strncat(args, " ", sizeof(args) - strlen(args) - 1);
		strncat(args, argv[i], sizeof(args) - strlen(args) - 1);
	}

	fd = open(argv[1], O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "insmodf: open %s: %s\n", argv[1], strerror(errno));
		return 1;
	}

	if (syscall(__NR_finit_module, fd, args,
		    MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC)) {
		fprintf(stderr, "insmodf: %s: %s\n", argv[1], strerror(errno));
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}

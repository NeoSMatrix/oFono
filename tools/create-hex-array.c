/*
 *
 *  Multimedia Messaging Service
 *
 *  Copyright (C) 2010  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

static int dump_file(const char *pathname)
{
	struct stat st;
	unsigned char *map;
	size_t size, i;
	int fd;

	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}

	size = st.st_size;

	map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (!map || map == MAP_FAILED) {
		close(fd);
		return -1;
	}

	printf("static const unsigned char msg[] = {");

	for (i = 0; i < size; i++) {
		if ((i % 8) == 0)
			printf("\n\t\t\t\t");
		printf("0x%02X, ", map[i]);
	}

	printf("\n};\n");

	munmap(map, size);

	close(fd);

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Missing input\n");
		return 1;
	}

	if (dump_file(argv[1]) < 0) {
		fprintf(stderr, "Failed to open file\n");
		return 1;
	}

	return 0;
}

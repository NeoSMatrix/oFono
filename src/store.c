/*
 *
 *  Multimedia Messaging Service
 *
 *  Copyright (C) 2010-2011  Intel Corporation. All rights reserved.
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
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "mms.h"

#define MMS_SHA1_UUID_LEN 20

static const char *digest_to_str(const unsigned char *digest)
{
	static char buf[MMS_SHA1_UUID_LEN * 2 + 1];
	unsigned int i;

	for (i = 0; i < MMS_SHA1_UUID_LEN; i++)
		sprintf(&buf[i * 2], "%02X", digest[i]);

	buf[MMS_SHA1_UUID_LEN * 2] = 0;

	return buf;
}

static int create_dirs(const char *filename, const mode_t mode)
{
	struct stat st;
	char *dir;
	const char *prev, *next;
	int err;

	if (filename[0] != '/')
		return -1;

	err = stat(filename, &st);
	if (!err && S_ISREG(st.st_mode))
		return 0;

	dir = g_try_malloc(strlen(filename) + 1);
	if (dir == NULL)
		return -1;

	strcpy(dir, "/");

	for (prev = filename; (next = strchr(prev + 1, '/')); prev = next) {
		/* Skip consecutive '/' characters */
		if (next - prev == 1)
			continue;

		strncat(dir, prev + 1, next - prev);

		if (mkdir(dir, mode) == -1 && errno != EEXIST) {
			g_free(dir);
			return -1;
		}
	}

	g_free(dir);
	return 0;
}


static const char *generate_uuid_from_pdu(unsigned char *pdu, unsigned int len)
{
	GChecksum *checksum;
	guint8 digest[MMS_SHA1_UUID_LEN];
	gsize digest_size = MMS_SHA1_UUID_LEN;

	DBG("pdu %p len %d", pdu, len);

	checksum = g_checksum_new(G_CHECKSUM_SHA1);
	if (checksum == NULL)
		return NULL;

	g_checksum_update(checksum, pdu, len);

	g_checksum_get_digest(checksum, digest, &digest_size);

	g_checksum_free(checksum);

	return digest_to_str(digest);
}

static GString *generate_pdu_pathname(const char *service_id, const char *uuid)
{
	GString *pathname;
	const char *homedir;

	homedir = g_get_home_dir();
	if (homedir == NULL)
		return NULL;

	pathname = g_string_new(homedir);

	g_string_append_printf(pathname, "/.mms/%s/", service_id);

	g_string_append(pathname, uuid);

	DBG("pathname %s", pathname->str);

	if (create_dirs(pathname->str, S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
		mms_error("Failed to create path %s", pathname->str);

		g_string_free(pathname, TRUE);
		return NULL;
	}

	return pathname;
}

const char *mms_store(const char *service_id, unsigned char *pdu,
							unsigned int len)
{
	GString *pathname;
	const char *uuid;
	ssize_t size;
	int fd;

	uuid = generate_uuid_from_pdu(pdu, len);
	if (uuid == NULL)
		return NULL;

	pathname = generate_pdu_pathname(service_id, uuid);
	if (pathname == NULL)
		return NULL;

	fd = open(pathname->str, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR);
	if (fd < 0) {
		mms_error("Failed to open %s", pathname->str);
		uuid = NULL;
		goto done;
	}

	size = write(fd, pdu, len);
	if (size < 0)
		mms_error("Failed to write to %s", pathname->str);

	fdatasync(fd);

	close(fd);

done:
	g_string_free(pathname, TRUE);

	return uuid;
}

const char *mms_store_file(const char *service_id, const char *path)
{
	GString *pathname;
	const char *uuid;
	int fd;
	struct stat st;
	unsigned char *pdu;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		mms_error("Failed to open %s\n", path);
		return NULL;
	}

	if (fstat(fd, &st) < 0) {
		mms_error("Failed to fstat %s\n", path);
		close(fd);
		return NULL;
	}

	pdu = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (pdu == NULL || pdu == MAP_FAILED) {
		mms_error("Failed to mmap %s\n", path);
		close(fd);
		return NULL;
	}

	uuid = generate_uuid_from_pdu(pdu, st.st_size);

	munmap(pdu, st.st_size);

	close(fd);

	if (uuid == NULL)
		return NULL;

	pathname = generate_pdu_pathname(service_id, uuid);
	if (pathname == NULL)
		return NULL;

	if (g_rename(path, pathname->str) < 0) {
		mms_error("Failed to rename %s to %s\n", path, pathname->str);

		uuid = NULL;
	}

	g_string_free(pathname, TRUE);

	return uuid;
}

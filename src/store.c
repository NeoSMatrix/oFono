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

#ifdef TEMP_FAILURE_RETRY
#define TFR TEMP_FAILURE_RETRY
#else
#define TFR
#endif

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

char *mms_store_get_path(const char *service_id, const char *uuid)
{
	const char *homedir;

	homedir = g_get_home_dir();
	if (homedir == NULL)
		return NULL;

	return g_strdup_printf("%s/.mms/%s/%s", homedir, service_id, uuid);
}

static char *generate_pdu_pathname(const char *service_id, const char *uuid)
{
	char *pathname;

	pathname = mms_store_get_path(service_id, uuid);
	if (pathname == NULL)
		return NULL;

	if (create_dirs(pathname, S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
		mms_error("Failed to create path %s", pathname);

		g_free(pathname);
		return NULL;
	}

	return pathname;
}

/*
 * Write a buffer to a file in a transactionally safe form
 *
 * Given a buffer, write it to a file named after
 * @filename. However, to make sure the file contents are
 * consistent (ie: a crash right after opening or during write()
 * doesn't leave a file half baked), the contents are written to a
 * file with a temporary name and when closed, it is renamed to the
 * specified name (@filename).
 */
static ssize_t write_file(const unsigned char *buffer, size_t len,
							const char *filename)
{
	char *tmp_file;
	ssize_t written;
	int fd;

	tmp_file = g_strdup_printf("%s.XXXXXX.tmp", filename);

	written = -1;

	fd = TFR(g_mkstemp_full(tmp_file, O_WRONLY | O_CREAT | O_TRUNC,
							S_IWUSR | S_IRUSR));
	if (fd < 0)
		goto error_mkstemp_full;

	written = TFR(write(fd, buffer, len));

	TFR(fdatasync(fd));

	TFR(close(fd));

	if (written != (ssize_t) len) {
		written = -1;
		goto error_write;
	}

	/*
	 * Now that the file contents are written, rename to the real
	 * file name; this way we are uniquely sure that the whole
	 * thing is there.
	 */
	unlink(filename);

	/* conserve @written's value from 'write' */
	if (link(tmp_file, filename) == -1)
		written = -1;

error_write:
	unlink(tmp_file);

error_mkstemp_full:
	g_free(tmp_file);

	return written;
}

const char *mms_store(const char *service_id, unsigned char *pdu,
							unsigned int len)
{
	char *pathname;
	const char *uuid;

	uuid = generate_uuid_from_pdu(pdu, len);
	if (uuid == NULL)
		return NULL;

	pathname = generate_pdu_pathname(service_id, uuid);
	if (pathname == NULL)
		return NULL;

	if (write_file(pdu, len, pathname) < 0) {
		mms_error("Failed to write to %s", pathname);

		uuid = NULL;
	}

	DBG("pathname %s", pathname);

	g_free(pathname);

	return uuid;
}

const char *mms_store_file(const char *service_id, const char *path)
{
	char *pathname;
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

	if (g_rename(path, pathname) < 0) {
		mms_error("Failed to rename %s to %s\n", path, pathname);

		uuid = NULL;
	}

	DBG("pathname %s", pathname);

	g_free(pathname);

	return uuid;
}

void mms_store_remove(const char *service_id, const char *uuid)
{
	char *pdu_path;
	char *meta_path;

	pdu_path = mms_store_get_path(service_id, uuid);
	if (pdu_path == NULL)
		return;

	unlink(pdu_path);

	meta_path = g_strdup_printf("%s%s", pdu_path, ".status");

	g_free(pdu_path);

	unlink(meta_path);

	g_free(meta_path);
}

GKeyFile *mms_store_meta_open(const char *service_id, const char *uuid)
{
	GKeyFile *keyfile;
	char *pdu_path;
	char *meta_path;

	pdu_path = generate_pdu_pathname(service_id, uuid);
	if (pdu_path == NULL)
		return NULL;

	meta_path = g_strdup_printf("%s%s", pdu_path, ".status");

	g_free(pdu_path);

	keyfile = g_key_file_new();

	g_key_file_load_from_file(keyfile, meta_path, 0, NULL);

	g_free(meta_path);

	return keyfile;
}

static void meta_store_sync(const char *service_id, const char *uuid,
							GKeyFile *keyfile)
{
	char *data;
	gsize length = 0;
	char *pdu_path;
	char *meta_path;

	pdu_path = mms_store_get_path(service_id, uuid);
	if (pdu_path == NULL)
		return;

	meta_path = g_strdup_printf("%s%s", pdu_path, ".status");

	g_free(pdu_path);

	data = g_key_file_to_data(keyfile, &length, NULL);

	g_file_set_contents(meta_path, data, length, NULL);

	g_free(data);

	g_free(meta_path);
}

void mms_store_meta_close(const char *service_id, const char *uuid,
					GKeyFile *keyfile, gboolean save)
{
	if (save == TRUE)
		meta_store_sync(service_id, uuid, keyfile);

	g_key_file_free(keyfile);
}

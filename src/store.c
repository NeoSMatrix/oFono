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

#include <glib.h>

#include "mms.h"

void mms_store(unsigned char *pdu, unsigned int len)
{
	GChecksum *checksum;
	guint8 uuid[20];
	gsize uuid_size = sizeof(uuid);
	GString *pathname;
	const char *homedir;
	unsigned int i;
	ssize_t size;
	int fd;

	DBG("pdu %p len %d", pdu, len);

	checksum = g_checksum_new(G_CHECKSUM_SHA1);
	if (checksum == NULL)
		return;

	g_checksum_update(checksum, pdu, len);

	g_checksum_get_digest(checksum, uuid, &uuid_size);

	g_checksum_free(checksum);

	homedir = g_get_home_dir();
	if (homedir == NULL)
		return;

	pathname = g_string_new(homedir);

	g_string_append(pathname, "/.mms/");

	for (i = 0; i < uuid_size; i++)
		g_string_append_printf(pathname, "%02X", uuid[i]);

	DBG("pathname %s", pathname->str);

	fd = open(pathname->str, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR);
	if (fd < 0) {
		mms_error("Failed to open %s", pathname->str);
		goto done;
	}

	size = write(fd, pdu, len);

	fdatasync(fd);

	close(fd);

done:
	g_string_free(pathname, TRUE);
}

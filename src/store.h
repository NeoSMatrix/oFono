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

#define MMS_SHA1_UUID_LEN 20
#define MMS_META_UUID_SUFFIX ".status"
#define MMS_META_UUID_SUFFIX_LEN 7
#define MMS_META_UUID_LEN (MMS_SHA1_UUID_LEN * 2)

const char *mms_store(const char *service_id, unsigned char *pdu,
							unsigned int len);
const char *mms_store_file(const char *service_id, const char *path);
void mms_store_remove(const char *service_id, const char *uuid);
char *mms_store_get_path(const char *service_id, const char *uuid);

GKeyFile *mms_store_meta_open(const char *service_id, const char *uuid);
void mms_store_meta_close(const char *service_id, const char *uuid,
					GKeyFile *keyfile, gboolean save);

GKeyFile *mms_settings_open(const char *service_id, const char *store);
void mms_settings_close(const char *service_id, const char *store,
					GKeyFile *keyfile, gboolean save);

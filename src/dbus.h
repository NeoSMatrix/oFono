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

#include <dbus/dbus.h>

#define MMS_SERVICE	"org.ofono.mms"
#define MMS_PATH	"/org/ofono/mms"

#define MMS_MANAGER_INTERFACE	MMS_SERVICE ".Manager"
#define MMS_SERVICE_INTERFACE	MMS_SERVICE ".Service"

#define MMS_ERROR_INTERFACE	MMS_SERVICE ".Error"

DBusConnection *mms_dbus_get_connection(void);

void mms_dbus_property_append_basic(DBusMessageIter *iter,
					const char *key, int type, void *val);

static inline void mms_dbus_dict_open(DBusMessageIter *iter,
						DBusMessageIter *dict)
{
	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, dict);
}

static inline void mms_dbus_dict_close(DBusMessageIter *iter,
						DBusMessageIter *dict)
{
	dbus_message_iter_close_container(iter, dict);
}

static inline void mms_dbus_dict_append_basic(DBusMessageIter *dict,
					const char *key, int type, void *val)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);
	mms_dbus_property_append_basic(&entry, key, type, val);
	dbus_message_iter_close_container(dict, &entry);
}

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

#include <gdbus.h>

#include "mms.h"

static DBusConnection *connection;

DBusConnection *mms_dbus_get_connection(void)
{
	return connection;
}

void __mms_dbus_set_connection(DBusConnection *conn)
{
	connection = conn;
}

void mms_dbus_property_append_basic(DBusMessageIter *iter,
					const char *key, int type, void *val)
{
	DBusMessageIter value;
	const char *signature;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &key);

	switch (type) {
	case DBUS_TYPE_BOOLEAN:
		signature = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case DBUS_TYPE_STRING:
		signature = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_BYTE:
		signature = DBUS_TYPE_BYTE_AS_STRING;
		break;
	case DBUS_TYPE_UINT16:
		signature = DBUS_TYPE_UINT16_AS_STRING;
		break;
	case DBUS_TYPE_INT16:
		signature = DBUS_TYPE_INT16_AS_STRING;
		break;
	case DBUS_TYPE_UINT32:
		signature = DBUS_TYPE_UINT32_AS_STRING;
		break;
	case DBUS_TYPE_INT32:
		signature = DBUS_TYPE_INT32_AS_STRING;
		break;
	case DBUS_TYPE_OBJECT_PATH:
		signature = DBUS_TYPE_OBJECT_PATH_AS_STRING;
		break;
	default:
		signature = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
							signature, &value);
	dbus_message_iter_append_basic(&value, type, val);
	dbus_message_iter_close_container(iter, &value);
}

DBusMessage *__mms_error_invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg, MMS_ERROR_INTERFACE
				".InvalidArguments",
				"Invalid arguments in method call");
}

DBusMessage *__mms_error_unsupported_message(DBusMessage *msg)
{
	return g_dbus_create_error(msg, MMS_ERROR_INTERFACE
				".UnsupportedMessage",
				"The MMSC does not support the request");
}

DBusMessage *__mms_error_trans_failure(DBusMessage *msg)
{
	return g_dbus_create_error(msg, MMS_ERROR_INTERFACE
				".TransientFailure",
				"Request is valid but the MMSC is unable to "
				"process it due to some temporary conditions");
}

DBusMessage *__mms_error_trans_network_problem(DBusMessage *msg)
{
	return g_dbus_create_error(msg, MMS_ERROR_INTERFACE
				".TransientNetworkProblem",
				"The MMSC is unable to process the request "
				"because of capacity overload");
}

DBusMessage *__mms_error_perm_failure(DBusMessage *msg)
{
	return g_dbus_create_error(msg, MMS_ERROR_INTERFACE
				".PermanentFailure",
				"An unspecified permanent error occured during"
				" the processing of the request by the MMSC");
}

DBusMessage *__mms_error_perm_service_denied(DBusMessage *msg)
{
	return g_dbus_create_error(msg, MMS_ERROR_INTERFACE
				".PermanentServiceDenied",
				"The request is rejected because of service "
				"authentication or authorization failure(s)");
}

DBusMessage *__mms_error_perm_message_format_corrupt(DBusMessage *msg)
{
	return g_dbus_create_error(msg, MMS_ERROR_INTERFACE
				".PermanentMessageFormatCorrupt",
				"The request is rejected by the MMSC because "
				"of an inconsistency with the message format");
}

DBusMessage *__mms_error_perm_invalid_address(DBusMessage *msg)
{
	return g_dbus_create_error(msg, MMS_ERROR_INTERFACE
				".PermanentInvalidAddress",
				"No recipient address or none of them belongs "
				"to the recipient MMSC");
}

DBusMessage *__mms_error_perm_content_not_accepted(DBusMessage *msg)
{
	return g_dbus_create_error(msg, MMS_ERROR_INTERFACE
				".PermanentContentNotAccepted",
				"The message content is not accepted because "
				"of message size, media type or copyrights "
				"issues");
}

DBusMessage *__mms_error_perm_lack_of_prepaid(DBusMessage *msg)
{
	return g_dbus_create_error(msg, MMS_ERROR_INTERFACE
				".PermanentLackOfPrepaid",
				"The request is rejected due to insufficient "
				"credit of the user");
}

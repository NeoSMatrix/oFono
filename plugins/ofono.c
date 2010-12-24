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

#include <errno.h>

#include <glib.h>
#include <gdbus.h>

#include "plugin.h"
#include "log.h"

#define OFONO_SERVICE		"org.ofono"

#define OFONO_MANAGER_INTERFACE	OFONO_SERVICE ".Manager"
#define OFONO_MODEM_INTERFACE	OFONO_SERVICE ".Modem"
#define OFONO_PUSH_INTERFACE	OFONO_SERVICE ".PushNotification"
#define OFONO_AGENT_INTERFACE	OFONO_SERVICE ".PushNotificationAgent"

struct modem_data {
	char *path;
	DBusConnection *conn;
	gboolean has_push;
	gboolean has_agent;
};

static GHashTable *modem_list;

static gboolean ofono_running = FALSE;

static void remove_agent(struct modem_data *modem)
{
	DBG("path %s", modem->path);

	if (g_dbus_unregister_interface(modem->conn, modem->path,
					OFONO_AGENT_INTERFACE) == FALSE) {
		mms_error("Failed to unregister notification agent");
		return;
	}

	modem->has_agent = FALSE;
}

static DBusMessage *agent_receive(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct modem_data *modem = user_data;
	DBusMessageIter iter, array;
	unsigned char *data;
	int data_len;

	DBG("path %s", modem->path);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		goto done;

	dbus_message_iter_recurse(&iter, &array);
	dbus_message_iter_get_fixed_array(&array, &data, &data_len);

	DBG("notification with %d bytes", data_len);

done:
	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *agent_release(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct modem_data *modem = user_data;

	DBG("path %s", modem->path);

	remove_agent(modem);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable agent_methods[] = {
	{ "ReceiveNotification", "aya{sv}", "", agent_receive },
	{ "Release",             "",        "", agent_release },
	{ }
};

static void create_agent(struct modem_data *modem)
{
	DBG("path %s", modem->path);

	if (g_dbus_register_interface(modem->conn, modem->path,
						OFONO_AGENT_INTERFACE,
						agent_methods, NULL, NULL,
						modem, NULL) == FALSE) {
		mms_error("Failed to register notification agent");
		return;
	}

	modem->has_agent = TRUE;
}

static void remove_modem(gpointer data)
{
	struct modem_data *modem = data;

	DBG("path %s", modem->path);

	if (modem->has_agent == TRUE)
		remove_agent(modem);

	dbus_connection_unref(modem->conn);

	g_free(modem->path);
	g_free(modem);
}

static void register_agent_reply(DBusPendingCall *call, void *user_data)
{
	struct modem_data *modem = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;

	DBG("path %s", modem->path);

	dbus_error_init(&err);

	if (dbus_set_error_from_message(&err, reply) == TRUE) {
		dbus_error_free(&err);
		remove_agent(modem);
		goto done;
	}

done:
	dbus_message_unref(reply);
}

static int register_agent(struct modem_data *modem)
{
	DBusConnection *conn = modem->conn;
	DBusMessage *msg;
	DBusPendingCall *call;

	DBG("path %s", modem->path);

	msg = dbus_message_new_method_call(OFONO_SERVICE, modem->path,
					OFONO_PUSH_INTERFACE, "RegisterAgent");
	if (msg == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(msg, FALSE);

	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &modem->path,
							DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(conn, msg, &call, -1) == FALSE) {
		dbus_message_unref(msg);
		return -EIO;
	}

	dbus_message_unref(msg);

	if (call == NULL)
		return -EINVAL;

	dbus_pending_call_set_notify(call, register_agent_reply, modem, NULL);

	dbus_pending_call_unref(call);

	return 0;
}

static void check_interfaces(struct modem_data *modem, DBusMessageIter *iter)
{
	DBusMessageIter entry;
	gboolean has_push = FALSE;

	dbus_message_iter_recurse(iter, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *interface;

		dbus_message_iter_get_basic(&entry, &interface);

		if (g_str_equal(interface, OFONO_PUSH_INTERFACE) == TRUE)
			has_push = TRUE;

		dbus_message_iter_next(&entry);
	}

	if (modem->has_push == has_push)
		return;

	modem->has_push = has_push;

	DBG("path %s push notification %d", modem->path, modem->has_push);

	if (modem->has_push == TRUE && modem->has_agent == FALSE) {
		create_agent(modem);
		register_agent(modem);
	}

	if (modem->has_push == FALSE && modem->has_agent == TRUE)
		remove_agent(modem);
}

static void create_modem(DBusConnection *conn,
				const char *path, DBusMessageIter *iter)
{
	struct modem_data *modem;
	DBusMessageIter dict;

	modem = g_try_new0(struct modem_data, 1);
	if (modem == NULL)
		return;

	modem->path = g_strdup(path);
	modem->conn = dbus_connection_ref(conn);

	modem->has_push = FALSE;
	modem->has_agent = FALSE;

	DBG("path %s", modem->path);

	g_hash_table_replace(modem_list, modem->path, modem);

	dbus_message_iter_recurse(iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Interfaces") == TRUE)
			check_interfaces(modem, &value);

		dbus_message_iter_next(&dict);
	}
}

static guint modem_added_watch;
static guint modem_removed_watch;
static guint modem_changed_watch;

static gboolean modem_added(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	DBusMessageIter iter, dict;
	const char *path;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &path);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &dict);

	create_modem(connection, path, &iter);

	return TRUE;
}

static gboolean modem_removed(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	DBusMessageIter iter;
	const char *path;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &path);

	g_hash_table_remove(modem_list, path);

	return TRUE;
}

static gboolean modem_changed(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *path, *key;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	path = dbus_message_get_path(message);

	modem = g_hash_table_lookup(modem_list, path);
	if (modem == NULL)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Interfaces") == TRUE)
		check_interfaces(modem, &value);

	return TRUE;
}

static void get_modems_reply(DBusPendingCall *call, void *user_data)
{
	DBusConnection *conn = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessageIter iter, list;
	DBusError err;

	dbus_error_init(&err);

	if (dbus_set_error_from_message(&err, reply) == TRUE) {
		dbus_error_free(&err);
		goto done;
	}

	if (dbus_message_has_signature(reply, "a(oa{sv})") == FALSE)
		goto done;

	if (dbus_message_iter_init(reply, &iter) == FALSE)
		goto done;

	dbus_message_iter_recurse(&iter, &list);

	while (dbus_message_iter_get_arg_type(&list) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry, dict;
		const char *path;

		dbus_message_iter_recurse(&list, &entry);
		dbus_message_iter_get_basic(&entry, &path);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &dict);

		create_modem(conn, path, &entry);

		dbus_message_iter_next(&list);
	}

done:
	dbus_message_unref(reply);
}

static int get_modems(DBusConnection *conn)
{
	DBusMessage *msg;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call(OFONO_SERVICE, "/",
					OFONO_MANAGER_INTERFACE, "GetModems");
	if (msg == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(msg, FALSE);

	if (dbus_connection_send_with_reply(conn, msg, &call, -1) == FALSE) {
		dbus_message_unref(msg);
		return -EIO;
	}

	dbus_message_unref(msg);

	if (call == NULL)
		return -EINVAL;

	dbus_pending_call_set_notify(call, get_modems_reply, conn, NULL);

	dbus_pending_call_unref(call);

	return 0;
}

static void ofono_connect(DBusConnection *conn, void *user_data)
{
	DBG("");

	ofono_running = TRUE;

	modem_list = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, remove_modem);

	modem_added_watch = g_dbus_add_signal_watch(conn, NULL, NULL,
					OFONO_MANAGER_INTERFACE, "ModemAdded",
						modem_added, NULL, NULL);

	modem_removed_watch = g_dbus_add_signal_watch(conn, NULL, NULL,
					OFONO_MANAGER_INTERFACE, "ModemRemoved",
						modem_removed, NULL, NULL);

	modem_changed_watch = g_dbus_add_signal_watch(conn, NULL, NULL,
				OFONO_MODEM_INTERFACE, "PropertyChanged",
						modem_changed, NULL, NULL);

	get_modems(conn);
}

static void ofono_disconnect(DBusConnection *conn, void *user_data)
{
	DBG("");

	ofono_running = FALSE;

	if (modem_added_watch > 0) {
		g_dbus_remove_watch(conn, modem_added_watch);
		modem_added_watch = 0;
	}

	if (modem_removed_watch > 0) {
		g_dbus_remove_watch(conn, modem_removed_watch);
		modem_removed_watch = 0;
	}

	if (modem_changed_watch > 0) {
		g_dbus_remove_watch(conn, modem_changed_watch);
		modem_changed_watch = 0;
	}

	g_hash_table_destroy(modem_list);
	modem_list = NULL;
}

static DBusConnection *connection;
static guint ofono_watch;

static int ofono_init(void)
{
	connection = g_dbus_setup_private(DBUS_BUS_SYSTEM, NULL, NULL);
	if (connection == NULL)
		return -EPERM;

	ofono_watch = g_dbus_add_service_watch(connection, OFONO_SERVICE,
				ofono_connect, ofono_disconnect, NULL, NULL);

	return 0;
}

static void ofono_exit(void)
{
	if (ofono_watch > 0)
		g_dbus_remove_watch(connection, ofono_watch);

	if (ofono_running == TRUE)
		ofono_disconnect(connection, NULL);

	dbus_connection_unref(connection);
}

MMS_PLUGIN_DEFINE(ofono, ofono_init, ofono_exit)

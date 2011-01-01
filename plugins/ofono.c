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
#include "dbus.h"
#include "service.h"

#define OFONO_SERVICE		"org.ofono"

#define OFONO_MANAGER_INTERFACE	OFONO_SERVICE ".Manager"
#define OFONO_MODEM_INTERFACE	OFONO_SERVICE ".Modem"
#define OFONO_SIM_INTERFACE	OFONO_SERVICE ".SimManager"
#define OFONO_GPRS_INTERFACE	OFONO_SERVICE ".ConnectionManager"
#define OFONO_CONTEXT_INTERFACE	OFONO_SERVICE ".ConnectionContext"
#define OFONO_PUSH_INTERFACE	OFONO_SERVICE ".PushNotification"
#define OFONO_AGENT_INTERFACE	OFONO_SERVICE ".PushNotificationAgent"

struct modem_data {
	char *path;
	DBusConnection *conn;
	gboolean has_sim;
	gboolean has_gprs;
	gboolean has_push;
	gboolean has_agent;
	struct mms_service *service;
	dbus_bool_t sim_present;
	char *sim_identity;
	dbus_bool_t gprs_attached;
	char *message_center;
	char *context_path;
	dbus_bool_t context_active;
	char *context_interface;
	char *context_proxy;
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

	mms_service_push_notify(modem->service, data, data_len);

done:
	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *agent_release(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct modem_data *modem = user_data;

	DBG("path %s", modem->path);

	remove_agent(modem);

	return NULL;
}

static GDBusMethodTable agent_methods[] = {
	{ "ReceiveNotification", "aya{sv}", "", agent_receive },
	{ "Release",             "",        "", agent_release,
						G_DBUS_METHOD_FLAG_NOREPLY },
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

	if (modem->sim_present == TRUE && modem->sim_identity != NULL)
		mms_service_unregister(modem->service);

	mms_service_unref(modem->service);

	if (modem->has_agent == TRUE)
		remove_agent(modem);

	dbus_connection_unref(modem->conn);

	g_free(modem->message_center);
	g_free(modem->context_path);
	g_free(modem->context_interface);
	g_free(modem->context_proxy);

	g_free(modem->sim_identity);

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

static void check_sim_present(struct modem_data *modem, DBusMessageIter *iter)
{
	dbus_bool_t present;

	dbus_message_iter_get_basic(iter, &present);

	if (modem->sim_present == present)
		return;

	modem->sim_present = present;

	DBG("SIM present %d", modem->sim_present);

	if (modem->sim_identity == NULL)
		return;

	if (modem->sim_present == FALSE) {
		mms_service_unregister(modem->service);

		g_free(modem->sim_identity);
		modem->sim_identity = NULL;
	} else
		mms_service_register(modem->service);
}

static void check_sim_identity(struct modem_data *modem, DBusMessageIter *iter)
{
	const char *identity;

	dbus_message_iter_get_basic(iter, &identity);

	g_free(modem->sim_identity);
	modem->sim_identity = g_strdup(identity);

	if (modem->sim_identity == NULL)
		return;

	mms_service_set_identity(modem->service, modem->sim_identity);

	if (modem->sim_present == TRUE)
		mms_service_register(modem->service);
}

static gboolean sim_changed(DBusConnection *connection,
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

	if (g_str_equal(key, "Present") == TRUE)
		check_sim_present(modem, &value);
	else if (g_str_equal(key, "SubscriberIdentity") == TRUE)
		check_sim_identity(modem, &value);

	return TRUE;
}

static void get_sim_properties_reply(DBusPendingCall *call, void *user_data)
{
	struct modem_data *modem = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessageIter iter, dict;
	DBusError err;

	dbus_error_init(&err);

	if (dbus_set_error_from_message(&err, reply) == TRUE) {
		dbus_error_free(&err);
		goto done;
	}

	if (dbus_message_has_signature(reply, "a{sv}") == FALSE)
		goto done;

	if (dbus_message_iter_init(reply, &iter) == FALSE)
		goto done;

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Present") == TRUE)
			check_sim_present(modem, &value);
		else if (g_str_equal(key, "SubscriberIdentity") == TRUE)
			check_sim_identity(modem, &value);

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);
}

static int get_sim_properties(struct modem_data *modem)
{
	DBusConnection *conn = modem->conn;
	DBusMessage *msg;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call(OFONO_SERVICE, modem->path,
					OFONO_SIM_INTERFACE, "GetProperties");
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

	dbus_pending_call_set_notify(call, get_sim_properties_reply,
							modem, NULL);

	dbus_pending_call_unref(call);

	return 0;
}

static void check_context_active(struct modem_data *modem,
						DBusMessageIter *iter)
{
	dbus_bool_t active;

	dbus_message_iter_get_basic(iter, &active);

	if (modem->context_active == active)
		return;

	modem->context_active = active;

	DBG("Context active %d", modem->context_active);

	if (modem->context_active == FALSE) {
		g_free(modem->context_interface);
		modem->context_interface = NULL;

		g_free(modem->context_proxy);
		modem->context_proxy = NULL;

		mms_service_bearer_notify(modem->service, FALSE, NULL, NULL);
	} else if (modem->context_proxy != NULL)
		mms_service_bearer_notify(modem->service, TRUE,
						modem->context_interface,
						modem->context_proxy);
}

static void check_context_settings(struct modem_data *modem,
						DBusMessageIter *iter)
{
	DBusMessageIter dict;

	g_free(modem->context_interface);
	modem->context_interface = NULL;

	g_free(modem->context_proxy);
	modem->context_proxy = NULL;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Interface") == TRUE) {
			const char *str;

			dbus_message_iter_get_basic(&value, &str);

			g_free(modem->context_interface);
			modem->context_interface = g_strdup(str);
		} else if (g_str_equal(key, "Proxy") == TRUE) {
			const char *str;

			dbus_message_iter_get_basic(&value, &str);

			g_free(modem->context_proxy);
			modem->context_proxy = g_strdup(str);
		}

		dbus_message_iter_next(&dict);
	}

	if (modem->context_active == FALSE)
		return;

	mms_service_bearer_notify(modem->service, TRUE,
					modem->context_interface,
					modem->context_proxy);
}

static void check_context_message_center(struct modem_data *modem,
						DBusMessageIter *iter)
{
	char *message_center;

	dbus_message_iter_get_basic(iter, &message_center);

	g_free(modem->message_center);
	modem->message_center = g_strdup(message_center);

	DBG("Message center %s", modem->message_center);

	mms_service_set_mmsc(modem->service, modem->message_center);
}

static void create_context(struct modem_data *modem,
				const char *path, DBusMessageIter *iter)
{
	DBusMessageIter dict;

	if (modem->context_path != NULL)
		return;

	dbus_message_iter_recurse(iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Type") == TRUE) {
			const char *type;

			dbus_message_iter_get_basic(&value, &type);

			if (g_str_equal(type, "mms") == FALSE)
				return;

			modem->context_path = g_strdup(path);

			DBG("path %s", modem->context_path);
		} else if (g_str_equal(key, "Active") == TRUE)
			check_context_active(modem, &value);
		else if (g_str_equal(key, "Settings") == TRUE)
			check_context_settings(modem, &value);
		else if (g_str_equal(key, "MessageCenter") == TRUE)
			check_context_message_center(modem, &value);

		dbus_message_iter_next(&dict);
	}
}

static gboolean context_added(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct modem_data *modem;
	DBusMessageIter iter;
	const char *path;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	path = dbus_message_get_path(message);

	modem = g_hash_table_lookup(modem_list, path);
	if (modem == NULL)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &path);

	dbus_message_iter_next(&iter);

	create_context(modem, path, &iter);

	return TRUE;
}

static gboolean context_removed(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct modem_data *modem;
	DBusMessageIter iter;
	const char *path;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	path = dbus_message_get_path(message);

	modem = g_hash_table_lookup(modem_list, path);
	if (modem == NULL)
		return TRUE;

	if (modem->context_path == NULL)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &path);

	if (g_str_equal(path, modem->context_path) == TRUE) {
		modem->context_path = NULL;
		modem->context_active = FALSE;

		DBG("Context active %d", modem->context_active);
	}

	return TRUE;
}

static gboolean context_match(gpointer key, gpointer value,
						gpointer user_data)
{
	struct modem_data *modem = value;
	const char *path = user_data;

	if (modem->context_path == NULL)
		return FALSE;

	return g_str_equal(modem->context_path, path);
}

static gboolean context_changed(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *path, *key;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	path = dbus_message_get_path(message);

	modem = g_hash_table_find(modem_list, context_match, (char *) path);
	if (modem == NULL)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Active") == TRUE)
		check_context_active(modem, &value);
	else if (g_str_equal(key, "Settings") == TRUE)
		check_context_settings(modem, &value);
	else if (g_str_equal(key, "MessageCenter") == TRUE)
		check_context_message_center(modem, &value);

	return TRUE;
}

static void get_contexts_reply(DBusPendingCall *call, void *user_data)
{
	struct modem_data *modem = user_data;
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
		DBusMessageIter entry;
		const char *path;

		dbus_message_iter_recurse(&list, &entry);
		dbus_message_iter_get_basic(&entry, &path);

		dbus_message_iter_next(&entry);

		create_context(modem, path, &entry);

		dbus_message_iter_next(&list);
	}

done:
	dbus_message_unref(reply);
}

static int get_contexts(struct modem_data *modem)
{
	DBusConnection *conn = modem->conn;
	DBusMessage *msg;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call(OFONO_SERVICE, modem->path,
					OFONO_GPRS_INTERFACE, "GetContexts");
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

	dbus_pending_call_set_notify(call, get_contexts_reply, modem, NULL);

	dbus_pending_call_unref(call);

	return 0;
}

static void set_context_reply(DBusPendingCall *call, void *user_data)
{
	struct modem_data *modem = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;

	dbus_error_init(&err);

	if (dbus_set_error_from_message(&err, reply) == TRUE) {
		dbus_error_free(&err);
		mms_service_bearer_notify(modem->service, FALSE, NULL, NULL);
	}

	dbus_message_unref(reply);
}

static int set_context(struct modem_data *modem, dbus_bool_t active)
{
	DBusConnection *conn = modem->conn;
	DBusMessage *msg;
	DBusMessageIter iter;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call(OFONO_SERVICE, modem->context_path,
					OFONO_CONTEXT_INTERFACE, "SetProperty");
	if (msg == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(msg, FALSE);

	dbus_message_iter_init_append(msg, &iter);

	mms_dbus_property_append_basic(&iter, "Active",
					DBUS_TYPE_BOOLEAN, &active);

	if (dbus_connection_send_with_reply(conn, msg, &call, -1) == FALSE) {
		dbus_message_unref(msg);
		return -EIO;
	}

	dbus_message_unref(msg);

	if (call == NULL)
		return -EINVAL;

	dbus_pending_call_set_notify(call, set_context_reply, modem, NULL);

	dbus_pending_call_unref(call);

	return 0;
}

static void bearer_handler(mms_bool_t active, void *user_data)
{
	struct modem_data *modem = user_data;

	DBG("path %s active %d", modem->path, active);

	if (active == TRUE && modem->context_active == TRUE) {
		mms_service_bearer_notify(modem->service, TRUE,
						modem->context_interface,
						modem->context_proxy);
		return;
	}

	if (active == FALSE && modem->context_active == FALSE) {
		mms_service_bearer_notify(modem->service, FALSE, NULL, NULL);
		return;
	}

	if (modem->gprs_attached == FALSE || modem->context_path == NULL) {
		mms_service_bearer_notify(modem->service, FALSE, NULL, NULL);
		return;
	}

	if (set_context(modem, active == TRUE ? TRUE : FALSE) < 0)
		mms_service_bearer_notify(modem->service, FALSE, NULL, NULL);
}

static void check_gprs_attached(struct modem_data *modem, DBusMessageIter *iter)
{
	dbus_bool_t attached;

	dbus_message_iter_get_basic(iter, &attached);

	if (modem->gprs_attached == attached)
		return;

	modem->gprs_attached = attached;

	DBG("GPRS attached %d", modem->gprs_attached);

	if (modem->gprs_attached == FALSE) {
		g_free(modem->context_path);
		modem->context_path = NULL;

		modem->context_active = FALSE;

		DBG("Context active %d", modem->context_active);

		mms_service_set_bearer_handler(modem->service, NULL, NULL);
	} else
		mms_service_set_bearer_handler(modem->service,
							bearer_handler, modem);
}

static gboolean gprs_changed(DBusConnection *connection,
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

	if (g_str_equal(key, "Attached") == TRUE)
		check_gprs_attached(modem, &value);

	return TRUE;
}

static void get_gprs_properties_reply(DBusPendingCall *call, void *user_data)
{
	struct modem_data *modem = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessageIter iter, dict;
	DBusError err;

	dbus_error_init(&err);

	if (dbus_set_error_from_message(&err, reply) == TRUE) {
		dbus_error_free(&err);
		goto done;
	}

	if (dbus_message_has_signature(reply, "a{sv}") == FALSE)
		goto done;

	if (dbus_message_iter_init(reply, &iter) == FALSE)
		goto done;

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Attached") == TRUE)
			check_gprs_attached(modem, &value);

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);

	get_contexts(modem);
}

static int get_gprs_properties(struct modem_data *modem)
{
	DBusConnection *conn = modem->conn;
	DBusMessage *msg;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call(OFONO_SERVICE, modem->path,
					OFONO_GPRS_INTERFACE, "GetProperties");
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

	dbus_pending_call_set_notify(call, get_gprs_properties_reply,
							modem, NULL);

	dbus_pending_call_unref(call);

	return 0;
}

static void check_interfaces(struct modem_data *modem, DBusMessageIter *iter)
{
	DBusMessageIter entry;
	gboolean has_sim = FALSE;
	gboolean has_gprs = FALSE;
	gboolean has_push = FALSE;

	dbus_message_iter_recurse(iter, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *interface;

		dbus_message_iter_get_basic(&entry, &interface);

		if (g_str_equal(interface, OFONO_SIM_INTERFACE) == TRUE)
			has_sim = TRUE;
		else if (g_str_equal(interface, OFONO_GPRS_INTERFACE) == TRUE)
			has_gprs = TRUE;
		else if (g_str_equal(interface, OFONO_PUSH_INTERFACE) == TRUE)
			has_push = TRUE;

		dbus_message_iter_next(&entry);
	}

	if (modem->has_sim != has_sim) {
		modem->has_sim = has_sim;

		DBG("path %s sim %d", modem->path, modem->has_sim);

		if (modem->has_sim == FALSE) {
			mms_service_unregister(modem->service);

			g_free(modem->sim_identity);
			modem->sim_identity = NULL;

			modem->sim_present = FALSE;

			DBG("SIM present %d", modem->sim_present);
		} else
			get_sim_properties(modem);
	}

	if (modem->has_gprs != has_gprs) {
		modem->has_gprs = has_gprs;

		DBG("path %s gprs %d", modem->path, modem->has_gprs);

		if (modem->has_gprs == FALSE) {
			modem->gprs_attached = FALSE;

			DBG("GPRS attached %d", modem->gprs_attached);

			g_free(modem->context_path);
			modem->context_path = NULL;

			modem->context_active = FALSE;

			DBG("Context active %d", modem->context_active);

			mms_service_set_bearer_handler(modem->service,
								NULL, NULL);
		} else
			get_gprs_properties(modem);
	}

	if (modem->has_push != has_push) {
		modem->has_push = has_push;

		DBG("path %s push %d", modem->path, modem->has_push);

		if (modem->has_push == TRUE && modem->has_agent == FALSE) {
			create_agent(modem);
			register_agent(modem);
		}

		if (modem->has_push == FALSE && modem->has_agent == TRUE)
			remove_agent(modem);
	}
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

	modem->has_sim = FALSE;
	modem->has_gprs = FALSE;
	modem->has_push = FALSE;
	modem->has_agent = FALSE;

	modem->service = mms_service_create();

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

static gboolean modem_added(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	DBusMessageIter iter;
	const char *path;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &path);

	dbus_message_iter_next(&iter);

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
		DBusMessageIter entry;
		const char *path;

		dbus_message_iter_recurse(&list, &entry);
		dbus_message_iter_get_basic(&entry, &path);

		dbus_message_iter_next(&entry);

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

static guint modem_added_watch;
static guint modem_removed_watch;
static guint modem_changed_watch;
static guint sim_changed_watch;
static guint gprs_changed_watch;
static guint context_added_watch;
static guint context_removed_watch;
static guint context_changed_watch;

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

	sim_changed_watch = g_dbus_add_signal_watch(conn, NULL, NULL,
				OFONO_SIM_INTERFACE, "PropertyChanged",
						sim_changed, NULL, NULL);

	gprs_changed_watch = g_dbus_add_signal_watch(conn, NULL, NULL,
				OFONO_GPRS_INTERFACE, "PropertyChanged",
						gprs_changed, NULL, NULL);

	context_added_watch = g_dbus_add_signal_watch(conn, NULL, NULL,
					OFONO_GPRS_INTERFACE, "ContextAdded",
						context_added, NULL, NULL);

	context_removed_watch = g_dbus_add_signal_watch(conn, NULL, NULL,
					OFONO_GPRS_INTERFACE, "ContextRemoved",
						context_removed, NULL, NULL);

	context_changed_watch = g_dbus_add_signal_watch(conn, NULL, NULL,
				OFONO_CONTEXT_INTERFACE, "PropertyChanged",
						context_changed, NULL, NULL);

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

	if (sim_changed_watch > 0) {
		g_dbus_remove_watch(conn, sim_changed_watch);
		sim_changed_watch = 0;
	}

	if (gprs_changed_watch > 0) {
		g_dbus_remove_watch(conn, gprs_changed_watch);
		gprs_changed_watch = 0;
	}

	if (context_added_watch > 0) {
		g_dbus_remove_watch(conn, context_added_watch);
		context_added_watch = 0;
	}

	if (context_removed_watch > 0) {
		g_dbus_remove_watch(conn, context_removed_watch);
		context_removed_watch = 0;
	}

	if (context_changed_watch > 0) {
		g_dbus_remove_watch(conn, context_changed_watch);
		context_changed_watch = 0;
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

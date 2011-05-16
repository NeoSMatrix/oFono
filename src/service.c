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

#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <fcntl.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <gdbus.h>

#include <gweb/gweb.h>

#include "mmsutil.h"
#include "mms.h"

#define BEARER_SETUP_TIMEOUT	20	/* 20 seconds */
#define BEARER_IDLE_TIMEOUT	10	/* 10 seconds */

struct mms_service {
	gint refcount;
	char *identity;
	char *path;
	char *mmsc;
	mms_service_bearer_handler_func_t bearer_handler;
	void *bearer_data;
	guint bearer_timeout;
	gboolean bearer_setup;
	gboolean bearer_active;
	GQueue *request_queue;
	guint current_request_id;
	GWeb *web;
};

enum mms_request_type {
	MMS_REQUEST_TYPE_GET,
	MMS_REQUEST_TYPE_POST
};

struct mms_request {
	enum mms_request_type type;
	char *data_path;
	char *tmp_path;
	char *location;
	gsize data_size;
	int recv_fd;
	guint16 status;
	struct mms_service *service;
};

static GList *service_list;

static DBusConnection *connection;

static void mms_request_destroy(struct mms_request *request)
{
	g_free(request->data_path);
	g_free(request->tmp_path);
	g_free(request->location);
	g_free(request);
}

static gboolean send_message_get_recipients(DBusMessageIter *top_iter,
						struct mms_message *msg)
{
	DBusMessageIter recipients;

	dbus_message_iter_recurse(top_iter, &recipients);

	while (dbus_message_iter_get_arg_type(&recipients)
						== DBUS_TYPE_STRING) {
		const char *rec;
		char *tmp;

		dbus_message_iter_get_basic(&recipients, &rec);

		if (msg->sr.to != NULL) {
			tmp = g_strjoin(",", msg->sr.to, rec, NULL);
			if (tmp == NULL)
				return FALSE;

			g_free(msg->sr.to);

			msg->sr.to = tmp;
		} else
			msg->sr.to = g_strdup(rec);

		dbus_message_iter_next(&recipients);
	}

	return TRUE;
}

static gboolean send_message_get_attachments(DBusMessageIter *top_iter,
						struct mms_message *msg)
{
	DBusMessageIter attachments;

	dbus_message_iter_recurse(top_iter, &attachments);

	while (dbus_message_iter_get_arg_type(&attachments)
						== DBUS_TYPE_STRUCT) {
		DBusMessageIter entry;
		const char *id;
		const char *ct;
		const char *filename;
		struct mms_attachment *attach;

		dbus_message_iter_recurse(&attachments, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return FALSE;

		dbus_message_iter_get_basic(&entry, &id);

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return FALSE;

		dbus_message_iter_get_basic(&entry, &ct);

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return FALSE;

		dbus_message_iter_get_basic(&entry, &filename);

		attach = g_try_new0(struct mms_attachment, 1);
		if (attach == NULL)
			return FALSE;

		attach->content_id = g_strdup(id);
		attach->content_type = g_strdup(ct);
		attach->file = g_strdup(filename);

		msg->attachments = g_slist_append(msg->attachments, attach);

		dbus_message_iter_next(&attachments);
	}

	return TRUE;
}

static gboolean send_message_get_args(DBusMessage *dbus_msg,
						struct mms_message *msg)
{
	DBusMessageIter top_iter;
	const char *smil;

	if (dbus_message_iter_init(dbus_msg, &top_iter) == FALSE)
		return FALSE;

	if (dbus_message_iter_get_arg_type(&top_iter) != DBUS_TYPE_ARRAY)
		return FALSE;

	if (send_message_get_recipients(&top_iter, msg) == FALSE)
		return FALSE;

	if (!dbus_message_iter_next(&top_iter))
		return FALSE;

	if (dbus_message_iter_get_arg_type(&top_iter) != DBUS_TYPE_STRING)
		return FALSE;

	dbus_message_iter_get_basic(&top_iter, &smil);
	msg->sr.smil = g_strdup(smil);

	if (!dbus_message_iter_next(&top_iter))
		return FALSE;

	if (dbus_message_iter_get_arg_type(&top_iter) != DBUS_TYPE_ARRAY)
		return FALSE;

	return send_message_get_attachments(&top_iter, msg);
}

static DBusMessage *send_message(DBusConnection *conn,
					DBusMessage *dbus_msg, void *data)
{
	DBusMessage *reply;
	struct mms_message msg;

	memset(&msg, 0, sizeof(msg));

	msg.type = MMS_MESSAGE_TYPE_SEND_REQ;

	msg.sr.status = MMS_MESSAGE_STATUS_DRAFT;

	if (send_message_get_args(dbus_msg, &msg) == FALSE) {
		mms_debug("Invalid arguments");

		mms_message_free(&msg);

		return __mms_error_invalid_args(dbus_msg);
	}

	/*
	 * TODO:
	 * -encode pdu & store it
	 * -register new updated dbus message object
	 * -post gweb send request
	 * -post AddedMessage dbus signal
	 */

	reply = dbus_message_new_method_return(dbus_msg);

	/*
	 * TODO set new message object path
	 */

	mms_message_free(&msg);

	return reply;
}

static GDBusMethodTable service_methods[] = {
	{ "SendMessage", "assa(sss)", "o", send_message },
	{ }
};

static GDBusSignalTable service_signals[] = {
	{ "MessageAdded",   "oa{sv}" },
	{ "MessageRemoved", "o" },
	{ }
};

struct mms_service *mms_service_create(void)
{
	struct mms_service *service;

	service = g_try_new0(struct mms_service, 1);
	if (service == NULL)
		return NULL;

	service->refcount = 1;

	service->request_queue = g_queue_new();
	if (service->request_queue == NULL) {
		g_free(service);
		return NULL;
	}

	service->current_request_id = 0;

	DBG("service %p", service);

	return service;
}

struct mms_service *mms_service_ref(struct mms_service *service)
{
	if (service == NULL)
		return NULL;

	g_atomic_int_inc(&service->refcount);

	return service;
}

static void process_request_queue(struct mms_service *service);

static void complete_request(struct mms_request *request)
{
	struct mms_service *service = request->service;

	mms_request_destroy(request);

	if (service->current_request_id == 0)
		return;

	service->current_request_id = 0;

	process_request_queue(service);
}

void mms_service_unref(struct mms_service *service)
{
	struct mms_request *request;

	if (service == NULL)
		return;

	if (g_atomic_int_dec_and_test(&service->refcount) == FALSE)
		return;

	DBG("service %p", service);

	while ((request = g_queue_pop_head(service->request_queue)))
		mms_request_destroy(request);

	g_queue_free(service->request_queue);

	if (service->web != NULL)
		g_web_unref(service->web);

	g_free(service->mmsc);

	g_free(service->identity);
	g_free(service->path);
	g_free(service);
}

static void append_properties(DBusMessageIter *dict,
				struct mms_service *service)
{
	mms_dbus_dict_append_basic(dict, "Identity",
				DBUS_TYPE_STRING, &service->identity);
}

static void emit_service_added(struct mms_service *service)
{
	DBusMessage *signal;
	DBusMessageIter iter, dict;

	DBG("service %p", service);

	signal = dbus_message_new_signal(MMS_PATH, MMS_MANAGER_INTERFACE,
							"ServiceAdded");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							&service->path);

	mms_dbus_dict_open(&iter, &dict);
	append_properties(&dict, service);
	mms_dbus_dict_close(&iter, &dict);

	g_dbus_send_message(connection, signal);
}

static void emit_service_removed(struct mms_service *service)
{
	DBG("service %p", service);

	g_dbus_emit_signal(connection, MMS_PATH, MMS_MANAGER_INTERFACE,
				"ServiceRemoved", DBUS_TYPE_OBJECT_PATH,
				&service->path, DBUS_TYPE_INVALID);
}

int mms_service_register(struct mms_service *service)
{
	DBG("service %p", service);

	if (service == NULL)
		return -EINVAL;

	if (service->identity == NULL)
		return -EINVAL;

	if (service->path != NULL)
		return -EBUSY;

	service->path = g_strdup_printf("%s/%s", MMS_PATH, service->identity);
	if (service->path == NULL)
		return -ENOMEM;

	if (g_dbus_register_interface(connection, service->path,
						MMS_SERVICE_INTERFACE,
						service_methods,
						service_signals, NULL,
						service, NULL) == FALSE) {
		mms_error("Failed to register service interface");
		g_free(service->path);
		service->path = NULL;
		return -EIO;
	}

	service_list = g_list_append(service_list, service);

	emit_service_added(service);

	return 0;
}

int mms_service_unregister(struct mms_service *service)
{
	DBG("service %p", service);

	if (service == NULL)
		return -EINVAL;

	if (service->path == NULL)
		return -EINVAL;

	if (g_dbus_unregister_interface(connection, service->path,
					MMS_SERVICE_INTERFACE) == FALSE) {
		mms_error("Failed to unregister service interface");
		return -EIO;
	}

	service_list = g_list_remove(service_list, service);

	emit_service_removed(service);

	g_free(service->path);
	service->path = NULL;

	return 0;
}

int mms_service_set_identity(struct mms_service *service,
					const char *identity)
{
	DBG("service %p identity %s", service, identity);

	if (service == NULL)
		return -EINVAL;

	if (service->path != NULL)
		return -EBUSY;

	g_free(service->identity);
	service->identity = g_strdup(identity);

	return 0;
}

int mms_service_set_mmsc(struct mms_service *service, const char *mmsc)
{
	DBG("service %p mmsc %s", service, mmsc);

	if (service == NULL)
		return -EINVAL;

	g_free(service->mmsc);
	service->mmsc = g_strdup(mmsc);

	return 0;
}

int mms_service_set_bearer_handler(struct mms_service *service,
				mms_service_bearer_handler_func_t handler,
							void *user_data)
{
	DBG("service %p handler %p", service, handler);

	if (service == NULL)
		return -EINVAL;

	service->bearer_handler = handler;
	service->bearer_data = user_data;

	return 0;
}

static gboolean bearer_setup_timeout(gpointer user_data)
{
	struct mms_service *service = user_data;

	DBG("service %p", service);

	service->bearer_timeout = 0;

	service->bearer_setup = FALSE;

	return FALSE;
}

static void activate_bearer(struct mms_service *service)
{
	DBG("service %p", service);

	if (service->bearer_setup == TRUE)
		return;

	if (service->bearer_active == TRUE) {
		process_request_queue(service);
		return;
	}

	if (service->bearer_handler == NULL)
		return;

	DBG("service %p", service);

	service->bearer_setup = TRUE;

	service->bearer_timeout = g_timeout_add_seconds(BEARER_SETUP_TIMEOUT,
						bearer_setup_timeout, service);

	service->bearer_handler(TRUE, service->bearer_data);
}

static void deactivate_bearer(struct mms_service *service)
{
	DBG("service %p", service);

	if (service->bearer_setup == TRUE)
		return;

	if (service->bearer_active == FALSE)
		return;

	if (service->bearer_handler == NULL)
		return;

	DBG("service %p", service);

	service->bearer_setup = TRUE;

	service->bearer_timeout = g_timeout_add_seconds(BEARER_SETUP_TIMEOUT,
						bearer_setup_timeout, service);

	service->bearer_handler(FALSE, service->bearer_data);
}

static gboolean bearer_idle_timeout(gpointer user_data)
{
	struct mms_service *service = user_data;

	DBG("service %p", service);

	service->bearer_timeout = 0;

	deactivate_bearer(service);

	return FALSE;
}

static gboolean web_get_cb(GWebResult *result, gpointer user_data)
{
	gsize written;
	gsize chunk_size;
	struct mms_request *request = user_data;
	const guint8 *chunk;

	if (g_web_result_get_chunk(result, &chunk, &chunk_size) == FALSE)
		goto complete;

	if (chunk_size == 0) {
		close(request->recv_fd);

		request->status = g_web_result_get_status(result);

		DBG("status: %03u", request->status);
		DBG("data size = %zd", request->data_size);

		g_rename(request->tmp_path, request->data_path);

		goto complete;
	}

	request->data_size += chunk_size;

	written = write(request->recv_fd, chunk, chunk_size);
	if (written != chunk_size) {
		mms_error("only %zd/%zd bytes written\n",
			  written, chunk_size);

		close(request->recv_fd);

		unlink(request->tmp_path);

		goto complete;
	}

	return TRUE;

complete:
	complete_request(request);

	return FALSE;
}

static guint process_request(struct mms_request *request)
{
	struct mms_service *service = request->service;
	guint id;

	switch (request->type) {
	case MMS_REQUEST_TYPE_GET:
		request->tmp_path = g_strdup_printf("%s.XXXXXX.tmp",
						    request->data_path);

		request->recv_fd = g_mkstemp_full(request->tmp_path,
						  O_WRONLY | O_CREAT | O_TRUNC,
						  S_IWUSR | S_IRUSR);
		if (request->recv_fd < 0)
			return 0;

		id = g_web_request_get(service->web, request->location,
				       web_get_cb, request);
		if (id == 0) {
			close(request->recv_fd);
			unlink(request->tmp_path);
		}

		return id;

	case MMS_REQUEST_TYPE_POST:
		break;
	}

	return 0;
}

static void process_request_queue(struct mms_service *service)
{
	struct mms_request *request;

	DBG("service %p", service);

	if (service->bearer_timeout > 0) {
		g_source_remove(service->bearer_timeout);
		service->bearer_timeout = 0;
	}

	if (service->current_request_id > 0)
		return;

	while (1) {
		request = g_queue_pop_head(service->request_queue);
		if (request == NULL)
			break;

		DBG("location %s", request->location);

		service->current_request_id = process_request(request);
		if (service->current_request_id > 0)
			return;

		mms_request_destroy(request);
	}

	service->bearer_timeout = g_timeout_add_seconds(BEARER_IDLE_TIMEOUT,
						bearer_idle_timeout, service);
}

static void dump_notification_ind(struct mms_message *msg)
{
	char buf[128];

	strftime(buf, 127, "%Y-%m-%dT%H:%M:%S%z", localtime(&msg->ni.expiry));
	buf[127] = '\0';

	mms_info("MMS transaction id: %s\n", msg->transaction_id);
	mms_info("MMS version: %u.%u\n", (msg->version & 0x70) >> 4,
						msg->version & 0x0f);
	mms_info("From: %s\n", msg->ni.from);
	mms_info("Subject: %s\n", msg->ni.subject);
	mms_info("Class: %s\n", msg->ni.cls);
	mms_info("Size: %d\n", msg->ni.size);
	mms_info("Expiry: %s\n", buf);
	mms_info("Location: %s\n", msg->ni.location);
}

static struct mms_request *create_get_request(void)
{
	struct mms_request *request;

	request = g_try_new0(struct mms_request, 1);
	if (request == NULL)
		return NULL;

	request->type = MMS_REQUEST_TYPE_GET;

	request->data_path = g_strdup_printf("%s%s", g_get_home_dir(),
					     "/.mms/receive.mms");

	request->status = 0;

	return request;
}

void mms_service_push_notify(struct mms_service *service,
					unsigned char *data, int len)
{
	struct mms_request *request;
	struct mms_message msg;
	unsigned int nread;
	const char *uuid;

	DBG("service %p data %p len %d", service, data, len);

	if (mms_push_notify(data, len, &nread) == FALSE)
		return;

	uuid = mms_store(service->identity, data + nread, len - nread);
	if (uuid == NULL)
		return;

	if (mms_message_decode(data + nread, len - nread, &msg) == FALSE)
		goto out;

	if (msg.type != MMS_MESSAGE_TYPE_NOTIFICATION_IND)
		goto out;

	dump_notification_ind(&msg);

	request = create_get_request();
	if (request == NULL)
		goto out;

	msg.uuid = g_strdup(uuid);

	request->location = g_strdup(msg.ni.location);

	request->service = service;

	g_queue_push_tail(service->request_queue, request);

	activate_bearer(service);

out:
	mms_message_free(&msg);
}

void mms_service_bearer_notify(struct mms_service *service, mms_bool_t active,
				const char *interface, const char *proxy)
{
	int ifindex;

	DBG("service %p active %d", service, active);

	if (service == NULL)
		return;

	if (service->bearer_timeout > 0) {
		g_source_remove(service->bearer_timeout);
		service->bearer_timeout = 0;
	}

	service->bearer_setup = FALSE;

	service->bearer_active = active;

	if (active == FALSE)
		return;

	DBG("interface %s proxy %s", interface, proxy);

	if (service->web != NULL) {
		g_web_unref(service->web);
		service->web = NULL;
	}

	if (interface == NULL)
		return;

	ifindex = if_nametoindex(interface);
	if (ifindex == 0)
		return;

	service->web = g_web_new(ifindex);
	if (service->web == NULL)
		return;

	/* Sometimes no proxy is reported as string instead of NULL */
	if (g_strcmp0(proxy, "") != 0)
		g_web_set_proxy(service->web, proxy);

	process_request_queue(service);
}

static void append_struct(gpointer value, gpointer user_data)
{
	struct mms_service *service = value;
	DBusMessageIter *iter = user_data;
	DBusMessageIter entry, dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
							&service->path);

	mms_dbus_dict_open(&entry, &dict);
	append_properties(&dict, service);
	mms_dbus_dict_close(&entry, &dict);

	dbus_message_iter_close_container(iter, &entry);
}

static DBusMessage *get_services(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter, array;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_STRUCT_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_OBJECT_PATH_AS_STRING
			DBUS_TYPE_ARRAY_AS_STRING
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING
			DBUS_STRUCT_END_CHAR_AS_STRING, &array);


	g_list_foreach(service_list, append_struct, &array);

	dbus_message_iter_close_container(&iter, &array);

	return reply;
}

static GDBusMethodTable manager_methods[] = {
	{ "GetServices", "", "a(oa{sv})", get_services },
	{ }
};

static GDBusSignalTable manager_signals[] = {
	{ "ServiceAdded",   "oa{sv}" },
	{ "ServiceRemoved", "o"      },
	{ }
};

int __mms_service_init(void)
{
	DBG("");

	connection = mms_dbus_get_connection();

	if (g_dbus_register_interface(connection, MMS_PATH,
					MMS_MANAGER_INTERFACE,
					manager_methods, manager_signals,
					NULL, NULL, NULL) == FALSE) {
		mms_error("Failed to register manager interface");
		return -EIO;
	}

	return 0;
}

void __mms_service_cleanup(void)
{
	DBG("");

	if (g_dbus_unregister_interface(connection, MMS_PATH,
					MMS_MANAGER_INTERFACE) == FALSE)
		mms_error("Failed to unregister manager interface");
}

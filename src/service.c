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
#include <ctype.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <gdbus.h>

#include <gweb/gweb.h>

#include "mmsutil.h"
#include "mms.h"

#define BEARER_SETUP_TIMEOUT	20	/* 20 seconds */
#define BEARER_IDLE_TIMEOUT	10	/* 10 seconds */

#define uninitialized_var(x) x = x

typedef void (*mms_request_result_cb_t) (guint status, const char *data_path,
						gpointer user_data);

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
	GHashTable *messages;
};

enum mms_request_type {
	MMS_REQUEST_TYPE_GET,
	MMS_REQUEST_TYPE_POST
};

struct mms_request {
	enum mms_request_type type;
	char *data_path;
	char *location;
	gsize data_size;
	gpointer data;
	gsize offset;
	int fd;
	guint16 status;
	struct mms_service *service;
	mms_request_result_cb_t result_cb;
};

static GList *service_list;

static DBusConnection *connection;

static void mms_request_destroy(struct mms_request *request)
{
	g_free(request->data_path);
	g_free(request->location);
	g_free(request);
}

static DBusMessage *msg_delete(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct mms_service *service = user_data;
	const char *path;
	const char *uuid;

	path = dbus_message_get_path(msg);

	DBG("message path %s", path);

	uuid = g_hash_table_lookup(service->messages, path);
	if (uuid == NULL)
		return __mms_error_invalid_args(msg);

	if (mms_message_unregister(service, path) < 0)
		return __mms_error_invalid_args(msg);

	mms_store_remove(service->identity, uuid);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void emit_msg_status_changed(const char *path, const char *new_status)
{
	DBusMessage *signal;
	DBusMessageIter iter;
	DBusMessageIter variant;
	const char *property = "status";

	signal = dbus_message_new_signal(path, MMS_MESSAGE_INTERFACE,
							"PropertyChanged");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &property);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					DBUS_TYPE_STRING_AS_STRING, &variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &new_status);
	dbus_message_iter_close_container(&iter, &variant);

	g_dbus_send_message(connection, signal);
}

static DBusMessage *msg_mark_read(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct mms_service *service = user_data;
	const char *path;
	const char *uuid;
	const char *state;
	GKeyFile *meta;

	path = dbus_message_get_path(msg);

	DBG("message path %s", path);

	uuid = g_hash_table_lookup(service->messages, path);
	if (uuid == NULL)
		return __mms_error_invalid_args(msg);

	meta = mms_store_meta_open(service->identity, uuid);

	state = g_key_file_get_string(meta, "info", "state", NULL);
	if (state == NULL) {
		mms_store_meta_close(service->identity, uuid, meta, FALSE);
		return __mms_error_invalid_args(msg);
	}

	if (strcmp(state, "received") != 0 && strcmp(state, "sent") != 0) {
		mms_store_meta_close(service->identity, uuid, meta, FALSE);
		return __mms_error_invalid_args(msg);
	}

	g_key_file_set_boolean(meta, "info", "read", TRUE);

	mms_store_meta_close(service->identity, uuid, meta, TRUE);

	emit_msg_status_changed(path, "read");

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable message_methods[] = {
	{ "MarkRead", "", "", msg_mark_read },
	{ "Delete",   "", "", msg_delete },
	{ }
};

static GDBusSignalTable message_signals[] = {
	{ "PropertyChanged", "sv" },
	{ }
};

static gboolean valid_number_format(const char *number)
{
	int len = strlen(number);
	int begin = 0;
	unsigned int num_digits = 0;
	int i;

	if (len == 0)
		return FALSE;

	if (number[0] == '+')
		begin = 1;

	if (begin == len)
		return FALSE;

	for (i = begin; i < len; i++) {
		if (number[i] >= '0' && number[i] <= '9') {
			num_digits++;

			if (num_digits > 20)
				return FALSE;

			continue;
		}

		if (number[i] == '-' || number[i] == '.')
			continue;

		return FALSE;
	}

	return TRUE;
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

		if (valid_number_format(rec) == FALSE)
			return FALSE;

		if (msg->sr.to != NULL) {
			tmp = g_strconcat(msg->sr.to, ",", rec, "/TYPE=PLMN",
									NULL);
			if (tmp == NULL)
				return FALSE;

			g_free(msg->sr.to);

			msg->sr.to = tmp;
		} else
			msg->sr.to = g_strdup_printf("%s/TYPE=PLMN", rec);

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

static struct mms_request *create_request(enum mms_request_type type,
					  mms_request_result_cb_t result_cb,
					  char *location,
					  struct mms_service *service)
{
	struct mms_request *request;

	request = g_try_new0(struct mms_request, 1);
	if (request == NULL)
		return NULL;

	request->type = type;

	switch (request->type) {
	case MMS_REQUEST_TYPE_GET:
		request->data_path = g_strdup_printf("%s%s", g_get_home_dir(),
						"/.mms/receive.XXXXXX.mms");

		break;
	case MMS_REQUEST_TYPE_POST:
		request->data_path = g_strdup_printf("%s%s", g_get_home_dir(),
						"/.mms/send.XXXXXX.mms");

		break;
	}

	request->fd = g_mkstemp_full(request->data_path,
				     O_WRONLY | O_CREAT | O_TRUNC,
				     S_IWUSR | S_IRUSR);
	if (request->fd < 0) {
		g_free(request->data_path);

		g_free(request);

		return NULL;
	}

	request->result_cb = result_cb;

	request->location = location;

	request->service = service;

	request->status = 0;

	return request;
}

static gboolean bearer_setup_timeout(gpointer user_data)
{
	struct mms_service *service = user_data;

	DBG("service %p", service);

	service->bearer_timeout = 0;

	service->bearer_setup = FALSE;

	return FALSE;
}

static void process_request_queue(struct mms_service *service);

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

static DBusMessage *send_message(DBusConnection *conn,
					DBusMessage *dbus_msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	struct mms_message msg;
	struct mms_service *service;

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
	 * -post gweb send request
	 */

	service = data;
	if (mms_message_register(service, &msg) < 0)
		return __mms_error_trans_failure(dbus_msg);

	reply = dbus_message_new_method_return(dbus_msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
								&msg.path);

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

	service->messages = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);
	if (service->messages == NULL) {
		g_queue_free(service->request_queue);
		g_free(service);
		return NULL;
	}

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

	g_hash_table_destroy(service->messages);

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

static gboolean mms_attachment_is_smil(const struct mms_attachment *part)
{
	if (g_str_has_prefix(part->content_type, "application/smil"))
		return TRUE;

	return FALSE;
}

static const char *time_to_str(const time_t *t)
{
	static char buf[128];
	struct tm tm;

	strftime(buf, 127, "%Y-%m-%dT%H:%M:%S%z", localtime_r(t, &tm));
	buf[127] = '\0';

	return buf;
}

static void append_attachment_properties(struct mms_attachment *part,
			DBusMessageIter *dict, DBusMessageIter *part_array)
{
	DBusMessageIter entry;
	dbus_uint64_t val;

	dbus_message_iter_open_container(part_array, DBUS_TYPE_STRUCT,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
							&part->content_id);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
							&part->content_type);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
							&part->file);
	val = part->offset;
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_UINT64, &val);
	val = part->length;
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_UINT64, &val);

	dbus_message_iter_close_container(part_array, &entry);
}

static void append_smil(DBusMessageIter *dict,
					const struct mms_attachment *part)
{
	const char *to_codeset = "utf-8";
	char *from_codeset;
	int fd;
	struct stat st;
	unsigned char *data;
	char *smil;

	fd = open(part->file, O_RDONLY);
	if (fd < 0) {
		mms_error("Failed to open %s\n", part->file);
		return;
	}

	if (fstat(fd, &st) < 0)
		goto out;

	data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == NULL || data == MAP_FAILED)
		goto out;

	from_codeset = mms_content_type_get_param_value(part->content_type,
								"charset");
	if (from_codeset != NULL) {
		smil = g_convert((const char *) data + part->offset,
					part->length, to_codeset, from_codeset,
					NULL, NULL, NULL);

		g_free(from_codeset);
	} else
		smil = g_convert((const char *) data + part->offset,
					part->length, to_codeset, "us-ascii",
					NULL, NULL, NULL);

	munmap(data, st.st_size);

	if (smil == NULL) {
		mms_error("Failed to convert smil attachment\n");
		goto out;
	}

	mms_dbus_dict_append_basic(dict, "Smil", DBUS_TYPE_STRING, &smil);

	g_free(smil);
out:
	close(fd);
}

static void append_msg_attachments(DBusMessageIter *dict,
					struct mms_message *msg)
{
	const char *dict_entry = "Attachments";
	DBusMessageIter array;
	DBusMessageIter entry;
	DBusMessageIter variant;
	GSList *part;
	struct mms_attachment *smil;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &dict_entry);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						"a(ssstt)", &variant);

	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						"(ssstt)", &array);

	smil = NULL;
	for (part = msg->attachments; part != NULL;
					part = g_slist_next(part)) {
		if (mms_attachment_is_smil(part->data))
			smil = part->data;
		else
			append_attachment_properties(part->data, dict, &array);
	}

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(&entry, &variant);

	dbus_message_iter_close_container(dict, &entry);

	if (smil == NULL)
		return;

	switch (msg->type) {
	case MMS_MESSAGE_TYPE_SEND_REQ:
		return;
	case MMS_MESSAGE_TYPE_SEND_CONF:
		return;
	case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
		return;
	case MMS_MESSAGE_TYPE_NOTIFYRESP_IND:
		return;
	case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
		append_smil(dict, smil);
		break;
	case MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND:
		return;
	case MMS_MESSAGE_TYPE_DELIVERY_IND:
		return;
	}
}

static const char *mms_address_to_string(char *mms_address)
{
	unsigned int prefix_len;

	if (g_str_has_suffix(mms_address, "/TYPE=PLMN") == TRUE) {
		prefix_len = strlen(mms_address) - 10;

		mms_address[prefix_len] = '\0';
	}

	return (const char *) mms_address;
}

static void append_msg_recipients(DBusMessageIter *dict,
					struct mms_message *msg)
{
	const char *dict_entry = "Recipients";
	DBusMessageIter array;
	DBusMessageIter entry;
	DBusMessageIter variant;
	gchar **uninitialized_var(tokens);
	unsigned int i;
	const char *rcpt;

	switch (msg->type) {
	case MMS_MESSAGE_TYPE_SEND_REQ:
		tokens = g_strsplit(msg->sr.to, ",", -1);
		break;
	case MMS_MESSAGE_TYPE_SEND_CONF:
		return;
	case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
		return;
	case MMS_MESSAGE_TYPE_NOTIFYRESP_IND:
		return;
	case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
		tokens = g_strsplit(msg->rc.to, ",", -1);
		break;
	case MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND:
		return;
	case MMS_MESSAGE_TYPE_DELIVERY_IND:
		return;
	}

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
					NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &dict_entry);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
							"as", &variant);
	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
							"s", &array);

	for (i = 0; tokens[i] != NULL; i++) {
		rcpt = mms_address_to_string(tokens[i]);

		dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &rcpt);
	}

	g_strfreev(tokens);

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(&entry, &variant);

	dbus_message_iter_close_container(dict, &entry);
}

static void append_rc_msg_properties(DBusMessageIter *dict,
					struct mms_message *msg)
{
	const char *date = time_to_str(&msg->rc.date);
	const char *status = "received";
	const char *from_prefix;
	char *from;

	mms_dbus_dict_append_basic(dict, "Status",
					DBUS_TYPE_STRING, &status);

	mms_dbus_dict_append_basic(dict, "Date",
					DBUS_TYPE_STRING,  &date);

	if (msg->rc.subject != NULL)
		mms_dbus_dict_append_basic(dict, "Subject",
					DBUS_TYPE_STRING, &msg->rc.subject);

	from = g_strdup(msg->rc.from);

	if (from != NULL) {
		from_prefix = mms_address_to_string(from);
		mms_dbus_dict_append_basic(dict, "Sender",
					DBUS_TYPE_STRING, &from_prefix);
		g_free(from);
	}

	if (msg->rc.to != NULL)
		append_msg_recipients(dict, msg);
}

static void append_sr_msg_properties(DBusMessageIter *dict,
					struct mms_message *msg)
{
	const char *date = time_to_str(&msg->rc.date);
	const char *status = "draft";

	mms_dbus_dict_append_basic(dict, "Status",
					DBUS_TYPE_STRING, &status);

	mms_dbus_dict_append_basic(dict, "Date",
					DBUS_TYPE_STRING,  &date);

	/* Smil available from message struct */
	if (msg->sr.smil != NULL)
		mms_dbus_dict_append_basic(dict, "Smil", DBUS_TYPE_STRING,
						&msg->sr.smil);

	if (msg->sr.to != NULL)
		append_msg_recipients(dict, msg);
}

static void emit_message_added(const struct mms_service *service,
						struct mms_message *msg)
{
	DBusMessage *signal;
	DBusMessageIter iter, dict;

	DBG("message %p", msg);

	signal = dbus_message_new_signal(service->path, MMS_SERVICE_INTERFACE,
							"MessageAdded");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							&msg->path);

	mms_dbus_dict_open(&iter, &dict);

	switch (msg->type) {
	case MMS_MESSAGE_TYPE_SEND_REQ:
		append_sr_msg_properties(&dict, msg);
		break;
	case MMS_MESSAGE_TYPE_SEND_CONF:
		break;
	case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
		break;
	case MMS_MESSAGE_TYPE_NOTIFYRESP_IND:
		break;
	case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
		append_rc_msg_properties(&dict, msg);
		break;
	case MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND:
		break;
	case MMS_MESSAGE_TYPE_DELIVERY_IND:
		break;
	}

	if (msg->attachments != NULL)
		append_msg_attachments(&dict, msg);

	mms_dbus_dict_close(&iter, &dict);

	g_dbus_send_message(connection, signal);
}

int mms_message_register(struct mms_service *service,
						struct mms_message *msg)
{
	msg->path = g_strdup_printf("%s/%s", service->path, msg->uuid);
	if (msg->path == NULL)
		return -ENOMEM;

	if (g_dbus_register_interface(connection, msg->path,
						MMS_MESSAGE_INTERFACE,
						message_methods,
						message_signals, NULL,
						service, NULL) == FALSE) {
		mms_error("Failed to register message interface");
		g_free(msg->path);
		msg->path = NULL;
		return -EIO;;
	}

	g_hash_table_replace(service->messages, g_strdup(msg->path),
							g_strdup(msg->uuid));

	DBG("message registered %s", msg->path);

	emit_message_added(service, msg);

	return 0;
}

static void emit_message_removed(const char *svc_path, const char *msg_path)
{
	g_dbus_emit_signal(connection, svc_path, MMS_MESSAGE_INTERFACE,
				"MessageRemoved", DBUS_TYPE_OBJECT_PATH,
				&msg_path, DBUS_TYPE_INVALID);
}

int mms_message_unregister(const struct mms_service *service,
						const char *msg_path)
{
	emit_message_removed(service->path, msg_path);

	if (g_dbus_unregister_interface(connection, msg_path,
					MMS_MESSAGE_INTERFACE) == FALSE) {
		mms_error("Failed to unregister message interface");
		return -EIO;
	}

	g_hash_table_remove(service->messages, msg_path);

	DBG("message unregistered %s", msg_path);

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

static void result_request_get(guint status, const char *data_path,
				gpointer user_data)
{
	int fd;
	struct mms_message msg;
	struct stat st;
	unsigned char *pdu;
	struct mms_service *service = user_data;
	const char *uuid;
	GKeyFile *meta;

	if (status != 200)
		return;

	fd = open(data_path, O_RDONLY);
	if (fd < 0) {
		mms_error("Failed to open %s", data_path);

		return;
	}

	if (fstat(fd, &st) < 0) {
		mms_error("Failed to stat %s", data_path);

		close(fd);

		return;
	}

	pdu = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

	close(fd);

	if (pdu == NULL || pdu == MAP_FAILED)
		goto exit;

	uuid = mms_store_file(service->identity, data_path);
	if (uuid == NULL)
		goto exit;

	if (mms_message_decode(pdu, st.st_size, &msg) == FALSE) {
		mms_error("Failed to decode %s", data_path);

		goto error;
	}

	meta = mms_store_meta_open(service->identity, uuid);
	if (meta == NULL)
		goto error;

	g_key_file_set_boolean(meta, "info", "read", FALSE);

	g_key_file_set_string(meta, "info", "state", "downloaded");

	mms_store_meta_close(service->identity, uuid, meta, TRUE);

	goto exit;

error:
	mms_store_remove(service->identity, uuid);

exit:
	munmap(pdu, st.st_size);
}

static gboolean web_get_cb(GWebResult *result, gpointer user_data)
{
	gsize written;
	gsize chunk_size;
	struct mms_request *request = user_data;
	struct mms_service *service;
	const guint8 *chunk;

	if (g_web_result_get_chunk(result, &chunk, &chunk_size) == FALSE)
		goto error;

	if (chunk_size == 0) {
		close(request->fd);

		request->status = g_web_result_get_status(result);

		DBG("status: %03u", request->status);
		DBG("data size = %zd", request->data_size);

		goto complete;
	}

	request->data_size += chunk_size;

	written = write(request->fd, chunk, chunk_size);

	if (written != chunk_size) {
		mms_error("only %zd/%zd bytes written\n", written, chunk_size);
		goto error;
	}

	return TRUE;

error:
	close(request->fd);
	unlink(request->data_path);

complete:
	service = request->service;

	if (request->result_cb != NULL)
		request->result_cb(request->status,
				   request->data_path, service);

	mms_request_destroy(request);

	service->current_request_id = 0;

	process_request_queue(service);

	return FALSE;
}

static guint process_request(struct mms_request *request)
{
	struct mms_service *service = request->service;
	guint id;

	switch (request->type) {
	case MMS_REQUEST_TYPE_GET:
		id = g_web_request_get(service->web, request->location,
					web_get_cb, request);
		if (id == 0) {
			close(request->fd);
			unlink(request->data_path);
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

void mms_service_push_notify(struct mms_service *service,
					unsigned char *data, int len)
{
	struct mms_request *request;
	struct mms_message msg;
	unsigned int nread;
	const char *uuid;
	GKeyFile *meta;
	char *location;

	DBG("service %p data %p len %d", service, data, len);

	if (mms_push_notify(data, len, &nread) == FALSE)
		return;

	uuid = mms_store(service->identity, data + nread, len - nread);
	if (uuid == NULL)
		return;

	if (mms_message_decode(data + nread, len - nread, &msg) == FALSE)
		goto error;

	if (msg.type != MMS_MESSAGE_TYPE_NOTIFICATION_IND)
		goto error;

	dump_notification_ind(&msg);

	meta = mms_store_meta_open(service->identity, uuid);
	if (meta == NULL)
		goto error;

	g_key_file_set_boolean(meta, "info", "read", FALSE);

	g_key_file_set_string(meta, "info", "state", "notification");

	mms_store_meta_close(service->identity, uuid, meta, TRUE);

	location = g_strdup(msg.ni.location);

	request = create_request(MMS_REQUEST_TYPE_GET,
				 result_request_get, location, service);
	if (request == NULL) {
		g_free(location);

		goto out;
	}

	msg.uuid = g_strdup(uuid);

	g_queue_push_tail(service->request_queue, request);

	activate_bearer(service);

	goto out;

error:
	mms_store_remove(service->identity, uuid);

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
		goto interface_down;

	DBG("interface %s proxy %s", interface, proxy);

	if (service->web != NULL) {
		g_web_unref(service->web);
		service->web = NULL;
	}

	if (interface == NULL)
		goto interface_down;

	ifindex = if_nametoindex(interface);
	if (ifindex == 0)
		goto interface_down;

	service->web = g_web_new(ifindex);
	if (service->web == NULL)
		return;

	/* Sometimes no proxy is reported as string instead of NULL */
	if (g_strcmp0(proxy, "") != 0)
		g_web_set_proxy(service->web, proxy);

	process_request_queue(service);

	return;

interface_down:
	if (service->current_request_id > 0)
		g_web_cancel_request(service->web, service->current_request_id);
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

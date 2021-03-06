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
#define CHUNK_SIZE 2048                 /* 2 Kib */
#define DEFAULT_CONTENT_TYPE "application/vnd.wap.mms-message"

#define CT_MUTLIPART "Content-Type: \"application/vnd.wap.multipart."
#define CT_TYPE ";type=\"application/smil\""
#define CT_START ";start=\"<SMIL>\""
#define CT_MULTIPART_RELATED CT_MUTLIPART "related\"" CT_TYPE CT_START
#define CT_MULTIPART_MIXED CT_MUTLIPART "mixed\""
#define CONTENT_ID_SMIL "SMIL"
#define CONTENT_TYPE_APP_SMIL "Content-Type: \"application/smil\";charset=utf-8"

#define MAX_ATTACHMENTS_NUMBER 25
#define MAX_ATTEMPTS 3

#define SETTINGS_STORE "mms"
#define SETTINGS_GROUP "Settings"

#define uninitialized_var(x) x = x

static const char *ctl_chars = "\x01\x02\x03\x04\x05\x06\x07\x08\x0A"
				"\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14"
				"\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E"
				"\x1F\x7F";

static const char *sep_chars = "()<>@,;:\\\"/[]?={} \t";

static const char *delivery_status[] = {
	"none",
	"expired",
	"retrieved",
	"rejected",
	"deferred",
	"indeterminate",
	"forwarded",
	"unreachable"
};

struct mms_request;

typedef gboolean (*mms_request_result_cb_t) (struct mms_request *request);

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
	GKeyFile *settings;
	gboolean use_delivery_reports;
};

enum mms_request_type {
	MMS_REQUEST_TYPE_GET,
	MMS_REQUEST_TYPE_POST,
	MMS_REQUEST_TYPE_POST_TMP
};

struct mms_request {
	enum mms_request_type type;
	char *data_path;
	char *location;
	gsize data_size;
	int fd;
	guint16 status;
	guint16 attempt;
	struct mms_service *service;
	mms_request_result_cb_t result_cb;
	struct mms_message *msg;
};

static GList *service_list;

static DBusConnection *connection;

static guint32 transaction_id_start = 0;

static void mms_load_settings(struct mms_service *service)
{
	GError *error;

	service->settings = mms_settings_open(service->identity,
							SETTINGS_STORE);
	if (service->settings == NULL)
		return;

	error = NULL;
	service->use_delivery_reports =
		g_key_file_get_boolean(service->settings, SETTINGS_GROUP,
						"UseDeliveryReports", &error);

	if (error) {
		g_error_free(error);
		g_key_file_set_boolean(service->settings, SETTINGS_GROUP,
						"UseDeliveryReports",
						service->use_delivery_reports);
	}
}

static void mms_request_destroy(struct mms_request *request)
{
	g_free(request->data_path);
	g_free(request->location);
	g_free(request);
}

static struct mms_message *mms_request_steal_message(struct mms_request
								*request)
{
	struct mms_message *msg = request->msg;

	request->msg = NULL;

	return msg;
}

static DBusMessage *msg_delete(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct mms_service *service = user_data;
	struct mms_message *mms;
	const char *path;
	char *uuid;

	path = dbus_message_get_path(msg);

	DBG("message path %s", path);

	mms = g_hash_table_lookup(service->messages, path);
	if (mms == NULL)
		return __mms_error_invalid_args(msg);

	uuid = g_strdup(mms->uuid);

	if (mms_message_unregister(service, path) < 0)
		return __mms_error_invalid_args(msg);

	mms_store_remove(service->identity, uuid);

	g_free(uuid);

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
	struct mms_message *mms;
	const char *path;
	char *state;
	GKeyFile *meta;

	path = dbus_message_get_path(msg);

	DBG("message path %s", path);

	mms = g_hash_table_lookup(service->messages, path);
	if (mms == NULL)
		return __mms_error_invalid_args(msg);

	meta = mms_store_meta_open(service->identity, mms->uuid);

	state = g_key_file_get_string(meta, "info", "state", NULL);
	if (state == NULL) {
		mms_store_meta_close(service->identity, mms->uuid, meta, FALSE);
		return __mms_error_invalid_args(msg);
	}

	if (strcmp(state, "received") != 0 && strcmp(state, "sent") != 0) {
		mms_store_meta_close(service->identity, mms->uuid, meta, FALSE);
		g_free(state);
		return __mms_error_invalid_args(msg);
	}

	g_free(state);

	g_key_file_set_boolean(meta, "info", "read", TRUE);

	mms_store_meta_close(service->identity, mms->uuid, meta, TRUE);

	emit_msg_status_changed(path, "read");

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable message_methods[] = {
	{ GDBUS_METHOD("MarkRead", NULL, NULL, msg_mark_read) },
	{ GDBUS_METHOD("Delete", NULL, NULL, msg_delete) },
	{ }
};

static const GDBusSignalTable message_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
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

static gboolean valid_content_type(const char *ct)
{
	if (strlen(ct) == 0)
		return FALSE;

	if (strpbrk(ct, ctl_chars) != NULL)
		return FALSE;

	if (isspace(*ct) == TRUE)
		return FALSE;

	ct = strpbrk(ct, sep_chars);
	if (ct == NULL)
		return FALSE;

	if (ct[0] != '/')
		return FALSE;

	ct += 1;

	ct = strpbrk(ct, sep_chars);
	if (ct == NULL)
		return TRUE;

	return FALSE;
}

static gboolean mmap_file(const char *path, void **out_pdu, size_t *out_len)
{
	struct stat st;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		mms_error("Failed to open %s", path);
		return FALSE;
	}

	if (fstat(fd, &st) < 0) {
		mms_error("Failed to stat %s", path);
		close(fd);
		return FALSE;
	}

	*out_pdu = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

	close(fd);

	if (*out_pdu == MAP_FAILED) {
		mms_error("Failed to mmap %s", path);
		return FALSE;
	}

	*out_len = st.st_size;

	return TRUE;
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
	unsigned int attach_num = 0;

	dbus_message_iter_recurse(top_iter, &attachments);

	while (dbus_message_iter_get_arg_type(&attachments)
						== DBUS_TYPE_STRUCT) {
		DBusMessageIter entry;
		const char *id;
		const char *ct;
		const char *filename;
		struct mms_attachment *attach;
		void *ptr;

		if (++attach_num > MAX_ATTACHMENTS_NUMBER)
			return FALSE;

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

		if (valid_content_type(ct) == FALSE)
			return FALSE;

		attach = g_try_new0(struct mms_attachment, 1);
		if (attach == NULL)
			return FALSE;

		if (mmap_file(filename, &ptr, &attach->length) == FALSE) {
			g_free(attach);
			return FALSE;
		}

		attach->data = ptr;

		attach->content_id = g_strdup(id);

		if (g_str_has_prefix(ct, "text/") == TRUE)
			attach->content_type = g_strconcat("Content-Type: \"",
							ct,
							"\";charset=utf-8",
							NULL);
		else
			attach->content_type = g_strconcat("Content-Type: \"",
							ct,
							"\"",
							NULL);

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

	if (smil[0] != '\0') {
		struct mms_attachment *attach;

		attach = g_try_new0(struct mms_attachment, 1);
		if (attach == NULL)
			return FALSE;

		attach->content_id = g_strdup(CONTENT_ID_SMIL);
		attach->content_type = g_strdup(CONTENT_TYPE_APP_SMIL);
		attach->length = strlen(smil) + 1;
		attach->data = g_memdup(smil, attach->length);

		msg->attachments = g_slist_append(msg->attachments, attach);

		msg->sr.content_type = g_strdup(CT_MULTIPART_RELATED);
	} else
		msg->sr.content_type = g_strdup(CT_MULTIPART_MIXED);

	if (!dbus_message_iter_next(&top_iter))
		return FALSE;

	if (dbus_message_iter_get_arg_type(&top_iter) != DBUS_TYPE_ARRAY)
		return FALSE;

	return send_message_get_attachments(&top_iter, msg);
}

static struct mms_request *create_request(enum mms_request_type type,
				mms_request_result_cb_t result_cb,
				char *location, struct mms_service *service,
				struct mms_message *msg)
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
	case MMS_REQUEST_TYPE_POST_TMP:
		request->data_path = g_strdup_printf("%s%s", g_get_home_dir(),
						"/.mms/send.XXXXXX.mms");

		break;
	}

	request->fd = g_mkstemp_full(request->data_path,
					O_WRONLY | O_CREAT | O_TRUNC,
							S_IWUSR | S_IRUSR);
	if (request->fd < 0) {
		mms_request_destroy(request);

		return NULL;
	}

	request->result_cb = result_cb;

	request->location = g_strdup(location);

	request->service = service;

	request->msg = msg;

	request->status = 0;

	request->attempt = 0;

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
static void emit_message_added(const struct mms_service *service,
						struct mms_message *msg);

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

static inline char *create_transaction_id(void)
{
	return g_strdup_printf("%08X%s", transaction_id_start++,
					"0123456789ABCDEF0123456789ABCDEF");
}

static gboolean result_request_send_conf(struct mms_request *request)
{
	struct mms_message *msg;
	struct mms_service *service = request->service;
	const char *uuid;
	GKeyFile *meta;
	void *pdu;
	size_t len;
	char *path;

	if (request->msg == NULL)
		return FALSE;

	uuid = request->msg->uuid;

	path = g_strdup_printf("%s/%s/%s", MMS_PATH, service->identity, uuid);

	if (request->status != 200)
		goto error;

	msg = g_try_new0(struct mms_message, 1);
	if (msg == NULL)
		goto error;

	if (mmap_file(request->data_path, &pdu, &len) == FALSE) {
		mms_message_free(msg);
		goto error;
	}

	if (mms_message_decode(pdu, len, msg) == FALSE) {
		mms_error("Failed to decode pdu %s", request->data_path);

		munmap(pdu, len);

		mms_message_free(msg);

		goto error;
	}

	mms_debug("response status : %d", msg->sc.rsp_status);

	munmap(pdu, len);

	unlink(request->data_path);

	meta = mms_store_meta_open(service->identity, uuid);
	if (meta == NULL) {
		mms_message_free(msg);

		goto error;
	}

	g_key_file_set_string(meta, "info", "state", "sent");
	g_key_file_set_string(meta, "info", "id", msg->sc.msgid);

	mms_message_free(msg);

	mms_store_meta_close(service->identity, uuid, meta, TRUE);

	emit_msg_status_changed(path, "sent");

	g_free(path);

	return TRUE;

error:
	if (request->attempt == MAX_ATTEMPTS)
		emit_msg_status_changed(path, "draft");

	g_free(path);

	return FALSE;
}

static void append_message(const char *path, const struct mms_service *service,
				struct mms_message *msg, DBusMessageIter *iter);

static void append_message_entry(char *path, const struct mms_service *service,
				struct mms_message *msg, DBusMessageIter *iter)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &entry);

	append_message(path, service, msg, &entry);

	dbus_message_iter_close_container(iter, &entry);
}

static DBusMessage *get_messages(DBusConnection *conn,
					DBusMessage *dbus_msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter, array;
	const struct mms_service *service = data;
	GHashTableIter table_iter;
	gpointer key, value;

	reply = dbus_message_new_method_return(dbus_msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
							"(oa{sv})", &array);

	g_hash_table_iter_init(&table_iter, service->messages);
	while (g_hash_table_iter_next(&table_iter, &key, &value))
		append_message_entry(key, service, value, &array);

	dbus_message_iter_close_container(&iter, &array);

	return reply;
}

static gint fill_conversation_sort(gconstpointer a, gconstpointer b)
{
	const struct mms_message *msg1 = a;
	const struct mms_message *msg2 = b;
	time_t date1, date2;

	if (msg1->type == MMS_MESSAGE_TYPE_SEND_REQ)
		date1 = msg1->sr.date;
	else
		date1 = msg1->rc.date;

	if (msg2->type == MMS_MESSAGE_TYPE_SEND_REQ)
		date2 = msg2->sr.date;
	else
		date2 = msg2->rc.date;

	if (date1 > date2)
		return 1;

	if (date1 < date2)
		return -1;

	return 0;
}

static gboolean is_recipient(const char *recipients, const char *number)
{
	const char *subrecpts, *subnum;

	/*
	 * Search for "number" substring in "recipients" string,
	 * ignoring '-' and '.' which are valid chars in a phone number
	 */
	while (*recipients != '\0') {
		subrecpts = recipients;
		subnum = number;

		while (*subrecpts != '\0' && *subnum != '\0') {
			if (*subrecpts == *subnum) {
				subrecpts++;
				subnum++;
			} else {
				if (*subrecpts == '-' || *subrecpts == '.') {
					subrecpts++;
					continue;
				}

				if (*subnum == '-' || *subnum == '.') {
					subnum++;
					continue;
				}

				if (*subrecpts != *number)
					subrecpts++;

				break;
			}
		}

		/*
		 * Phone numbers in recipients end with /TYPE=PLMN, so the
		 * wanted number is found if the whole string number is found
		 * and if the matched phone number ends with the wanted number
		 * (i.e.: "/TYPE=PLMN" must follow).
		 */
		if (*subnum == '\0' && *subrecpts == '/')
			return TRUE;

		recipients = subrecpts;
	}

	return FALSE;
}

static GList *fill_conversation(const struct mms_service *service,
				GList *conversation, const char *number)
{
	GHashTableIter table_iter;
	gpointer key, value;

	g_hash_table_iter_init(&table_iter, service->messages);
	while (g_hash_table_iter_next(&table_iter, &key, &value)) {
		struct mms_message *msg = value;
		char *recipients;

		if (msg->type == MMS_MESSAGE_TYPE_SEND_REQ)
			recipients = msg->sr.to;
		else if (msg->type == MMS_MESSAGE_TYPE_RETRIEVE_CONF)
			recipients = msg->rc.from;
		else
			continue;

		if (is_recipient(recipients, number) == TRUE)
			conversation = g_list_insert_sorted(conversation, value,
							fill_conversation_sort);
	}

	return conversation;
}

static DBusMessage *get_conversation(DBusConnection *conn,
					DBusMessage *dbus_msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter, array;
	const struct mms_service *service = data;
	struct mms_message *msg;
	GList *msg_elt = NULL;
	GList *conversation = NULL;
	const char *number;
	unsigned int count, i;

	if (dbus_message_iter_init(dbus_msg, &iter) == FALSE)
		return __mms_error_invalid_args(dbus_msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __mms_error_invalid_args(dbus_msg);

	dbus_message_iter_get_basic(&iter, &number);
	if (number[0] == '\0')
		return __mms_error_invalid_args(dbus_msg);

	if (valid_number_format(number) == FALSE)
		return __mms_error_invalid_args(dbus_msg);

	if (!dbus_message_iter_next(&iter))
		return __mms_error_invalid_args(dbus_msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32)
		return __mms_error_invalid_args(dbus_msg);

	dbus_message_iter_get_basic(&iter, &count);

	reply = dbus_message_new_method_return(dbus_msg);
	if (reply == NULL)
		return __mms_error_trans_failure(dbus_msg);

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
							"(oa{sv})", &array);

	conversation = fill_conversation(service, conversation, number);
	if (conversation == NULL)
		goto out;

	i = 0;

	for (msg_elt = g_list_first(conversation); msg_elt != NULL;
					msg_elt = g_list_next(msg_elt), i++) {
		if (count != 0 && i == count)
			break;
		msg = msg_elt->data;
		append_message_entry(msg->path, service, msg, &array);
	}
out:
	dbus_message_iter_close_container(&iter, &array);

	return reply;
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct mms_service *service = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	mms_dbus_dict_open(&iter, &dict);

	mms_dbus_dict_append_basic(&dict, "UseDeliveryReports",
					DBUS_TYPE_BOOLEAN,
					&service->use_delivery_reports);

	mms_dbus_dict_close(&iter, &dict);

	return reply;
}

static DBusMessage *set_property(DBusConnection *conn, DBusMessage *dbus_msg,
								void *data)
{
	struct mms_service *service = data;
	DBusMessageIter iter;
	DBusMessageIter var;
	const char *property;

	if (!dbus_message_iter_init(dbus_msg, &iter))
		return __mms_error_invalid_args(dbus_msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __mms_error_invalid_args(dbus_msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __mms_error_invalid_args(dbus_msg);

	dbus_message_iter_recurse(&iter, &var);

	if (!strcmp(property, "UseDeliveryReports")) {
		dbus_bool_t value;

		if (dbus_message_iter_get_arg_type(&var) != DBUS_TYPE_BOOLEAN)
			return __mms_error_invalid_args(dbus_msg);

		dbus_message_iter_get_basic(&var, &value);

		if (service->use_delivery_reports != (gboolean) value) {
			DBG("use_delivery_reports = %d", value);

			service->use_delivery_reports = value;
		}

		return g_dbus_create_reply(dbus_msg, DBUS_TYPE_INVALID);
	}

	return __mms_error_invalid_args(dbus_msg);
}

static gboolean mms_attachment_is_smil(const struct mms_attachment *part)
{
	if (g_str_has_prefix(part->content_type, "application/smil"))
		return TRUE;

	return FALSE;
}

static void release_data(gpointer data, gpointer user_data)
{
	struct mms_attachment *attach = data;

	if (mms_attachment_is_smil(attach))
		g_free(attach->data);
	else
		munmap(attach->data, attach->length);
}

static void release_attachement_data(GSList *attach)
{
	if (attach != NULL)
		g_slist_foreach(attach, release_data, NULL);
}

static DBusMessage *send_message(DBusConnection *conn,
					DBusMessage *dbus_msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	struct mms_message *msg;
	struct mms_service *service = data;
	struct mms_request *request;
	GKeyFile *meta;

	msg = g_new0(struct mms_message, 1);
	if (msg == NULL)
		return __mms_error_trans_failure(dbus_msg);

	msg->type = MMS_MESSAGE_TYPE_SEND_REQ;
	msg->version = MMS_MESSAGE_VERSION_1_0;

	msg->sr.status = MMS_MESSAGE_STATUS_DRAFT;

	msg->sr.dr = service->use_delivery_reports;

	if (send_message_get_args(dbus_msg, msg) == FALSE) {
		mms_debug("Invalid arguments");

		release_attachement_data(msg->attachments);

		mms_message_free(msg);

		return __mms_error_invalid_args(dbus_msg);
	}

	msg->transaction_id = create_transaction_id();
	if (msg->transaction_id == NULL)
		goto release_msg;

	request = create_request(MMS_REQUEST_TYPE_POST,
				result_request_send_conf, NULL, service, msg);
	if (request == NULL)
		goto release_msg;

	if (mms_message_encode(msg, request->fd) == FALSE)
		goto release_request;

	close(request->fd);

	request->fd = -1;

	msg->uuid = g_strdup(mms_store_file(service->identity,
						request->data_path));
	if (msg->uuid == NULL)
		goto release_request;

	g_free(request->data_path);

	request->data_path = g_strdup_printf("%s/.mms/%s/%s", g_get_home_dir(),
						service->identity, msg->uuid);

	meta = mms_store_meta_open(service->identity, msg->uuid);
	if (meta == NULL)
		goto release_request;

	g_key_file_set_string(meta, "info", "state", "draft");

	if (service->use_delivery_reports) {
		char **tos;
		int i;

		tos = g_strsplit(msg->sr.to, ",", 0);

		for (i = 0; tos[i] != NULL; i++) {
			char *to = g_strdup(tos[i]);

			mms_address_to_string(to);

			DBG("%s=%s", to, delivery_status[0]);

			g_key_file_set_string(meta, "delivery_status", to,
							delivery_status[0]);

			g_free(to);
		}

		g_strfreev(tos);
	}

	mms_store_meta_close(service->identity, msg->uuid, meta, TRUE);

	if (mms_message_register(service, msg) < 0)
		goto release_request;

	emit_message_added(service, msg);

	release_attachement_data(msg->attachments);

	g_queue_push_tail(service->request_queue, request);

	activate_bearer(service);

	reply = dbus_message_new_method_return(dbus_msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
								&msg->path);

	return reply;

release_request:
	unlink(request->data_path);
	mms_request_destroy(request);

release_msg:
	release_attachement_data(msg->attachments);
	mms_message_free(msg);

	return __mms_error_trans_failure(dbus_msg);
}

static const GDBusMethodTable service_methods[] = {
	{ GDBUS_METHOD("SendMessage",
			GDBUS_ARGS({ "recipients", "as" }, { "smil", "s" },
						{ "attachments", "a(sss)" }),
			GDBUS_ARGS({ "path", "o" }),
			send_message) },
	{ GDBUS_METHOD("GetMessages",
			NULL,
			GDBUS_ARGS({ "messages_with_properties", "a(oa{sv})" }),
			get_messages) },
	{ GDBUS_METHOD("GetConversation",
			GDBUS_ARGS({ "number", "s" }, { "count", "s" }),
			GDBUS_ARGS({ "messages_with_properties", "a(oa{sv}" }),
			get_conversation) },
	{ GDBUS_METHOD("SetProperty",
			GDBUS_ARGS({ "property", "s" }, { "value", "v" }),
			NULL,
			set_property) },
	{ GDBUS_METHOD("GetProperties",
			NULL,
			GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ }
};

static const GDBusSignalTable service_signals[] = {
	{ GDBUS_SIGNAL("MessageAdded", GDBUS_ARGS({ "path", "o" },
						{ "properties", "a{sv}" })) },
	{ GDBUS_SIGNAL("MessageRemoved", GDBUS_ARGS({ "path", "o" })) },
	{ }
};

static void destroy_message(gpointer data)
{
	struct mms_message *mms = data;

	mms_message_free(mms);
}

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
							NULL, destroy_message);
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

static void unregister_message(gpointer key, gpointer value, gpointer user_data)
{
	struct mms_service *service = user_data;
	struct mms_message *msg = value;

	mms_message_unregister(service, msg->path);
}

static void destroy_message_table(struct mms_service *service)
{
	if (service->messages == NULL)
		return;

	/*
	 * Each message is first unregistered from dbus, then destroyed from
	 * the hash table.
	 * This step is required because we need access to mms_service when
	 * unregistering the message object.
	 */
	g_hash_table_foreach(service->messages, unregister_message, service);

	g_hash_table_destroy(service->messages);
	service->messages = NULL;
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

	destroy_message_table(service);

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

static gboolean load_message_from_store(const char *service_id,
				const char *uuid, struct mms_message *msg)
{
	GKeyFile *meta;
	char *state = NULL;
	gboolean read_status;
	char *data_path = NULL;
	gboolean success = FALSE;
	gboolean tainted = FALSE;
	void *pdu;
	size_t len;

	meta = mms_store_meta_open(service_id, uuid);
	if (meta == NULL)
		return FALSE;

	state = g_key_file_get_string(meta, "info", "state", NULL);
	if (state == NULL)
		goto out;

	read_status = g_key_file_get_boolean(meta, "info", "read", NULL);

	data_path = mms_store_get_path(service_id, uuid);
	if (data_path == NULL)
		goto out;

	if (mmap_file(data_path, &pdu, &len) == FALSE)
		goto out;

	if (mms_message_decode(pdu, len, msg) == FALSE) {
		mms_error("Failed to decode %s", data_path);
		munmap(pdu, len);
		tainted = TRUE;
		goto out;
	}

	munmap(pdu, len);

	msg->uuid = g_strdup(uuid);

	if (strcmp(state, "received") == 0
			&& msg->type == MMS_MESSAGE_TYPE_RETRIEVE_CONF) {
		if (read_status == TRUE)
			msg->rc.status = MMS_MESSAGE_STATUS_READ;
		else
			msg->rc.status = MMS_MESSAGE_STATUS_RECEIVED;
	} else if (strcmp(state, "downloaded") == 0
			&& msg->type == MMS_MESSAGE_TYPE_RETRIEVE_CONF) {
		msg->rc.status = MMS_MESSAGE_STATUS_DOWNLOADED;
		if (msg->transaction_id == NULL)
			msg->transaction_id = "";
	} else if (strcmp(state, "sent") == 0
			&& msg->type == MMS_MESSAGE_TYPE_SEND_REQ)
		msg->sr.status = MMS_MESSAGE_STATUS_SENT;
	else if (strcmp(state, "draft") == 0
			&& msg->type == MMS_MESSAGE_TYPE_SEND_REQ)
		msg->sr.status = MMS_MESSAGE_STATUS_DRAFT;
	else if (msg->type != MMS_MESSAGE_TYPE_NOTIFICATION_IND &&
			msg->type != MMS_MESSAGE_TYPE_DELIVERY_IND)
		goto out;

	success = TRUE;

out:
	g_free(state);
	g_free(data_path);

	mms_store_meta_close(service_id, uuid, meta, FALSE);

	if (tainted == TRUE)
		mms_store_remove(service_id, uuid);

	return success;
}

static gboolean result_request_retrieve_conf(struct mms_request *request);
static gboolean result_request_notify_resp(struct mms_request *request);

static struct mms_request *build_notify_resp_ind(struct mms_service *service,
					enum mms_message_notify_status status,
					struct mms_message *rc_msg)
{
	struct mms_message *ni_msg;
	struct mms_request *notify_request;
	gboolean result;

	ni_msg = g_try_new0(struct mms_message, 1);
	if (ni_msg == NULL)
		return NULL;

	ni_msg->type = MMS_MESSAGE_TYPE_NOTIFYRESP_IND;
	ni_msg->version = MMS_MESSAGE_VERSION_1_0;
	ni_msg->transaction_id = g_strdup(rc_msg->transaction_id);
	ni_msg->nri.notify_status = status;

	notify_request = create_request(MMS_REQUEST_TYPE_POST_TMP,
					result_request_notify_resp,
					NULL, service, rc_msg);

	if (notify_request == NULL) {
		mms_message_free(ni_msg);
		return NULL;
	}

	if (status == MMS_MESSAGE_NOTIFY_STATUS_UNRECOGNISED)
		notify_request->msg = NULL;

	result = mms_message_encode(ni_msg, notify_request->fd);

	close(notify_request->fd);

	notify_request->fd = -1;

	mms_message_free(ni_msg);

	if (result == FALSE) {
		unlink(notify_request->data_path);
		mms_request_destroy(notify_request);

		return NULL;
	}

	return notify_request;
}

static void process_message_on_start(struct mms_service *service,
							const char *uuid)
{
	struct mms_message *msg;
	struct mms_request *request;
	const char *service_id = service->identity;

	msg = g_try_new0(struct mms_message, 1);
	if (msg == NULL)
		return;

	if (load_message_from_store(service_id, uuid, msg) == FALSE) {
		mms_message_free(msg);
		return;
	}

	if (msg->type == MMS_MESSAGE_TYPE_NOTIFICATION_IND) {
		char *location = g_strdup(msg->ni.location);

		request = create_request(MMS_REQUEST_TYPE_GET,
					result_request_retrieve_conf,
					location, service, msg);
		if (request == NULL) {
			mms_message_free(msg);
			g_free(location);
			return;
		}
	} else if (msg->type == MMS_MESSAGE_TYPE_SEND_REQ) {
		if (msg->sr.status == MMS_MESSAGE_STATUS_DRAFT) {
			request = create_request(MMS_REQUEST_TYPE_POST,
				result_request_send_conf, NULL, service, NULL);
			if (request == NULL)
				goto register_sr;

			close(request->fd);
			request->fd = -1;

			unlink(request->data_path);
			g_free(request->data_path);
			request->data_path = mms_store_get_path(service_id,
									uuid);

			request->msg = msg;
		} else
			request = NULL;
register_sr:
		mms_message_register(service, msg);
	} else if (msg->type == MMS_MESSAGE_TYPE_RETRIEVE_CONF) {
		if (msg->rc.status == MMS_MESSAGE_STATUS_DOWNLOADED) {
			request = build_notify_resp_ind(service,
					MMS_MESSAGE_NOTIFY_STATUS_RETRIEVED,
					msg);
			if (request == NULL)
				mms_message_free(msg);
		} else {
			request = NULL;
			mms_message_register(service, msg);
		}
	} else if (msg->type == MMS_MESSAGE_TYPE_DELIVERY_IND) {
		request = NULL;
	} else
		request = NULL;

	if (request != NULL) {
		g_queue_push_tail(service->request_queue, request);
		activate_bearer(service);
	}
}

static void load_messages(struct mms_service *service)
{
	GDir *dir;
	const char *file;
	const char *homedir;
	char *service_path;

	homedir = g_get_home_dir();
	if (homedir == NULL)
		return;

	service_path = g_strdup_printf("%s/.mms/%s/", homedir,
							service->identity);

	dir = g_dir_open(service_path, 0, NULL);
	g_free(service_path);
	if (dir == NULL)
		return;

	while ((file = g_dir_read_name(dir)) != NULL) {
		const size_t suffix_len = 7;
		char *uuid;

		if (g_str_has_suffix(file, ".status") == FALSE)
			continue;
		if (strlen(file) - suffix_len == 0)
			continue;

		uuid = g_strndup(file, strlen(file) - suffix_len);

		process_message_on_start(service, uuid);

		g_free(uuid);
	}

	g_dir_close(dir);
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

	mms_load_settings(service);

	load_messages(service);

	return 0;
}

int mms_service_unregister(struct mms_service *service)
{
	DBG("service %p", service);

	if (service == NULL)
		return -EINVAL;

	if (service->path == NULL)
		return -EINVAL;

	if (service->messages != NULL)
		destroy_message_table(service);

	if (service->settings != NULL) {
		g_key_file_set_boolean(service->settings, SETTINGS_GROUP,
					"UseDeliveryReports",
					service->use_delivery_reports);

		mms_settings_close(service->identity, SETTINGS_STORE,
						service->settings, TRUE);

		service->settings = NULL;
	}

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

static const char *time_to_str(const time_t *t)
{
	static char buf[128];
	struct tm tm;

	strftime(buf, 127, "%Y-%m-%dT%H:%M:%S%z", localtime_r(t, &tm));
	buf[127] = '\0';

	return buf;
}

static void append_attachment_properties(struct mms_attachment *part,
			DBusMessageIter *dict, const char *path,
			DBusMessageIter *part_array)
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
							&path);
	val = part->offset;
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_UINT64, &val);
	val = part->length;
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_UINT64, &val);

	dbus_message_iter_close_container(part_array, &entry);
}

static void append_smil(DBusMessageIter *dict, const char *path,
					const struct mms_attachment *part)
{
	const char *to_codeset = "utf-8";
	char *from_codeset;
	void *data;
	size_t len;
	char *smil;

	if (mmap_file(path, &data, &len) == FALSE)
		return;

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

	munmap(data, len);

	if (smil == NULL) {
		mms_error("Failed to convert smil attachment\n");
		return;
	}

	mms_dbus_dict_append_basic(dict, "Smil", DBUS_TYPE_STRING, &smil);

	g_free(smil);
}

static inline void check_null_content_id(struct mms_attachment *attachment)
{
	if (attachment->content_id == NULL)
		attachment->content_id = g_strdup("");
}

static void append_msg_attachments(DBusMessageIter *dict, const char *path,
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
		check_null_content_id(part->data);

		if (mms_attachment_is_smil(part->data))
			smil = part->data;
		else
			append_attachment_properties(part->data, dict, path,
									&array);
	}

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(&entry, &variant);

	dbus_message_iter_close_container(dict, &entry);

	if (smil == NULL)
		return;

	switch (msg->type) {
	case MMS_MESSAGE_TYPE_SEND_REQ:
		append_smil(dict, path, smil);
		return;
	case MMS_MESSAGE_TYPE_SEND_CONF:
		return;
	case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
		return;
	case MMS_MESSAGE_TYPE_NOTIFYRESP_IND:
		return;
	case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
		append_smil(dict, path, smil);
		break;
	case MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND:
		return;
	case MMS_MESSAGE_TYPE_DELIVERY_IND:
		return;
	}
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
	const char *status = mms_message_status_get_string(msg->sr.status);

	mms_dbus_dict_append_basic(dict, "Status",
					DBUS_TYPE_STRING, &status);

	mms_dbus_dict_append_basic(dict, "Date",
					DBUS_TYPE_STRING,  &date);

	if (msg->sr.to != NULL)
		append_msg_recipients(dict, msg);
}

static void append_message(const char *path, const struct mms_service *service,
				struct mms_message *msg, DBusMessageIter *iter)
{
	DBusMessageIter dict;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	mms_dbus_dict_open(iter, &dict);

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

	if (msg->attachments != NULL) {
		char *pdu_path = mms_store_get_path(service->identity,
								msg->uuid);
		append_msg_attachments(&dict, pdu_path, msg);
		g_free(pdu_path);
	}

	mms_dbus_dict_close(iter, &dict);
}

static void emit_message_added(const struct mms_service *service,
						struct mms_message *msg)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	DBG("message %p", msg);

	signal = dbus_message_new_signal(service->path, MMS_SERVICE_INTERFACE,
							"MessageAdded");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);

	append_message(msg->path, service, msg, &iter);

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
		return -EIO;
	}

	g_hash_table_replace(service->messages, msg->path, msg);

	DBG("message registered %s", msg->path);

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

	DBG("message unregistered %s", msg_path);

	g_hash_table_remove(service->messages, msg_path);

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

static inline gboolean bearer_is_active(struct mms_service *service)
{
	if (service->bearer_setup == TRUE)
		return FALSE;

	if (service->bearer_handler == NULL)
		return FALSE;

	return service->bearer_active;
}

static void deactivate_bearer(struct mms_service *service)
{
	DBG("service %p", service);

	if (bearer_is_active(service) == FALSE)
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

static gboolean result_request_notify_resp(struct mms_request *request)
{
	struct mms_message *msg;
	GKeyFile *meta;

	unlink(request->data_path);

	if (request->status != 200) {
		mms_error("POST m.notify.resp.ind failed with status %d",
						request->status);
		return FALSE;
	}

	if (request->msg == NULL)
		return FALSE;

	msg = mms_request_steal_message(request);

	if (mms_message_register(request->service, msg) != 0) {
		mms_message_free(msg);
		return FALSE;
	}

	emit_message_added(request->service, msg);

	meta = mms_store_meta_open(request->service->identity,
					msg->uuid);
	if (meta == NULL)
		return FALSE;

	g_key_file_set_string(meta, "info", "state", "received");

	mms_store_meta_close(request->service->identity,
				msg->uuid, meta, TRUE);

	return TRUE;
}

static gboolean result_request_retrieve_conf(struct mms_request *request)
{
	struct mms_message *msg;
	struct mms_service *service = request->service;
	const char *uuid;
	GKeyFile *meta;
	void *pdu;
	size_t len;
	struct mms_request *notify_request;
	gboolean decode_success;

	if (request->status != 200)
		return FALSE;

	if (mmap_file(request->data_path, &pdu, &len) == FALSE)
		return FALSE;

	uuid = mms_store_file(service->identity, request->data_path);
	if (uuid == NULL)
		goto exit;

	msg = g_try_new0(struct mms_message, 1);
	if (msg == NULL)
		goto exit;

	decode_success = mms_message_decode(pdu, len, msg);

	msg->transaction_id = g_strdup(request->msg->transaction_id);

	if (decode_success == TRUE) {
		msg->uuid = g_strdup(uuid);

		meta = mms_store_meta_open(service->identity, uuid);
		if (meta == NULL)
			goto error;

		g_key_file_set_boolean(meta, "info", "read", FALSE);
		g_key_file_set_string(meta, "info", "state", "downloaded");

		mms_store_meta_close(service->identity, uuid, meta, TRUE);

		notify_request = build_notify_resp_ind(service,
					MMS_MESSAGE_NOTIFY_STATUS_RETRIEVED,
					msg);
	} else {
		mms_error("Failed to decode %s", request->data_path);

		notify_request = build_notify_resp_ind(service,
				MMS_MESSAGE_NOTIFY_STATUS_UNRECOGNISED, msg);
	}

	/* Remove notify.ind pdu */
	mms_store_remove(service->identity, request->msg->uuid);

	if (notify_request == NULL)
		goto error;

	g_queue_push_tail(service->request_queue, notify_request);
	activate_bearer(service);

	if (decode_success == TRUE)
		goto exit;

error:
	mms_store_remove(service->identity, uuid);
	mms_message_free(msg);

exit:
	munmap(pdu, len);
	return TRUE;
}

static gboolean mms_requeue_request(struct mms_request *request)
{
	request->attempt += 1;

	if (request->attempt == MAX_ATTEMPTS)
		return FALSE;

	if (request->type == MMS_REQUEST_TYPE_GET) {
		request->fd = open(request->data_path, O_WRONLY | O_TRUNC,
							S_IWUSR | S_IRUSR);
		if (request->fd < 0)
			return FALSE;
	}

	g_queue_push_tail(request->service->request_queue, request);

	return TRUE;
}

static gboolean web_get_cb(GWebResult *result, gpointer user_data)
{
	gsize written;
	gsize chunk_size;
	struct mms_request *request = user_data;
	const guint8 *chunk;

	if (g_web_result_get_chunk(result, &chunk, &chunk_size) == FALSE) {
		mms_error("Fail to get data chunk");
		goto complete;
	}

	if (chunk_size == 0) {
		request->status = g_web_result_get_status(result);

		DBG("status: %03u", request->status);
		DBG("data size = %zd", request->data_size);

		goto complete;
	}

	request->data_size += chunk_size;

	written = write(request->fd, chunk, chunk_size);

	if (written != chunk_size) {
		mms_error("only %zd/%zd bytes written\n", written, chunk_size);
		goto complete;
	}

	return TRUE;

complete:
	close(request->fd);

	if (request->result_cb == NULL || request->result_cb(request) == TRUE)
		mms_request_destroy(request);
	else {
		mms_error("Fail to get data (http status = %03u)",
							request->status);
		if (mms_requeue_request(request) == TRUE)
			mms_error("retry later");
		else {
			unlink(request->data_path);
			mms_request_destroy(request);
		}
	}

	request->service->current_request_id = 0;

	process_request_queue(request->service);

	return FALSE;
}

static gboolean web_post_result_cb(GWebResult *result, gpointer user_data)
{
	struct mms_request *req = user_data;

	if (req->fd == -1) {
		if (req->type == MMS_REQUEST_TYPE_POST_TMP)
			unlink(req->data_path);

		DBG("Send <%s> complete", req->data_path);

		/* post complete, prepare for response reception */

		g_free(req->data_path);

		req->data_path = g_strdup_printf("%s/.mms/post-rsp.XXXXXX.mms",
							g_get_home_dir());

		req->fd = g_mkstemp_full(req->data_path,
						O_WRONLY | O_CREAT | O_TRUNC,
							S_IWUSR | S_IRUSR);
	}

	return web_get_cb(result, user_data);
}

static guint process_request(struct mms_request *request)
{
	struct mms_service *service = request->service;
	guint id;

	if (request->data_path == NULL)
		return 0;

	switch (request->type) {
	case MMS_REQUEST_TYPE_GET:
		id = g_web_request_get(service->web, request->location,
					web_get_cb, NULL, request);
		if (id == 0) {
			close(request->fd);
			break;
		}

		return id;

	case MMS_REQUEST_TYPE_POST:
	case MMS_REQUEST_TYPE_POST_TMP:
		id = g_web_request_post_file(service->web, service->mmsc,
						DEFAULT_CONTENT_TYPE,
						request->data_path,
						web_post_result_cb, request);
		if (id == 0)
			break;

		return id;
	}

	mms_error("Cannot process request (request type: %d)", request->type);

	unlink(request->data_path);

	mms_request_destroy(request);

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
		if (bearer_is_active(service) == FALSE)
			return;

		request = g_queue_pop_head(service->request_queue);
		if (request == NULL)
			break;

		DBG("location %s", request->location);

		service->current_request_id = process_request(request);
		if (service->current_request_id > 0)
			return;
	}

	service->bearer_timeout = g_timeout_add_seconds(BEARER_IDLE_TIMEOUT,
						bearer_idle_timeout, service);
}

static void dump_delivery_ind(struct mms_message *msg)
{
	char buf[128];

	strftime(buf, 127, "%Y-%m-%dT%H:%M:%S%z", localtime(&msg->di.date));
	buf[127] = '\0';

	mms_info("MMS version: %u.%u\n", (msg->version & 0x70) >> 4,
						msg->version & 0x0f);
	mms_info("Msg ID: %s\n", msg->di.msgid);
	mms_info("To: %s\n", msg->di.to);
	mms_info("Date: %s\n", buf);
	mms_info("Delivery Report status: %d\n", msg->di.dr_status);
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
	struct mms_message *msg;
	unsigned int nread;
	const char *uuid;
	GKeyFile *meta;

	DBG("service %p data %p len %d", service, data, len);

	msg = g_try_new0(struct mms_message, 1);
	if (msg == NULL) {
		mms_error("Failed to allocate message");
		return;
	}

	if (mms_push_notify(data, len, &nread) == FALSE)
		goto out;

	uuid = mms_store(service->identity, data + nread, len - nread);
	if (uuid == NULL)
		goto out;

	if (mms_message_decode(data + nread, len - nread, msg) == FALSE)
		goto error;

	if (msg->type == MMS_MESSAGE_TYPE_DELIVERY_IND) {
		msg->uuid = g_strdup(uuid);

		dump_delivery_ind(msg);

		meta = mms_store_meta_open(service->identity, uuid);
		if (meta == NULL)
			goto error;

		g_key_file_set_string(meta, "info", "state", "notification");

		mms_store_meta_close(service->identity, uuid, meta, TRUE);

		return;
	}

	if (msg->type != MMS_MESSAGE_TYPE_NOTIFICATION_IND)
		goto error;

	msg->uuid = g_strdup(uuid);

	dump_notification_ind(msg);

	meta = mms_store_meta_open(service->identity, uuid);
	if (meta == NULL)
		goto error;

	g_key_file_set_boolean(meta, "info", "read", FALSE);

	g_key_file_set_string(meta, "info", "state", "notification");

	mms_store_meta_close(service->identity, uuid, meta, TRUE);

	request = create_request(MMS_REQUEST_TYPE_GET,
				result_request_retrieve_conf,
				msg->ni.location, service, msg);
	if (request == NULL)
		goto out;

	g_queue_push_tail(service->request_queue, request);

	activate_bearer(service);

	return;

error:
	mms_store_remove(service->identity, uuid);

out:
	mms_message_free(msg);

	mms_error("Failed to handle incoming notification");
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

static const GDBusMethodTable manager_methods[] = {
	{ GDBUS_METHOD("GetServices", NULL,
			GDBUS_ARGS({ "services_with_properties", "a(oa{sv})" }),
			get_services) },
	{ }
};

static const GDBusSignalTable manager_signals[] = {
	{ GDBUS_SIGNAL("ServiceAdded", GDBUS_ARGS({ "path", "o" },
						{ "properties", "a{sv}" })) },
	{ GDBUS_SIGNAL("ServiceRemoved", GDBUS_ARGS({ "path", "o" })) },
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

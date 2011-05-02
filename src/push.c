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
#include <string.h>

#include <glib.h>

#include "wsputil.h"

#include "mms.h"

#define MMS_CONTENT_TYPE "application/vnd.wap.mms-message"
#define MMS_CONSUMER_INTERFACE "org.ofono.mms.PushConsumer"
#define MMS_CONSUMER_METHOD "Notify"

#define MMS_CONSUMER_KEY_MATCH_CONTENT_TYPE	"MatchContentType"
#define MMS_CONSUMER_KEY_MATCH_APPLICATION_ID	"MatchApplicationId"
#define MMS_CONSUMER_KEY_TARGET_BUS		"TargetBus"
#define MMS_CONSUMER_KEY_TARGET_SERVICE		"TargetService"
#define MMS_CONSUMER_KEY_TARGET_PATH		"TargetPath"

static const char *mms_consumer_possible_keys[] = {
	MMS_CONSUMER_KEY_MATCH_CONTENT_TYPE,
	MMS_CONSUMER_KEY_MATCH_APPLICATION_ID,
	MMS_CONSUMER_KEY_TARGET_BUS,
	MMS_CONSUMER_KEY_TARGET_SERVICE,
	MMS_CONSUMER_KEY_TARGET_PATH,
	NULL,
};

struct push_consumer {
	char *group;
	char *type;
	char *app_id;
	char *bus;
	char *service;
	char *path;
};

static GSList *pc_list;

static void dump_push_consumer(struct push_consumer *pc)
{
	mms_debug("consumer group: [%s] <%p>", pc->group, pc);
	mms_debug("type: %s", pc->type);
	mms_debug("app_id: %s", pc->app_id);
	mms_debug("targetbus: %s\n", pc->bus);
	mms_debug("service: %s\n", pc->service);
	mms_debug("path: %s\n", pc->path);
}

static void push_consumer_free(gpointer data, gpointer user_data)
{
	struct push_consumer *pc = data;

	g_free(pc->group);
	g_free(pc->type);
	g_free(pc->app_id);
	g_free(pc->bus);
	g_free(pc->service);
	g_free(pc->path);
	g_free(pc);
}

static void check_keys(GKeyFile *keyfile, const char *group,
			const char **possible_keys)
{
	char **avail_keys;
	gsize nb_avail_keys, i, j;

	avail_keys = g_key_file_get_keys(keyfile, group, &nb_avail_keys, NULL);
	if (avail_keys == NULL)
		return;

	/*
	 * For each key in the configuration file,
	 * verify it is understood by mmsd
	 */
	for (i = 0 ; i < nb_avail_keys; i++) {
		for (j = 0; possible_keys[j] ; j++)
			if (g_strcmp0(avail_keys[i], possible_keys[j]) == 0)
				break;

		if (possible_keys[j] == NULL)
			mms_warn("Unknown configuration key %s in [%s]",
					avail_keys[i], group);
	}

	g_strfreev(avail_keys);
}

static struct push_consumer *create_consumer(GKeyFile *keyfile,
						const char *group)
{
	struct push_consumer *pc;

	pc = g_try_new0(struct push_consumer, 1);
	if (pc == NULL)
		return NULL;

	pc->group = g_strdup(group);

	pc->type = g_key_file_get_string(keyfile, group,
				MMS_CONSUMER_KEY_MATCH_CONTENT_TYPE, NULL);
	if (pc->type == NULL)
		goto out;

	pc->app_id = g_key_file_get_string(keyfile, group,
				MMS_CONSUMER_KEY_MATCH_APPLICATION_ID, NULL);

	pc->bus = g_key_file_get_string(keyfile, group,
				MMS_CONSUMER_KEY_TARGET_BUS, NULL);
	if (pc->bus == NULL)
		pc->bus = g_strdup("session");
	else if (g_str_equal(pc->bus, "session") == FALSE)
		goto out;

	pc->service = g_key_file_get_string(keyfile, group,
				MMS_CONSUMER_KEY_TARGET_SERVICE, NULL);
	if (pc->service == NULL)
		goto out;

	pc->path = g_key_file_get_string(keyfile, group,
				MMS_CONSUMER_KEY_TARGET_PATH, NULL);
	if (pc->path == NULL)
		goto out;

	dump_push_consumer(pc);

	return pc;

out:
	mms_warn("Invalid or missing mandatory information for %s", group);

	push_consumer_free(pc, NULL);

	return NULL;
}

static void parse_config_file(const char *filename)
{
	GKeyFile *keyfile;
	GError *err = NULL;
	char **consumers;
	int i;

	DBG("filename %s", filename);

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (!g_key_file_load_from_file(keyfile, filename, 0, &err)) {
		mms_warn("Reading of %s failed: %s", filename, err->message);
		g_error_free(err);
		goto done;
	}

	consumers = g_key_file_get_groups(keyfile, NULL);

	for (i = 0; consumers[i]; i++) {
		struct push_consumer *pc;

		/* Verify that provided keys are good */
		check_keys(keyfile, consumers[i], mms_consumer_possible_keys);

		pc = create_consumer(keyfile, consumers[i]);
		if (pc == NULL)
			continue;

		pc_list = g_slist_prepend(pc_list, pc);
	}

	g_strfreev(consumers);

done:
	g_key_file_free(keyfile);
}

int __mms_push_config_files_init(void)
{
	GDir *dir;
	const char *file;
	char *filename;

	dir = g_dir_open(PUSHCONFDIR, 0, NULL);
	if (dir == NULL)
		return -EIO;

	while ((file = g_dir_read_name(dir)) != NULL) {
		if (g_str_has_suffix(file, ".conf") == FALSE)
			continue;

		filename = g_build_filename(PUSHCONFDIR, file, NULL);
		if (filename == NULL)
			continue;

		parse_config_file(filename);

		g_free(filename);
	}

	g_dir_close(dir);

	return 0;
}

void __mms_push_config_files_cleanup(void)
{
	g_slist_foreach(pc_list, push_consumer_free, NULL);

	g_slist_free(pc_list);
	pc_list = NULL;
}

static void mms_push_send_msg_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;

	dbus_error_init(&err);

	if (dbus_set_error_from_message(&err, reply) == TRUE)
		dbus_error_free(&err);

	dbus_message_unref(reply);
}

static gboolean mms_push_send_msg(const unsigned char *pdu, unsigned int msglen,
			unsigned int hdrlen, const struct push_consumer *hdlr)
{
	DBusConnection *conn = mms_dbus_get_connection();
	DBusMessage *msg;
	DBusPendingCall *call;
	DBusMessageIter iter;
	DBusMessageIter hdr_array;
	DBusMessageIter body_array;

	msg = dbus_message_new_method_call(hdlr->service, hdlr->path,
				MMS_CONSUMER_INTERFACE, MMS_CONSUMER_METHOD);
	if (msg == NULL) {
		mms_error("Can't allocate new message");
		return FALSE;
	}

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &hdr_array);

	dbus_message_iter_append_fixed_array(&hdr_array, DBUS_TYPE_BYTE,
						&pdu, hdrlen);

	dbus_message_iter_close_container(&iter, &hdr_array);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &body_array);

	pdu += hdrlen;

	dbus_message_iter_append_fixed_array(&body_array, DBUS_TYPE_BYTE,
						&pdu, msglen - hdrlen);

	dbus_message_iter_close_container(&iter, &body_array);

	if (dbus_connection_send_with_reply(conn, msg, &call, -1) == FALSE) {
		mms_error("Failed to execute method call");
		dbus_message_unref(msg);
		return FALSE;
	}

	dbus_message_unref(msg);

	if (call == NULL) {
		mms_error("D-Bus connection not available");
		return FALSE;
	}

	dbus_pending_call_set_notify(call, mms_push_send_msg_reply, NULL, NULL);

	dbus_pending_call_unref(call);

	return TRUE;
}

gboolean mms_push_notify(unsigned char *pdu, unsigned int len,
						unsigned int *offset)
{
	unsigned int headerslen;
	const void *ct;
	const void *aid;
	struct wsp_header_iter iter;
	unsigned int nread;
	unsigned int consumed;
	struct push_consumer *hdlr;
	unsigned int i;
	GSList *elt;
	GString *hex;

	DBG("pdu %p len %d", pdu, len);

	hex = g_string_sized_new(len * 2);

	for (i = 0; i < len; i++)
		g_string_append_printf(hex, "%02X", pdu[i]);

	DBG("%s", hex->str);

	g_string_free(hex, TRUE);

	/* PUSH pdu ? */
	if (pdu[1] != 0x06)
		return FALSE;

	/* Consume TID and Type */
	nread = 2;

	if (wsp_decode_uintvar(pdu + nread, len,
					&headerslen, &consumed) == FALSE)
		return FALSE;

	/* Consume uintvar bytes */
	nread += consumed;

	/* Try to decode content-type */
	if (wsp_decode_content_type(pdu + nread, headerslen, &ct,
					&consumed) == FALSE)
		return FALSE;

	if (ct == NULL)
		return FALSE;

	/* Consume Content Type bytes */
	nread += consumed;

	/* Parse header to decode application_id */
	wsp_header_iter_init(&iter, pdu + nread, headerslen - consumed, 0);

	aid = NULL;

	while (wsp_header_iter_next(&iter)) {
		const unsigned char *wk;

		/* Skip application headers */
		if (wsp_header_iter_get_hdr_type(&iter) !=
					WSP_HEADER_TYPE_WELL_KNOWN)
			continue;

		wk = wsp_header_iter_get_hdr(&iter);

		if ((wk[0] & 0x7f) != WSP_HEADER_TOKEN_APP_ID)
			continue;

		if (wsp_decode_application_id(&iter, &aid) == FALSE)
			return FALSE;
	}

	if (wsp_header_iter_at_end(&iter) == FALSE)
		return FALSE;

	nread += headerslen - consumed;

	mms_info("Body Length: %d\n", len - nread);

	if (g_str_equal(ct, MMS_CONTENT_TYPE) == TRUE) {
		if (offset != NULL)
			*offset = nread;
		return TRUE;
	}

	/* Handle other consumers */
	for (elt = pc_list; elt != NULL; elt = g_slist_next(elt)) {
		hdlr = elt->data;

		if (g_str_equal(hdlr->type, ct) == FALSE)
			continue;

		if (mms_push_send_msg(pdu, len, nread, hdlr) == FALSE) {
			mms_error("Failed to call consumer: [%s]\n",
					hdlr->group);
		}
	}

	return FALSE;
}

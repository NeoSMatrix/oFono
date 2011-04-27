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

#include <glib.h>

#include "wsputil.h"

#include "mms.h"

#define MMS_CONTENT_TYPE "application/vnd.wap.mms-message"

struct push_consumer {
	char *type;
	char *app_id;
	char *bus;
	char *service;
	char *path;
	char *method;
};

static GSList *pc_list;

static void dump_push_consumer(const char *group, struct push_consumer *pc)
{
	mms_debug("[%s] <%p>", group, pc);
	mms_debug("type: %s", pc->type);
	mms_debug("app_id: %s", pc->app_id);
	mms_debug("targetbus: %s\n", pc->bus);
	mms_debug("service: %s\n", pc->service);
	mms_debug("path: %s\n", pc->path);
	mms_debug("method: %s\n", pc->method);
}

static void push_consumer_free(gpointer data, gpointer user_data)
{
	struct push_consumer *pc = data;

	g_free(pc->type);
	g_free(pc->app_id);
	g_free(pc->bus);
	g_free(pc->service);
	g_free(pc->path);
	g_free(pc->method);
	g_free(pc);
}

static struct push_consumer *create_consumer(GKeyFile *keyfile,
						const char *group)
{
	struct push_consumer *pc;

	pc = g_try_new0(struct push_consumer, 1);
	if (pc == NULL)
		return NULL;

	pc->type = g_key_file_get_string(keyfile, group,
						"MatchContentType", NULL);
	if (pc->type == NULL)
		goto out;

	pc->app_id = g_key_file_get_string(keyfile, group,
						"MatchApplicationId", NULL);

	pc->bus = g_key_file_get_string(keyfile, group,
						"TargetBus", NULL);
	if (pc->bus == NULL)
		goto out;

	pc->service = g_key_file_get_string(keyfile, group,
						"TargetService", NULL);
	if (pc->service == NULL)
		goto out;

	pc->path = g_key_file_get_string(keyfile, group,
						"TargetPath", NULL);
	if (pc->path == NULL)
		goto out;

	pc->method = g_key_file_get_string(keyfile, group,
						"TargetMethod", NULL);
	if (pc->method == NULL)
		goto out;

	dump_push_consumer(group, pc);

	return pc;

out:
	mms_warn("Missing mandatory information for %s", group);

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

gboolean mms_push_notify(unsigned char *pdu, unsigned int len,
						unsigned int *offset)
{
	unsigned int headerslen;
	unsigned int content_len;
	enum wsp_value_type content_type;
	const void *content_data;
	struct wsp_header_iter iter;
	unsigned int nread;
	unsigned int consumed;
	unsigned int i;
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
					&headerslen, &consumed) != TRUE)
		return FALSE;

	/* Consume uintvar bytes */
	nread += consumed;

	/* Try to decode content-type */
	if (wsp_decode_field(pdu + nread, headerslen, &content_type,
				&content_data, &content_len, &consumed) != TRUE)
		return FALSE;

	/* Consume Content Type bytes */
	nread += consumed;

	if (content_type != WSP_VALUE_TYPE_TEXT)
		return FALSE;

	if (g_str_equal(content_data, MMS_CONTENT_TYPE) == FALSE)
		return FALSE;

	wsp_header_iter_init(&iter, pdu + nread, headerslen - consumed, 0);

	while (wsp_header_iter_next(&iter));

	if (wsp_header_iter_at_end(&iter) == FALSE)
		return FALSE;

	nread += headerslen - consumed;

	mms_info("Body Length: %d\n", len - nread);

	if (offset != NULL)
		*offset = nread;

return TRUE;
}

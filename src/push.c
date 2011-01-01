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

#include <glib.h>

#include "wsputil.h"
#include "mmsutil.h"

#include "mms.h"

#define MMS_CONTENT_TYPE "application/vnd.wap.mms-message"

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

char *mms_push_notify(unsigned char *pdu, unsigned int len)
{
	unsigned int headerslen;
	unsigned int content_len;
	enum wsp_value_type content_type;
	const void *content_data;
	struct wsp_header_iter iter;
	unsigned int nread;
	unsigned int consumed;
	struct mms_message msg;
	char *result;
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
		return NULL;

	/* Consume TID and Type */
	nread = 2;

	if (wsp_decode_uintvar(pdu + nread, len,
					&headerslen, &consumed) != TRUE)
		return NULL;

	/* Consume uintvar bytes */
	nread += consumed;

	/* Try to decode content-type */
	if (wsp_decode_field(pdu + nread, headerslen, &content_type,
				&content_data, &content_len, &consumed) != TRUE)
		return NULL;

	/* Consume Content Type bytes */
	nread += consumed;

	if (content_type != WSP_VALUE_TYPE_TEXT)
		return NULL;

	if (g_str_equal(content_data, MMS_CONTENT_TYPE) == FALSE)
		return NULL;

	wsp_header_iter_init(&iter, pdu + nread, headerslen - consumed, 0);

	while (wsp_header_iter_next(&iter));

	if (wsp_header_iter_at_end(&iter) == FALSE)
		return NULL;

	nread += headerslen - consumed;

	mms_info("Body Length: %d\n", len - nread);

	mms_store(pdu + nread, len - nread);

	if (mms_message_decode(pdu + nread, len - nread, &msg) == FALSE) {
		mms_message_free(&msg);
		return NULL;
	}

	if (msg.type != MMS_MESSAGE_TYPE_NOTIFICATION_IND) {
		mms_message_free(&msg);
		return NULL;
	}

	dump_notification_ind(&msg);

	result = g_strdup(msg.ni.location);

	mms_message_free(&msg);

	return result;
}

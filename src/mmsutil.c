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

#include <string.h>
#include <time.h>
#include <unistd.h>

#include <glib.h>

#include "wsputil.h"
#include "mmsutil.h"

#define MAX_TRANSACTION_ID_SIZE 40

#define uninitialized_var(x) x = x

typedef gboolean (*header_handler)(struct wsp_header_iter *, void *);

enum header_flag {
	HEADER_FLAG_MANDATORY =			1,
	HEADER_FLAG_MARKED =			8,
};

enum mms_header {
	MMS_HEADER_BCC =			0x01,
	MMS_HEADER_CC =				0x02,
	MMS_HEADER_CONTENT_LOCATION =		0x03,
	MMS_HEADER_CONTENT_TYPE =		0x04,
	MMS_HEADER_DATE =			0x05,
	MMS_HEADER_DELIVERY_REPORT =		0x06,
	MMS_HEADER_DELIVERY_TIME =		0x07,
	MMS_HEADER_EXPIRY =			0x08,
	MMS_HEADER_FROM =			0x09,
	MMS_HEADER_MESSAGE_CLASS =		0x0a,
	MMS_HEADER_MESSAGE_ID =			0x0b,
	MMS_HEADER_MESSAGE_TYPE =		0x0c,
	MMS_HEADER_MMS_VERSION =		0x0d,
	MMS_HEADER_MESSAGE_SIZE =		0x0e,
	MMS_HEADER_PRIORITY =			0x0f,
	MMS_HEADER_READ_REPLY =			0x10,
	MMS_HEADER_REPORT_ALLOWED =		0x11,
	MMS_HEADER_RESPONSE_STATUS =		0x12,
	MMS_HEADER_RESPONSE_TEXT =		0x13,
	MMS_HEADER_SENDER_VISIBILITY =		0x14,
	MMS_HEADER_STATUS =			0x15,
	MMS_HEADER_SUBJECT =			0x16,
	MMS_HEADER_TO =				0x17,
	MMS_HEADER_TRANSACTION_ID =		0x18,
	__MMS_HEADER_MAX =			0x19,
	MMS_HEADER_INVALID =			0x80,
};

/*
 * IANA Character Set Assignments (examples) used by WAPWSP
 *
 * Reference: WAP-230-WSP Appendix Table 42 Character Set Assignment Examples
 * Reference: IANA http://www.iana.org/assignments/character-sets
 */
static const struct {
	unsigned int mib_enum;
	const char *charset;
} charset_assignments[] = {
	{ 0x03,	"us-ascii"	},
	{ 0x6A,	"utf-8"		},
	{ 0x00,	NULL		}
};

#define FB_SIZE 256

struct file_buffer {
	unsigned char buf[FB_SIZE];
	unsigned int size;
	int fd;
};

static const char *charset_index2string(unsigned int index)
{
	unsigned int i = 0;

	for (i = 0; charset_assignments[i].charset; i++) {
		if (charset_assignments[i].mib_enum == index)
			return charset_assignments[i].charset;
	}

	return NULL;
}

static gboolean extract_short(struct wsp_header_iter *iter, void *user)
{
	unsigned char *out = user;
	const unsigned char *p;

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_SHORT)
		return FALSE;

	p = wsp_header_iter_get_val(iter);
	*out = p[0];

	return TRUE;
}

static const char *decode_text(struct wsp_header_iter *iter)
{
	const unsigned char *p;
	unsigned int l;

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_TEXT)
		return NULL;

	p = wsp_header_iter_get_val(iter);
	l = wsp_header_iter_get_val_len(iter);

	return wsp_decode_text(p, l, NULL);
}

static gboolean extract_text(struct wsp_header_iter *iter, void *user)
{
	char **out = user;
	const char *text;

	text = decode_text(iter);
	if (text == NULL)
		return FALSE;

	*out = g_strdup(text);

	return TRUE;
}

static gboolean extract_text_array_element(struct wsp_header_iter *iter,
						void *user)
{
	char **out = user;
	const char *element;
	char *tmp;

	element = decode_text(iter);
	if (element == NULL)
		return FALSE;

	if (*out == NULL) {
		*out = g_strdup(element);
		return TRUE;
	}

	tmp = g_strjoin(",", *out, element, NULL);
	if (tmp == NULL)
		return FALSE;

	g_free(*out);

	*out = tmp;

	return TRUE;
}

static char *decode_encoded_string_with_mib_enum(const unsigned char *p,
		unsigned int l)
{
	unsigned int mib_enum;
	unsigned int consumed;
	const char *text;
	const char *from_codeset;
	const char *to_codeset = "UTF-8";
	gsize bytes_read;
	gsize bytes_written;

	if (wsp_decode_integer(p, l, &mib_enum, &consumed) == FALSE)
		return NULL;

	if (mib_enum == 106) {
		/* header is UTF-8 already */
		text = wsp_decode_text(p + consumed, l - consumed, NULL);

		return g_strdup(text);
	}

	/* convert to UTF-8 */
	from_codeset = charset_index2string(mib_enum);
	if (from_codeset == NULL)
		return NULL;

	return g_convert((const char *) p + consumed, l - consumed,
			to_codeset, from_codeset,
			&bytes_read, &bytes_written, NULL);
}

static gboolean extract_encoded_text(struct wsp_header_iter *iter, void *user)
{
	char **out = user;
	const unsigned char *p;
	unsigned int l;
	const char *text;
	char *uninitialized_var(dec_text);

	p = wsp_header_iter_get_val(iter);
	l = wsp_header_iter_get_val_len(iter);

	switch (wsp_header_iter_get_val_type(iter)) {
	case WSP_VALUE_TYPE_TEXT:
		/* Text-string */
		text = wsp_decode_text(p, l, NULL);
		dec_text = g_strdup(text);
		break;
	case WSP_VALUE_TYPE_LONG:
		/* (Value-len) Char-set Text-string */
		dec_text = decode_encoded_string_with_mib_enum(p, l);
		break;
	case WSP_VALUE_TYPE_SHORT:
		dec_text = NULL;
		break;
	}

	if (dec_text == NULL)
		return FALSE;

	*out = dec_text;

	return TRUE;
}

static gboolean extract_date(struct wsp_header_iter *iter, void *user)
{
	time_t *out = user;
	const unsigned char *p;
	unsigned int l;
	unsigned int i;

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_LONG)
		return FALSE;

	p = wsp_header_iter_get_val(iter);
	l = wsp_header_iter_get_val_len(iter);

	if (l > 4)
		return FALSE;

	for (i = 0, *out = 0; i < l; i++)
		*out = *out << 8 | p[i];

	/* It is possible to overflow time_t on 32 bit systems */
	*out = *out & 0x7fffffff;

	return TRUE;
}

static gboolean extract_absolute_relative_date(struct wsp_header_iter *iter,
						void *user)
{
	time_t *out = user;
	const unsigned char *p;
	unsigned int l;
	unsigned int i;
	unsigned int seconds;

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_LONG)
		return FALSE;

	p = wsp_header_iter_get_val(iter);
	l = wsp_header_iter_get_val_len(iter);

	if (l < 2 || l > 5)
		return FALSE;

	if (p[0] != 128 && p[0] != 129)
		return FALSE;

	for (i = 2, seconds = 0; i < l; i++)
		seconds = seconds << 8 | p[i];

	if (p[0] == 129) {
		*out = time(NULL);
		*out += seconds;
	} else
		*out = seconds;

	/* It is possible to overflow time_t on 32 bit systems */
	*out = *out & 0x7fffffff;

	return TRUE;
}

static gboolean extract_from(struct wsp_header_iter *iter, void *user)
{
	char **out = user;
	const unsigned char *p;
	unsigned int l;
	const char *text;

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_LONG)
		return FALSE;

	p = wsp_header_iter_get_val(iter);
	l = wsp_header_iter_get_val_len(iter);

	if (p[0] != 128 && p[0] != 129)
		return FALSE;

	if (p[0] == 129) {
		*out = NULL;
		return TRUE;
	}

	text = wsp_decode_text(p + 1, l - 1, NULL);
	if (text == NULL)
		return FALSE;

	*out = g_strdup(text);

	return TRUE;
}

static gboolean extract_message_class(struct wsp_header_iter *iter, void *user)
{
	char **out = user;
	const unsigned char *p;
	unsigned int l;
	const char *text;

	if (wsp_header_iter_get_val_type(iter) == WSP_VALUE_TYPE_LONG)
		return FALSE;

	p = wsp_header_iter_get_val(iter);

	if (wsp_header_iter_get_val_type(iter) == WSP_VALUE_TYPE_SHORT) {
		switch (p[0]) {
		case 128:
			*out = g_strdup("Personal");
			return TRUE;
		case 129:
			*out = g_strdup("Advertisement");
			return TRUE;
		case 130:
			*out = g_strdup("Informational");
			return TRUE;
		case 131:
			*out = g_strdup("Auto");
			return TRUE;
		default:
			return FALSE;
		}
	}

	l = wsp_header_iter_get_val_len(iter);

	text = wsp_decode_token_text(p, l, NULL);
	if (text == NULL)
		return FALSE;

	*out = g_strdup(text);

	return TRUE;
}

static gboolean extract_priority(struct wsp_header_iter *iter, void *user)
{
	char **out = user;
	const unsigned char *p;

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_SHORT)
		return FALSE;

	p = wsp_header_iter_get_val(iter);

	switch (p[0]) {
	case 128:
		*out = g_strdup("Low");
		return TRUE;
	case 129:
		*out = g_strdup("Normal");
		return TRUE;
	case 130:
		*out = g_strdup("High");
		return TRUE;
	default:
		return FALSE;
	}

	return TRUE;
}

static gboolean extract_rsp_status(struct wsp_header_iter *iter, void *user)
{
	unsigned char *out = user;
	const unsigned char *p;

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_SHORT)
		return FALSE;

	p = wsp_header_iter_get_val(iter);

	switch (p[0]) {
	case MMS_MESSAGE_RSP_STATUS_OK:
	case MMS_MESSAGE_RSP_STATUS_ERR_UNSUPPORTED_MESSAGE:
	case MMS_MESSAGE_RSP_STATUS_ERR_TRANS_FAILURE:
	case MMS_MESSAGE_RSP_STATUS_ERR_TRANS_NETWORK_PROBLEM:
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_FAILURE:
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_SERVICE_DENIED:
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_MESSAGE_FORMAT_CORRUPT:
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_SENDING_ADDRESS_UNRESOLVED:
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_CONTENT_NOT_ACCEPTED:
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_LACK_OF_PREPAID:
		*out = p[0];
		return TRUE;
	}

	return FALSE;
}

static gboolean extract_unsigned(struct wsp_header_iter *iter, void *user)
{
	unsigned long *out = user;
	const unsigned char *p;
	unsigned int l;
	unsigned int i;

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_LONG)
		return FALSE;

	p = wsp_header_iter_get_val(iter);
	l = wsp_header_iter_get_val_len(iter);

	if (l > sizeof(unsigned long))
		return FALSE;

	for (i = 0, *out = 0; i < l; i++)
		*out = *out << 8 | p[i];

	return TRUE;
}

static header_handler handler_for_type(enum mms_header header)
{
	switch (header) {
	case MMS_HEADER_BCC:
		return extract_encoded_text;
	case MMS_HEADER_CC:
		return extract_encoded_text;
	case MMS_HEADER_CONTENT_LOCATION:
		return extract_text;
	case MMS_HEADER_CONTENT_TYPE:
		return extract_text;
	case MMS_HEADER_DATE:
		return extract_date;
	case MMS_HEADER_DELIVERY_REPORT:
		return NULL;
	case MMS_HEADER_DELIVERY_TIME:
		return extract_absolute_relative_date;
	case MMS_HEADER_EXPIRY:
		return extract_absolute_relative_date;
	case MMS_HEADER_FROM:
		return extract_from;
	case MMS_HEADER_MESSAGE_CLASS:
		return extract_message_class;
	case MMS_HEADER_MESSAGE_ID:
		return extract_text;
	case MMS_HEADER_MESSAGE_TYPE:
		return extract_short;
	case MMS_HEADER_MMS_VERSION:
		return extract_short;
	case MMS_HEADER_MESSAGE_SIZE:
		return extract_unsigned;
	case MMS_HEADER_PRIORITY:
		return extract_priority;
	case MMS_HEADER_READ_REPLY:
		return NULL;
	case MMS_HEADER_REPORT_ALLOWED:
		return NULL;
	case MMS_HEADER_RESPONSE_STATUS:
		return extract_rsp_status;
	case MMS_HEADER_RESPONSE_TEXT:
		return extract_encoded_text;
	case MMS_HEADER_SENDER_VISIBILITY:
		return NULL;
	case MMS_HEADER_STATUS:
		return NULL;
	case MMS_HEADER_SUBJECT:
		return extract_encoded_text;
	case MMS_HEADER_TO:
		return extract_text_array_element;
	case MMS_HEADER_TRANSACTION_ID:
		return extract_text;
	case MMS_HEADER_INVALID:
	case __MMS_HEADER_MAX:
		return NULL;
	}

	return NULL;
}

struct header_handler_entry {
	int flags;
	void *data;
};

static gboolean mms_parse_headers(struct wsp_header_iter *iter,
					enum mms_header header, ...)
{
	struct header_handler_entry entries[__MMS_HEADER_MAX + 1];
	va_list args;
	const unsigned char *p;
	int i;
	int expected_version_pos = 1;
	int version_pos = 0;

	memset(&entries, 0, sizeof(entries));

	va_start(args, header);

	while (header != MMS_HEADER_INVALID) {
		entries[header].flags = va_arg(args, int);
		entries[header].data = va_arg(args, void *);

		header = va_arg(args, enum mms_header);
	}

	va_end(args);

	for (i = 1; wsp_header_iter_next(iter); i++) {
		unsigned char h;
		header_handler handler;

		/* Skip application headers */
		if (wsp_header_iter_get_hdr_type(iter) !=
				WSP_HEADER_TYPE_WELL_KNOWN)
			continue;

		p = wsp_header_iter_get_hdr(iter);
		h = p[0] & 0x7f;

		/* Unsupported header, skip */
		if (entries[h].data == NULL)
			continue;

		/* Skip multiply present headers except for To */
		if ((entries[h].flags & HEADER_FLAG_MARKED)
					&& h != MMS_HEADER_TO)
			continue;

		handler = handler_for_type(h);
		if (handler == NULL)
			return FALSE;

		if (handler(iter, entries[h].data) == FALSE)
			return FALSE;

		if (h == MMS_HEADER_TRANSACTION_ID)
			expected_version_pos += 1;
		else if (h == MMS_HEADER_MMS_VERSION)
			version_pos = i;

		/* Parse the header */
		entries[h].flags |= HEADER_FLAG_MARKED;
	}

	for (i = 0; i < __MMS_HEADER_MAX + 1; i++) {
		if ((entries[i].flags & HEADER_FLAG_MANDATORY) &&
				!(entries[i].flags & HEADER_FLAG_MARKED))
			return FALSE;
	}

	if (version_pos != expected_version_pos)
		return FALSE;

	return TRUE;
}

static gboolean decode_notification_ind(struct wsp_header_iter *iter,
						struct mms_message *out)
{
	return mms_parse_headers(iter, MMS_HEADER_TRANSACTION_ID,
				HEADER_FLAG_MANDATORY, &out->transaction_id,
				MMS_HEADER_MMS_VERSION,
				HEADER_FLAG_MANDATORY, &out->version,
				MMS_HEADER_FROM,
				0, &out->ni.from,
				MMS_HEADER_SUBJECT,
				0, &out->ni.subject,
				MMS_HEADER_MESSAGE_CLASS,
				HEADER_FLAG_MANDATORY, &out->ni.cls,
				MMS_HEADER_MESSAGE_SIZE,
				HEADER_FLAG_MANDATORY, &out->ni.size,
				MMS_HEADER_EXPIRY,
				HEADER_FLAG_MANDATORY, &out->ni.expiry,
				MMS_HEADER_CONTENT_LOCATION,
				HEADER_FLAG_MANDATORY, &out->ni.location,
				MMS_HEADER_INVALID);
}

static gboolean decode_retrieve_conf(struct wsp_header_iter *iter,
						struct mms_message *out)
{
	return mms_parse_headers(iter, MMS_HEADER_TRANSACTION_ID,
				0, &out->transaction_id,
				MMS_HEADER_MMS_VERSION,
				HEADER_FLAG_MANDATORY, &out->version,
				MMS_HEADER_FROM,
				0, &out->rc.from,
				MMS_HEADER_TO,
				0, &out->rc.to,
				MMS_HEADER_SUBJECT,
				0, &out->rc.subject,
				MMS_HEADER_MESSAGE_CLASS,
				0, &out->rc.cls,
				MMS_HEADER_PRIORITY,
				0, &out->rc.priority,
				MMS_HEADER_MESSAGE_ID,
				0, &out->rc.msgid,
				MMS_HEADER_DATE,
				HEADER_FLAG_MANDATORY, &out->rc.date,
				MMS_HEADER_INVALID);
}

static gboolean decode_send_conf(struct wsp_header_iter *iter,
						struct mms_message *out)
{
	return mms_parse_headers(iter, MMS_HEADER_TRANSACTION_ID,
				HEADER_FLAG_MANDATORY, &out->transaction_id,
				MMS_HEADER_MMS_VERSION,
				HEADER_FLAG_MANDATORY, &out->version,
				MMS_HEADER_RESPONSE_STATUS,
				HEADER_FLAG_MANDATORY, &out->sc.rsp_status,
				MMS_HEADER_MESSAGE_ID,
				0, &out->sc.msgid,
				MMS_HEADER_INVALID);
}

#define CHECK_WELL_KNOWN_HDR(hdr)			\
	if (wsp_header_iter_next(&iter) == FALSE)	\
		return FALSE;				\
							\
	if (wsp_header_iter_get_hdr_type(&iter) !=	\
			WSP_HEADER_TYPE_WELL_KNOWN)	\
		return FALSE;				\
							\
	p = wsp_header_iter_get_hdr(&iter);		\
							\
	if ((p[0] & 0x7f) != hdr)			\
		return FALSE				\

gboolean mms_message_decode(const unsigned char *pdu,
				unsigned int len, struct mms_message *out)
{
	struct wsp_header_iter iter;
	const unsigned char *p;
	unsigned char octet;

	memset(out, 0, sizeof(*out));
	wsp_header_iter_init(&iter, pdu, len, WSP_HEADER_ITER_FLAG_REJECT_CP);

	CHECK_WELL_KNOWN_HDR(MMS_HEADER_MESSAGE_TYPE);

	if (extract_short(&iter, &octet) == FALSE)
		return FALSE;

	if (octet < MMS_MESSAGE_TYPE_SEND_REQ ||
			octet > MMS_MESSAGE_TYPE_DELIVERY_IND)
		return FALSE;

	out->type = octet;

	switch (out->type) {
	case MMS_MESSAGE_TYPE_SEND_REQ:
		return FALSE;
	case MMS_MESSAGE_TYPE_SEND_CONF:
		return decode_send_conf(&iter, out);
	case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
		return decode_notification_ind(&iter, out);
	case MMS_MESSAGE_TYPE_NOTIFYRESP_IND:
		return FALSE;
	case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
		return decode_retrieve_conf(&iter, out);
	case MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND:
		return FALSE;
	case MMS_MESSAGE_TYPE_DELIVERY_IND:
		return FALSE;
	}

	return FALSE;
}

static void free_attachment(gpointer data, gpointer user_data)
{
	struct mms_attachment *attach = data;

	g_free(attach->file);
	g_free(attach->content_type);
	g_free(attach->content_id);

	g_free(attach);
}

void mms_message_free(struct mms_message *msg)
{
	switch (msg->type) {
	case MMS_MESSAGE_TYPE_SEND_REQ:
		g_free(msg->sr.to);
		g_free(msg->sr.smil);
		break;
	case MMS_MESSAGE_TYPE_SEND_CONF:
		g_free(msg->sc.msgid);
		break;
	case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
		g_free(msg->ni.from);
		g_free(msg->ni.subject);
		g_free(msg->ni.cls);
		g_free(msg->ni.location);
		break;
	case MMS_MESSAGE_TYPE_NOTIFYRESP_IND:
		break;
	case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
		g_free(msg->rc.from);
		g_free(msg->rc.to);
		g_free(msg->rc.subject);
		g_free(msg->rc.cls);
		g_free(msg->rc.priority);
		g_free(msg->rc.msgid);
		break;
	case MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND:
		break;
	case MMS_MESSAGE_TYPE_DELIVERY_IND:
		break;
	}

	g_free(msg->uuid);
	g_free(msg->path);
	g_free(msg->transaction_id);

	if (msg->attachments != NULL) {
		g_slist_foreach(msg->attachments, free_attachment, NULL);
		g_slist_free(msg->attachments);
	}
}

static void fb_init(struct file_buffer *fb, int fd)
{
	fb->size = 0;
	fb->fd = fd;
}

static gboolean fb_flush(struct file_buffer *fb)
{
	unsigned int size;
	ssize_t len;

	if (fb->size == 0)
		return TRUE;

	len = write(fb->fd, fb->buf, fb->size);
	if (len < 0)
		return FALSE;

	size = len;

	if (size != fb->size)
		return FALSE;

	fb->size = 0;

	return TRUE;
}

static void *fb_request(struct file_buffer *fb, unsigned int count)
{
	if (fb->size + count < FB_SIZE) {
		void *ptr = fb->buf + fb->size;
		fb->size += count;
		return ptr;
	}

	if (fb_flush(fb) == FALSE)
		return NULL;

	if (count > FB_SIZE)
		return NULL;

	fb->size = count;

	return fb->buf;
}

static gboolean mms_encode_header(struct mms_message *msg,
						struct file_buffer *fb)
{
	char *ptr;
	unsigned int len;

	len = strlen(msg->transaction_id) + 1;

	if (len > MAX_TRANSACTION_ID_SIZE)
		return FALSE;

	ptr = fb_request(fb, 2);
	if (ptr == NULL)
		return FALSE;

	ptr[0] = MMS_HEADER_MESSAGE_TYPE | 0x80;
	ptr[1] = msg->type | 0x80;

	ptr = fb_request(fb, len + 1);
	if (ptr == NULL)
		return FALSE;

	ptr[0] = MMS_HEADER_TRANSACTION_ID | 0x80;
	strcpy(ptr + 1, msg->transaction_id);

	ptr = fb_request(fb, 2);
	if (ptr == NULL)
		return FALSE;

	ptr[0] = MMS_HEADER_MMS_VERSION | 0x80;
	ptr[1] = msg->version | 0x80;

	return TRUE;
}

static gboolean mms_encode_notify_resp_ind(struct mms_message *msg,
							struct file_buffer *fb)
{
	char *ptr;

	ptr = fb_request(fb, 2);
	if (ptr == NULL)
		return FALSE;

	ptr[0] = MMS_HEADER_STATUS | 0x80;
	ptr[1] = msg->nri.notify_status | 0x80;

	return fb_flush(fb);
}

gboolean mms_message_encode(struct mms_message *msg, int fd)
{
	struct file_buffer fb;

	fb_init(&fb, fd);

	if (mms_encode_header(msg, &fb) == FALSE)
		return FALSE;

	switch (msg->type) {
	case MMS_MESSAGE_TYPE_SEND_REQ:
	case MMS_MESSAGE_TYPE_SEND_CONF:
	case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
		return FALSE;
	case MMS_MESSAGE_TYPE_NOTIFYRESP_IND:
		return mms_encode_notify_resp_ind(msg, &fb);
	case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
	case MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND:
	case MMS_MESSAGE_TYPE_DELIVERY_IND:
		return FALSE;
	}

	return FALSE;
}

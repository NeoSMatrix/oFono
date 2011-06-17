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

#include <ctype.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <glib.h>

#include "wsputil.h"
#include "mmsutil.h"

#define uninitialized_var(x) x = x

enum header_flag {
	HEADER_FLAG_MANDATORY =			1,
	HEADER_FLAG_ALLOW_MULTI =		2,
	HEADER_FLAG_PRESET_POS =		4,
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

enum mms_part_header {
	MMS_PART_HEADER_CONTENT_LOCATION =	0x0e,
	MMS_PART_HEADER_CONTENT_ID =		0x40,
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

typedef gboolean (*header_handler)(struct wsp_header_iter *, void *);
typedef gboolean (*header_encoder)(struct file_buffer *, enum mms_header,
									void *);

char *mms_content_type_get_param_value(const char *content_type,
						const char *param_name)
{
	char *ret = NULL;
	const char *tmp;

	/* Skip content-type */
	tmp = strchr(content_type, ';');

	while (tmp != NULL) {
		const char *name;

		tmp++;

		/* Skip spaces */
		for (; *tmp != 0 && isspace(*tmp) != 0; tmp++)
			;

		if (*tmp == 0)
			break;

		name = tmp;

		/* Go to end of name */
		for (; *tmp != 0 && *tmp != '=' && isspace(*tmp) == 0; tmp++)
			;

		if (*tmp == 0)
			break;

		if (strncmp(param_name, name, tmp - name) == 0) {
			const char *value;

			/* Go to '=' */
			tmp = strchr(tmp, '=');
			if (tmp == NULL)
				break;

			tmp++;

			/* Skip spaces */
			for (; *tmp != 0 && isspace(*tmp) != 0; tmp++)
				;

			if (*tmp == 0)
				break;

			value = tmp;

			/* Go to end of value */
			for (; *tmp != 0 && *tmp != ';' && isspace(*tmp) == 0;
									tmp++)
				;

			ret = g_strndup(value, tmp - value);
			break;
		}

		/* Go to next parameter */
		tmp = strchr(tmp, ';');
	}

	return ret;
}

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

static gboolean extract_boolean(struct wsp_header_iter *iter, void *user)
{
	gboolean *out = user;
	const unsigned char *p;

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_SHORT)
		return FALSE;

	p = wsp_header_iter_get_val(iter);

	if (p[0] != 128 && p[0] != 129)
		return FALSE;

	*out = p[0] == 128;

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

static gboolean extract_sender_visibility(struct wsp_header_iter *iter,
						void *user)
{
	enum mms_message_sender_visibility *out = user;
	const unsigned char *p;

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_SHORT)
		return FALSE;

	p = wsp_header_iter_get_val(iter);

	if (p[0] != 128 && p[0] != 129)
		return FALSE;

	*out = p[0];

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

static gboolean extract_status(struct wsp_header_iter *iter, void *user)
{
	enum mms_message_delivery_status *out = user;
	const unsigned char *p;

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_SHORT)
		return FALSE;

	p = wsp_header_iter_get_val(iter);

	switch (p[0]) {
	case MMS_MESSAGE_DELIVERY_STATUS_EXPIRED:
	case MMS_MESSAGE_DELIVERY_STATUS_RETRIEVED:
	case MMS_MESSAGE_DELIVERY_STATUS_REJECTED:
	case MMS_MESSAGE_DELIVERY_STATUS_DEFERRED:
	case MMS_MESSAGE_DELIVERY_STATUS_UNRECOGNISED:
	case MMS_MESSAGE_DELIVERY_STATUS_INDETERMINATE:
	case MMS_MESSAGE_DELIVERY_STATUS_FORWARDED:
	case MMS_MESSAGE_DELIVERY_STATUS_UNREACHABLE:
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
		return extract_boolean;
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
		return extract_boolean;
	case MMS_HEADER_REPORT_ALLOWED:
		return extract_boolean;
	case MMS_HEADER_RESPONSE_STATUS:
		return extract_rsp_status;
	case MMS_HEADER_RESPONSE_TEXT:
		return extract_encoded_text;
	case MMS_HEADER_SENDER_VISIBILITY:
		return extract_sender_visibility;
	case MMS_HEADER_STATUS:
		return extract_status;
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
	int pos;
};

static gboolean mms_parse_headers(struct wsp_header_iter *iter,
					enum mms_header orig_header, ...)
{
	struct header_handler_entry entries[__MMS_HEADER_MAX + 1];
	va_list args;
	const unsigned char *p;
	unsigned int i;
	enum mms_header header;

	memset(&entries, 0, sizeof(entries));

	va_start(args, orig_header);
	header = orig_header;

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

		handler = handler_for_type(h);
		if (handler == NULL)
			return FALSE;

		/* Unsupported header, skip */
		if (entries[h].data == NULL)
			continue;

		/* Skip multiply present headers unless explicitly requested */
		if ((entries[h].flags & HEADER_FLAG_MARKED) &&
				!(entries[h].flags & HEADER_FLAG_ALLOW_MULTI))
			continue;

		/* Parse the header */
		if (handler(iter, entries[h].data) == FALSE)
			return FALSE;

		entries[h].pos = i;
		entries[h].flags |= HEADER_FLAG_MARKED;
	}

	for (i = 0; i < __MMS_HEADER_MAX + 1; i++) {
		if ((entries[i].flags & HEADER_FLAG_MANDATORY) &&
				!(entries[i].flags & HEADER_FLAG_MARKED))
			return FALSE;
	}

	/*
	 * Here we check for header positions.  This function assumes that
	 * headers marked with PRESET_POS are in the beginning of the message
	 * and follow the same order as given in the va_arg list.  The headers
	 * marked this way have to be contiguous.
	 */
	for (i = 0; i < __MMS_HEADER_MAX + 1; i++) {
		int check_flags = HEADER_FLAG_PRESET_POS | HEADER_FLAG_MARKED;
		int expected_pos = 1;

		if ((entries[i].flags & check_flags) != check_flags)
			continue;

		va_start(args, orig_header);
		header = orig_header;

		while (header != MMS_HEADER_INVALID && header != i) {
			va_arg(args, int);
			va_arg(args, void *);

			if (entries[header].flags & HEADER_FLAG_MARKED)
				expected_pos += 1;

			header = va_arg(args, enum mms_header);
		}

		va_end(args);

		if (entries[i].pos != expected_pos)
			return FALSE;
	}

	return TRUE;
}

static gboolean decode_notification_ind(struct wsp_header_iter *iter,
						struct mms_message *out)
{
	return mms_parse_headers(iter, MMS_HEADER_TRANSACTION_ID,
				HEADER_FLAG_MANDATORY | HEADER_FLAG_PRESET_POS,
				&out->transaction_id,
				MMS_HEADER_MMS_VERSION,
				HEADER_FLAG_MANDATORY | HEADER_FLAG_PRESET_POS,
				&out->version,
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

static const char *decode_attachment_charset(const unsigned char *pdu,
							unsigned int len)
{
	struct wsp_parameter_iter iter;
	struct wsp_parameter param;

	wsp_parameter_iter_init(&iter, pdu, len);

	while (wsp_parameter_iter_next(&iter, &param)) {
		if (param.type == WSP_PARAMETER_TYPE_CHARSET)
			return param.text;
	}

	return NULL;
}

static gboolean extract_content_id(struct wsp_header_iter *iter, void *user)
{
	char **out = user;
	const unsigned char *p;
	unsigned int l;
	const char *text;

	p = wsp_header_iter_get_val(iter);
	l = wsp_header_iter_get_val_len(iter);

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_TEXT)
		return FALSE;

	text = wsp_decode_quoted_string(p, l, NULL);

	if (text == NULL)
		return FALSE;

	*out = g_strdup(text);

	return TRUE;
}

static gboolean attachment_parse_headers(struct wsp_header_iter *iter,
						struct mms_attachment *part)
{
	while (wsp_header_iter_next(iter)) {
		const unsigned char *hdr = wsp_header_iter_get_hdr(iter);
		unsigned char h;

		/* Skip application headers */
		if (wsp_header_iter_get_hdr_type(iter) !=
				WSP_HEADER_TYPE_WELL_KNOWN)
			continue;

		h = hdr[0] & 0x7f;

		switch (h) {
		case MMS_PART_HEADER_CONTENT_ID:
			if (extract_content_id(iter, &part->content_id)
								== FALSE)
				return FALSE;
			break;
		case MMS_PART_HEADER_CONTENT_LOCATION:
			break;
		}
	}

	return TRUE;
}

static void free_attachment(gpointer data, gpointer user_data)
{
	struct mms_attachment *attach = data;

	g_free(attach->file);
	g_free(attach->content_type);
	g_free(attach->content_id);

	g_free(attach);
}

static gboolean mms_parse_attachments(struct wsp_header_iter *iter,
						struct mms_message *out)
{
	struct wsp_multipart_iter mi;
	const void *ct;
	unsigned int ct_len;
	unsigned int consumed;

	if (wsp_multipart_iter_init(&mi, iter, &ct, &ct_len) == FALSE)
		return FALSE;

	while (wsp_multipart_iter_next(&mi) == TRUE) {
		struct mms_attachment *part;
		struct wsp_header_iter hi;
		const void *mimetype;
		const char *charset;

		ct = wsp_multipart_iter_get_content_type(&mi);
		ct_len = wsp_multipart_iter_get_content_type_len(&mi);

		if (wsp_decode_content_type(ct, ct_len, &mimetype,
						&consumed) == FALSE)
			return FALSE;

		charset = decode_attachment_charset(ct + consumed,
							ct_len - consumed);

		wsp_header_iter_init(&hi, wsp_multipart_iter_get_hdr(&mi),
					wsp_multipart_iter_get_hdr_len(&mi),
					0);

		part = g_try_new0(struct mms_attachment, 1);
		if (part == NULL)
			return FALSE;

		if (attachment_parse_headers(&hi, part) == FALSE) {
			free_attachment(part, NULL);
			return FALSE;
		}

		if (wsp_header_iter_at_end(&hi) == FALSE) {
			free_attachment(part, NULL);
			return FALSE;
		}

		if (charset == NULL)
			part->content_type = g_strdup(mimetype);
		else
			part->content_type = g_strconcat(mimetype, ";charset=",
								charset, NULL);

		part->length = wsp_multipart_iter_get_body_len(&mi);
		part->offset = (const unsigned char *)
					wsp_multipart_iter_get_body(&mi) -
					wsp_header_iter_get_pdu(iter);

		out->attachments = g_slist_prepend(out->attachments, part);
	}

	if (wsp_multipart_iter_close(&mi, iter) == FALSE)
		return FALSE;

	out->attachments = g_slist_reverse(out->attachments);

	return TRUE;
}

static gboolean decode_retrieve_conf(struct wsp_header_iter *iter,
						struct mms_message *out)
{
	if (mms_parse_headers(iter, MMS_HEADER_TRANSACTION_ID,
				HEADER_FLAG_PRESET_POS, &out->transaction_id,
				MMS_HEADER_MMS_VERSION,
				HEADER_FLAG_MANDATORY | HEADER_FLAG_PRESET_POS,
				&out->version,
				MMS_HEADER_FROM,
				0, &out->rc.from,
				MMS_HEADER_TO,
				HEADER_FLAG_ALLOW_MULTI, &out->rc.to,
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
				MMS_HEADER_INVALID) == FALSE)
		return FALSE;

	if (wsp_header_iter_at_end(iter) == TRUE)
		return TRUE;

	if (wsp_header_iter_is_multipart(iter) == FALSE)
		return FALSE;

	if (mms_parse_attachments(iter, out) == FALSE)
		return FALSE;

	if (wsp_header_iter_at_end(iter) == FALSE)
		return FALSE;

	return TRUE;
}

static gboolean decode_send_conf(struct wsp_header_iter *iter,
						struct mms_message *out)
{
	return mms_parse_headers(iter, MMS_HEADER_TRANSACTION_ID,
				HEADER_FLAG_MANDATORY | HEADER_FLAG_PRESET_POS,
				&out->transaction_id,
				MMS_HEADER_MMS_VERSION,
				HEADER_FLAG_MANDATORY | HEADER_FLAG_PRESET_POS,
				&out->version,
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
	unsigned int flags = 0;
	struct wsp_header_iter iter;
	const unsigned char *p;
	unsigned char octet;

	memset(out, 0, sizeof(*out));

	flags |= WSP_HEADER_ITER_FLAG_REJECT_CP;
	flags |= WSP_HEADER_ITER_FLAG_DETECT_MMS_MULTIPART;
	wsp_header_iter_init(&iter, pdu, len, flags);

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

static gboolean encode_short(struct file_buffer *fb,
				enum mms_header header, void *user)
{
	char *ptr;
	unsigned int *wk = user;

	ptr = fb_request(fb, 2);
	if (ptr == NULL)
		return FALSE;

	ptr[0] = header | 0x80;
	ptr[1] = *wk | 0x80;

	return TRUE;
}

static gboolean encode_from(struct file_buffer *fb,
				enum mms_header header, void *user)
{
	char *ptr;
	char **text = user;

	if (strlen(*text) > 0)
		return FALSE;

	/* From: header token + value length + Insert-address-token */
	ptr = fb_request(fb, 3);
	if (ptr == NULL)
		return FALSE;

	ptr[0] = header | 0x80;
	ptr[1] = 1;
	ptr[2] = 129;

	return TRUE;
}

static gboolean encode_text(struct file_buffer *fb,
				enum mms_header header, void *user)
{
	char *ptr;
	char **text = user;
	unsigned int len;

	len = strlen(*text) + 1;

	ptr = fb_request(fb, len + 1);
	if (ptr == NULL)
		return FALSE;

	ptr[0] = header | 0x80;
	strcpy(ptr + 1, *text);

	return TRUE;
}

static gboolean encode_text_array_element(struct file_buffer *fb,
				enum mms_header header, void *user)
{
	char **text = user;
	char **tos;
	int i;

	tos = g_strsplit(*text, ",", 0);

	for (i = 0; tos[i] != NULL; i++) {
		if (encode_text(fb, header, &tos[i]) == FALSE) {
			g_strfreev(tos);
			return FALSE;
		}
	}

	g_strfreev(tos);

	return TRUE;
}

static header_encoder encoder_for_type(enum mms_header header)
{
	switch (header) {
	case MMS_HEADER_BCC:
		return NULL;
	case MMS_HEADER_CC:
		return NULL;
	case MMS_HEADER_CONTENT_LOCATION:
		return NULL;
	case MMS_HEADER_CONTENT_TYPE:
		return NULL;
	case MMS_HEADER_DATE:
		return NULL;
	case MMS_HEADER_DELIVERY_REPORT:
		return NULL;
	case MMS_HEADER_DELIVERY_TIME:
		return NULL;
	case MMS_HEADER_EXPIRY:
		return NULL;
	case MMS_HEADER_FROM:
		return encode_from;
	case MMS_HEADER_MESSAGE_CLASS:
		return NULL;
	case MMS_HEADER_MESSAGE_ID:
		return NULL;
	case MMS_HEADER_MESSAGE_TYPE:
		return encode_short;
	case MMS_HEADER_MMS_VERSION:
		return encode_short;
	case MMS_HEADER_MESSAGE_SIZE:
		return NULL;
	case MMS_HEADER_PRIORITY:
		return NULL;
	case MMS_HEADER_READ_REPLY:
		return NULL;
	case MMS_HEADER_REPORT_ALLOWED:
		return NULL;
	case MMS_HEADER_RESPONSE_STATUS:
		return NULL;
	case MMS_HEADER_RESPONSE_TEXT:
		return NULL;
	case MMS_HEADER_SENDER_VISIBILITY:
		return NULL;
	case MMS_HEADER_STATUS:
		return encode_short;
	case MMS_HEADER_SUBJECT:
		return NULL;
	case MMS_HEADER_TO:
		return encode_text_array_element;
	case MMS_HEADER_TRANSACTION_ID:
		return encode_text;
	case MMS_HEADER_INVALID:
	case __MMS_HEADER_MAX:
		return NULL;
	}

	return NULL;
}

static gboolean mms_encode_headers(struct file_buffer *fb,
					enum mms_header orig_header, ...)
{
	va_list args;
	void *data;
	enum mms_header header;
	header_encoder encoder;

	va_start(args, orig_header);
	header = orig_header;

	while (header != MMS_HEADER_INVALID) {
		data = va_arg(args, void *);

		encoder = encoder_for_type(header);
		if (encoder == NULL)
			return FALSE;

		if (data && encoder(fb, header, data) == FALSE)
			return FALSE;

		header = va_arg(args, enum mms_header);
	}

	va_end(args);

	return TRUE;
}

static gboolean mms_encode_notify_resp_ind(struct mms_message *msg,
							struct file_buffer *fb)
{
	if (mms_encode_headers(fb, MMS_HEADER_MESSAGE_TYPE, &msg->type,
				MMS_HEADER_TRANSACTION_ID, &msg->transaction_id,
				MMS_HEADER_MMS_VERSION, &msg->version,
				MMS_HEADER_STATUS, &msg->nri.notify_status,
				MMS_HEADER_INVALID) == FALSE)
		return FALSE;

	return fb_flush(fb);
}

gboolean mms_message_encode(struct mms_message *msg, int fd)
{
	struct file_buffer fb;

	fb_init(&fb, fd);

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

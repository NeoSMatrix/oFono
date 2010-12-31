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

#include <string.h>

#include <glib.h>

#include "wsputil.h"

/*
 * Control Characters 0-8, 10-31 and 127.  The tab character is omitted
 * since it is included in the sep chars array and the most generic TEXT
 * type of RFC 2616 explicitly allows tabs
 */
static const char *ctl_chars = "\x01\x02\x03\x04\x05\x06\x07\x08\x0A"
				"\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14"
				"\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E"
				"\x1F\x7F";

static const char *sep_chars = "()<>@,;:\\\"/[]?={} \t";

static const char *decode_text_common(const unsigned char *pdu,
					unsigned int len,
					gboolean filter_ctl,
					gboolean filter_sep,
					unsigned int *consumed)
{
	unsigned char *c;

	c = memchr(pdu, '\0', len);

	if (c == NULL)
		return NULL;

	c += 1;

	/* RFC 2616 Section 2.2 */
	if (filter_ctl && strpbrk((const char *) pdu, ctl_chars) != NULL)
		return NULL;

	if (filter_sep && strpbrk((const char *) pdu, sep_chars) != NULL)
		return NULL;

	if (consumed)
		*consumed = c - pdu;

	return (const char *) pdu;
}

const char *wsp_decode_token_text(const unsigned char *pdu, unsigned int len,
					unsigned int *consumed)
{
	return decode_text_common(pdu, len, TRUE, TRUE, consumed);
}

const char *wsp_decode_text(const unsigned char *pdu, unsigned int len,
					unsigned int *consumed)
{
	const char *r;
	unsigned int fudge = 0;

	if (*pdu == 127) {
		pdu++;

		if (*pdu < 128)
			return NULL;

		len -= 1;
		fudge += 1;
	}

	r = decode_text_common(pdu, len, TRUE, FALSE, consumed);

	if (consumed)
		*consumed += fudge;

	return r;
}

gboolean wsp_decode_uintvar(const unsigned char *pdu, unsigned int len,
				unsigned int *out_len, unsigned int *consumed)
{
	unsigned int var;
	unsigned int i;
	unsigned int cont;

	for (i = 0, var = 0, cont = TRUE; i < 5 && i < len && cont; i++) {
		cont = *pdu & 0x80;
		var = (var << 7) | *pdu;
	}

	if (cont)
		return FALSE;

	if (out_len)
		*out_len = var;

	if (consumed)
		*consumed = i;

	return TRUE;
}

gboolean wsp_decode_field(const unsigned char *pdu, unsigned int max,
					enum wsp_value_type *out_type,
					const void **out_value,
					unsigned int *out_len,
					unsigned int *out_read)
{
	const unsigned char *end = pdu + max;
	const unsigned char *begin = pdu;
	unsigned int len;
	enum wsp_value_type value;
	unsigned int consumed;

	if (*pdu <= 30) {
		len = *pdu;
		pdu++;

		if (pdu + len > end)
			return FALSE;

		value = WSP_VALUE_TYPE_LONG;
	} else if (*pdu >= 128) {
		len = 1;
		value = WSP_VALUE_TYPE_SHORT;
	} else if (*pdu == 31) {
		pdu++;

		if (pdu == end)
			return FALSE;

		if (wsp_decode_uintvar(pdu, end - pdu,
						&len, &consumed) == FALSE)
			return FALSE;

		pdu += consumed;

		if (pdu + len > end)
			return FALSE;

		value = WSP_VALUE_TYPE_LONG;
	} else {
		if (decode_text_common(pdu, end - pdu,
					TRUE, FALSE, &len) == NULL)
			return FALSE;

		value = WSP_VALUE_TYPE_TEXT;
	}

	if (out_type)
		*out_type = value;

	if (out_value)
		*out_value = pdu;

	if (out_len)
		*out_len = len;

	if (out_read)
		*out_read = pdu - begin + len;

	return TRUE;
}

void wsp_header_iter_init(struct wsp_header_iter *iter,
				const unsigned char *pdu, unsigned int len,
				unsigned int flags)
{
	iter->pdu = pdu;
	iter->pos = 0;
	iter->max = len;
	iter->code_page = 1;
	iter->flags = flags;
}

gboolean wsp_header_iter_next(struct wsp_header_iter *iter)
{
	const unsigned char *pdu = iter->pdu + iter->pos;
	const unsigned char *end = iter->pdu + iter->max;
	enum wsp_header_type header;
	const void *hdr;
	unsigned int consumed;

	if (pdu == end)
		return FALSE;

	/*
	 * 8.4.2.6 Header
	 * The following rules are used to encode headers.
	 * Header = Message-header | Shift-sequence
	 * Shift-sequence = (Shift-delimiter Page-identity) |
	 *					Short-cut-shift-delimiter
	 * Shift-delimiter = <Octet 127>
	 * Page-identity = <Any octet 1-255>
	 * Short-cut-shift-delimiter = <Any octet 1-31>
	 * Message-header = Well-known-header | Application-header
	 * Well-known-header = Well-known-field-name Wap-value
	 * Application-header = Token-text Application-specific-value
	 * Well-known-field-name = Short-integer
	 * Application-specific-value = Text-string
	 */
	while (*pdu == 127 || (*pdu >= 1 && *pdu <= 31)) {
		if (iter->flags & WSP_HEADER_ITER_FLAG_REJECT_CP)
			return FALSE;

		if (*pdu == 127) {
			pdu++;

			if (pdu == end)
				return FALSE;

			iter->code_page = *pdu;
			pdu++;
		}
	}

	if (pdu == end)
		return FALSE;

	if (*pdu >= 0x80) {
		header = WSP_HEADER_TYPE_WELL_KNOWN;
		hdr = pdu;
		pdu++;
	} else {
		if (wsp_decode_token_text(pdu, end - pdu, &consumed) == NULL)
			return FALSE;

		header = WSP_HEADER_TYPE_APPLICATION;
		hdr = pdu;
		pdu += consumed;
	}

	if (pdu == end)
		return FALSE;

	/*
	 * Section 8.4.1.2 of WAP-230:
	 * If the field name is encoded in text format, textual values MUST
	 * be used.
	 */
	if ((*pdu < 32 || *pdu > 127) && header == WSP_HEADER_TYPE_APPLICATION)
		return FALSE;

	if (wsp_decode_field(pdu, end - pdu, &iter->value_type,
				&iter->value, &iter->len, &consumed) == FALSE)
		return FALSE;

	iter->header_type = header;
	iter->header = hdr;

	iter->pos = pdu + consumed - iter->pdu;

	return TRUE;
}

unsigned char wsp_header_iter_get_code_page(struct wsp_header_iter *iter)
{
	return iter->code_page;
}

gboolean wsp_header_iter_at_end(struct wsp_header_iter *iter)
{
	if (iter->pos == iter->max)
		return TRUE;

	return FALSE;
}

enum wsp_header_type wsp_header_iter_get_hdr_type(struct wsp_header_iter *iter)
{
	return iter->header_type;
}

const void *wsp_header_iter_get_hdr(struct wsp_header_iter *iter)
{
	return iter->header;
}

enum wsp_value_type wsp_header_iter_get_val_type(struct wsp_header_iter *iter)
{
	return iter->value_type;
}

const void *wsp_header_iter_get_val(struct wsp_header_iter *iter)
{
	return iter->value;
}

unsigned int wsp_header_iter_get_val_len(struct wsp_header_iter *iter)
{
	return iter->len;
}

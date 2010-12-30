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
#include "mmsutil.h"

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
};

#define CHECK_WELL_KNOWN_HDR(hdr)			\
	if (wsp_header_iter_next(iter) == FALSE)	\
		return FALSE;				\
							\
	if (wsp_header_iter_get_hdr_type(iter) !=	\
			WSP_HEADER_TYPE_WELL_KNOWN)	\
		return FALSE;				\
							\
	p = wsp_header_iter_get_hdr(iter);		\
							\
	if ((p[0] & 0x7f) != hdr)			\
		return FALSE				\

static gboolean extract_short(struct wsp_header_iter *iter,
				enum mms_header hdr, unsigned char *out)
{
	const unsigned char *p;

	CHECK_WELL_KNOWN_HDR(hdr);

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_SHORT)
		return FALSE;

	p = wsp_header_iter_get_val(iter);
	*out = p[0];

	return TRUE;
}

static gboolean extract_text(struct wsp_header_iter *iter, enum mms_header hdr,
					const char **out)
{
	const unsigned char *p;
	unsigned int l;
	const char *text;

	CHECK_WELL_KNOWN_HDR(hdr);

	if (wsp_header_iter_get_val_type(iter) != WSP_VALUE_TYPE_TEXT)
		return FALSE;

	p = wsp_header_iter_get_val(iter);
	l = wsp_header_iter_get_val_len(iter);

	text = wsp_decode_text(p, l, NULL);
	if (text == NULL)
		return FALSE;

	*out = text;

	return TRUE;
}

gboolean mms_decode(const unsigned char *pdu,
				unsigned int len, struct mms *out)
{
	struct wsp_header_iter iter;
	unsigned char octet;
	const char *text;

	memset(out, 0, sizeof(*out));
	wsp_header_iter_init(&iter, pdu, len, WSP_HEADER_ITER_FLAG_REJECT_CP);

	if (extract_short(&iter, MMS_HEADER_MESSAGE_TYPE, &octet) == FALSE)
		return FALSE;

	if (octet < 128 || octet > 134)
		return FALSE;

	out->type = octet;

	if (extract_text(&iter, MMS_HEADER_TRANSACTION_ID, &text) == FALSE)
		return FALSE;

	out->transaction_id = g_strdup(text);

	if (extract_short(&iter, MMS_HEADER_MMS_VERSION, &octet) == FALSE)
		return FALSE;

	out->version = octet & 0x7f;

	return TRUE;
}

void mms_free(struct mms *mms)
{
	g_free(mms->transaction_id);
}

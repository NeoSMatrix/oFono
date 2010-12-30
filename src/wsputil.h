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

enum wsp_header_iter_flag {
	WSP_HEADER_ITER_FLAG_REJECT_CP =	0x1,
};

enum wsp_header_type {
	WSP_HEADER_TYPE_WELL_KNOWN,
	WSP_HEADER_TYPE_APPLICATION
};

enum wsp_value_type {
	WSP_VALUE_TYPE_LONG,
	WSP_VALUE_TYPE_SHORT,
	WSP_VALUE_TYPE_TEXT,
};

struct wsp_header_iter {
	const unsigned char *pdu;
	unsigned int max;
	unsigned int pos;
	unsigned int flags;
	unsigned char code_page;

	enum wsp_header_type header_type;
	const void *header;

	enum wsp_value_type value_type;
	const void *value;

	unsigned int len;
};

gboolean wsp_decode_uintvar(const unsigned char *pdu, unsigned int len,
				unsigned int *out_len, unsigned int *consumed);
gboolean wsp_decode_field(const unsigned char *pdu, unsigned int max,
					enum wsp_value_type *out_type,
					const void **out_value,
					unsigned int *out_len,
					unsigned int *consumed);
const char *wsp_decode_token_text(const unsigned char *pdu, unsigned int len,
					unsigned int *consumed);
const char *wsp_decode_text(const unsigned char *pdu, unsigned int len,
					unsigned int *consumed);

void wsp_header_iter_init(struct wsp_header_iter *iter,
				const unsigned char *pdu, unsigned int len,
				unsigned int flags);
gboolean wsp_header_iter_next(struct wsp_header_iter *iter);
unsigned char wsp_header_iter_get_code_page(struct wsp_header_iter *iter);

enum wsp_header_type wsp_header_iter_get_hdr_type(struct wsp_header_iter *iter);
const void *wsp_header_iter_get_hdr(struct wsp_header_iter *iter);
enum wsp_value_type wsp_header_iter_get_val_type(struct wsp_header_iter *iter);
const void *wsp_header_iter_get_val(struct wsp_header_iter *iter);
unsigned int wsp_header_iter_get_val_len(struct wsp_header_iter *iter);

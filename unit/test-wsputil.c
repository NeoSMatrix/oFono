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
#include <glib/gprintf.h>

#include "wsputil.h"

static void dump_field(enum wsp_value_type type, const void *data,
				unsigned int len)
{
	switch (type) {
	case WSP_VALUE_TYPE_LONG:
	{
		unsigned int i;
		const unsigned char *l = data;

		for (i = 0; i < len; i++) {
			g_print("%x ", l[i]);

			if ((i % 32) == 31)
				g_print("\n");
		}

		g_print("\n");
		break;
	}
	case WSP_VALUE_TYPE_SHORT:
	{
		const unsigned char *s = data;

		g_print("%x\n", s[0] & 0x7f);
		break;
	}
	case WSP_VALUE_TYPE_TEXT:
		g_print("%s\n", (const char *) data);
		break;
	}

	g_print("Field length: %d\n", len);
}

static const unsigned char push1[] = {
				0x01, 0x06, 0x24, 0x61, 0x70, 0x70, 0x6C, 0x69,
				0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x76,
				0x6E, 0x64, 0x2E, 0x77, 0x61, 0x70, 0x2E, 0x6D,
				0x6D, 0x73, 0x2D, 0x6D, 0x65, 0x73, 0x73, 0x61,
				0x67, 0x65, 0x00, 0xAF, 0x84, 0xB4, 0x86, 0x8C,
				0x82, 0x98, 0x4F, 0x67, 0x51, 0x4B, 0x4B, 0x42,
				0x00, 0x8D, 0x90, 0x89, 0x08, 0x80, 0x45, 0x72,
				0x6F, 0x74, 0x69, 0x6B, 0x00, 0x96, 0x50, 0x69,
				0x6E, 0x2D, 0x55, 0x70, 0x73, 0x00, 0x8A, 0x80,
				0x8E, 0x02, 0x40, 0x00, 0x88, 0x05, 0x81, 0x03,
				0x03, 0xF4, 0x80, 0x83, 0x68, 0x74, 0x74, 0x70,
				0x3A, 0x2F, 0x2F, 0x65, 0x70, 0x73, 0x33, 0x2E,
				0x64, 0x65, 0x2F, 0x4F, 0x2F, 0x5A, 0x39, 0x49,
				0x5A, 0x4F, 0x00
};

struct push_test {
	const unsigned char *pdu;
	unsigned int len;
};

static struct push_test push_test_1 = {
	.pdu = push1,
	.len = sizeof(push1),
};

static void test_decode_push(gconstpointer data)
{
	const struct push_test *test = data;
	const unsigned char *pdu = test->pdu;
	unsigned int len = test->len;
	unsigned int content_len;
	enum wsp_value_type content_type;
	const void *content_data;
	struct wsp_header_iter iter;
	gboolean ret;

	g_assert(pdu[1] == 0x06);

	if (g_test_verbose()) {
		g_print("Overall Push Length: %d\n", len);
		g_print("TID: %d\n", pdu[0]);
		g_print("Type: %d\n", pdu[1]);
		g_print("Push Content + Header Length: %d\n", pdu[2]);
	}

	ret = wsp_decode_field(pdu + 3, pdu[2],
				&content_type, &content_data, &content_len);
	g_assert(ret == TRUE);

	g_print("Content-Type: ");

	dump_field(content_type, content_data, content_len);

	wsp_header_iter_init(&iter, pdu + 3 + content_len,
				pdu[2] - content_len, 0);

	while (wsp_header_iter_next(&iter)) {
		const void *hdr = wsp_header_iter_get_hdr(&iter);
		const void *val = wsp_header_iter_get_val(&iter);
		const unsigned char *wk;

		g_print("Header: ");
		switch (wsp_header_iter_get_hdr_type(&iter)) {
		case WSP_HEADER_TYPE_WELL_KNOWN:
			wk = hdr;
			g_print("Well known %x\n", wk[0] & 0x7f);
			break;
		case WSP_HEADER_TYPE_APPLICATION:
			g_print("Application: %s\n", (const char *) hdr);
			break;
		}

		g_print("Value: ");
		dump_field(wsp_header_iter_get_val_type(&iter), val,
				wsp_header_iter_get_val_len(&iter));
	}
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_data_func("/wsputil/Decode Push 1", &push_test_1,
				test_decode_push);

	return g_test_run();
}

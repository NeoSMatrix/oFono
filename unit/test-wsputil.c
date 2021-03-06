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
			g_print("%02x ", l[i]);

			if ((i % 32) == 31)
				g_print("\n");
		}

		g_print("\n");
		break;
	}
	case WSP_VALUE_TYPE_SHORT:
	{
		const unsigned char *s = data;

		g_print("%02x\n", s[0] & 0x7f);
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
				0x67, 0x65, 0x00, 0xAF, 0x84, 0xB4, 0x86,
				0x8C, 0x82, 0x98, 0x4F, 0x67, 0x51, 0x4B, 0x4B,
				0x42, 0x00, 0x8D, 0x90, 0x89, 0x08, 0x80, 0x45,
				0x72, 0x6F, 0x74, 0x69, 0x6B, 0x00, 0x96, 0x50,
				0x69, 0x6E, 0x2D, 0x55, 0x70, 0x73, 0x00, 0x8A,
				0x80, 0x8E, 0x02, 0x40, 0x00, 0x88, 0x05, 0x81,
				0x03, 0x03, 0xF4, 0x80, 0x83, 0x68, 0x74, 0x74,
				0x70, 0x3A, 0x2F, 0x2F, 0x65, 0x70, 0x73, 0x33,
				0x2E, 0x64, 0x65, 0x2F, 0x4F, 0x2F, 0x5A, 0x39,
				0x49, 0x5A, 0x4F, 0x00
};

static const unsigned char push2[] = {
				0x00, 0x06, 0x24, 0x61, 0x70, 0x70, 0x6C, 0x69,
				0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x76,
				0x6E, 0x64, 0x2E, 0x77, 0x61, 0x70, 0x2E, 0x6D,
				0x6D, 0x73, 0x2D, 0x6D, 0x65, 0x73, 0x73, 0x61,
				0x67, 0x65, 0x00, 0xAF, 0x84, 0x8D, 0xDC,
				0x8C, 0x82, 0x98, 0x77, 0x4C, 0x4A, 0x65, 0x54,
				0x37, 0x54, 0x48, 0x75, 0x00, 0x8D, 0x90, 0x89,
				0x17, 0x80, 0x31, 0x35, 0x35, 0x35, 0x31, 0x32,
				0x33, 0x30, 0x30, 0x30, 0x30, 0x2F, 0x54, 0x59,
				0x50, 0x45, 0x3D, 0x50, 0x4C, 0x4D, 0x4E, 0x00,
				0x8A, 0x80, 0x8E, 0x02, 0x5A, 0x1D, 0x88, 0x05,
				0x81, 0x03, 0x03, 0xF4, 0x80, 0x83, 0x68, 0x74,
				0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6D, 0x6D, 0x73,
				0x63, 0x31, 0x31, 0x3A, 0x31, 0x30, 0x30, 0x32,
				0x31, 0x2F, 0x6D, 0x6D, 0x73, 0x63, 0x2F, 0x31,
				0x5F, 0x31, 0x3F, 0x77, 0x4C, 0x4A, 0x65, 0x54,
				0x37, 0x54, 0x48, 0x75, 0x00
};

static const unsigned char push3[] = {
				0x4C, 0x06, 0x03, 0xCB, 0xAF, 0x88,
				0x03, 0x0E, 0x6A, 0x00, 0xC5, 0x05, 0x85, 0x06,
				0x86, 0x07, 0x87, 0x01, 0x46, 0x47, 0x03, 0x31,
				0x2E, 0x30, 0x00, 0x01, 0x01, 0x49, 0x4A, 0x46,
				0x48, 0x03, 0x63, 0x69, 0x64, 0x3A, 0x32, 0x30,
				0x30, 0x35, 0x40, 0x67, 0x72, 0x61, 0x6E, 0x6A,
				0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x01, 0x01,
				0x4B, 0x4C, 0xC3, 0x10, 0xF1, 0xF7, 0x7C, 0x37,
				0x95, 0xD3, 0x39, 0x65, 0x84, 0x1E, 0x4A, 0x27,
				0xA6, 0xC2, 0x71, 0xDB, 0x01, 0x01, 0x01, 0x4D,
				0x4F, 0x52, 0x53, 0x03, 0x32, 0x00, 0x01, 0x01,
				0x01, 0x01, 0x01, 0x01
};

static const unsigned char push4[] = {
				0xB7, 0x06, 0x03, 0xC4, 0xAF, 0x87,
				0x00, 0xEF, 0xC4, 0x29, 0x75, 0x46, 0xCA, 0xD6,
				0xC5, 0x51, 0x08, 0xF1, 0x60, 0xBD, 0xB8, 0x00,
				0x03, 0x38, 0x00, 0x00, 0x00, 0x00, 0x48, 0x08,
				0x66, 0x75, 0x6E, 0x61, 0x6D, 0x62, 0x6F, 0x6C
};

static const unsigned char push5[] = {
				0xC4, 0x06, 0x2F, 0x1F, 0x2D, 0xB6, 0x91, 0x81,
				0x92, 0x35, 0x39, 0x44, 0x33, 0x36, 0x44, 0x31,
				0x34, 0x45, 0x38, 0x38, 0x34, 0x39, 0x39, 0x41,
				0x33, 0x44, 0x35, 0x36, 0x45, 0x42, 0x41, 0x36,
				0x44, 0x34, 0x46, 0x39, 0x34, 0x41, 0x36, 0x37,
				0x30, 0x34, 0x31, 0x42, 0x44, 0x32, 0x41, 0x39,
				0x43, 0x00, 0x03, 0x0B, 0x6A, 0x00, 0x45, 0xC6,
				0x00, 0x01, 0x55, 0x01, 0x87, 0x36, 0x06, 0x03,
				0x77, 0x32, 0x00, 0x01, 0x87, 0x22, 0x06, 0x03,
				0x49, 0x4E, 0x54, 0x45, 0x52, 0x4E, 0x45, 0x54,
				0x00, 0x01, 0xC6, 0x59, 0x01, 0x87, 0x3A, 0x06,
				0x03, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F,
				0x75, 0x73, 0x65, 0x72, 0x70, 0x69, 0x6E, 0x31,
				0x32, 0x33, 0x34, 0x00, 0x01, 0x87, 0x1C, 0x01,
				0x01, 0x01, 0x01,
};

struct push_test {
	const unsigned char *pdu;
	unsigned int len;
};

/*
 * MMS Push 1
 * This PDU shows a MMS push message with below content:
 * Overall Push Length: 107
 * TID: 1
 * Type: 6
 * Push Content + Header Length: 36
 * Content-Type: application/vnd.wap.mms-message
 * Header: Well known: 0x2F -> X-Wap-Application-Id
 * Value: 0x04 -> x-wap-application:mms.ua
 * Field length: 1
 * Header: Well known: 0x34 -> Push-Flag
 * Value: 0x06
 * Field length: 1
 * Body Length: 68
 */
static const struct push_test push_test_1 = {
	.pdu = push1,
	.len = sizeof(push1),
};

/*
 * MMS Push 2
 * This PDU shows a MMS push message with below content:
 * Overall Push Length: 132
 * TID: 0
 * Type: 6
 * Push Content + Header Length: 36
 * Content-Type: application/vnd.wap.mms-message
 * Header: Well known: 0x2F -> X-Wap-Application-Id
 * Value: 0x04 -> x-wap-application:mms.ua
 * Field length: 1
 * Header: Well known: 0x0D -> Content-Length
 * Value: 0x5C
 * Field length: 1
 * Body Length: 93
 */
static const struct push_test push_test_2 = {
	.pdu = push2,
	.len = sizeof(push2),
};

/*
 * DRM Push
 * This PDU shows a DRM push message with below content:
 * DRM Push
 * Overall Push Length: 90
 * TID: 76
 * Type: 6
 * Push Content + Header Length: 3
 * Content-Type: application/vnd.oma.drm.rights+wbxml
 * Header: Well known: 0x2F -> X-Wap-Application-Id
 * Value: 0x08 -> x-wap-application:drm.ua
 * Field length: 1
 * Body Length: 84
 */
static const struct push_test push_test_3 = {
	.pdu = push3,
	.len = sizeof(push3),
};

/*
 * DM Push
 * This PDU shows a DM push message with below content:
 * Overall Push Length: 38
 * TID: 183
 * Type: 6
 * Push Content + Header Length: 3
 * Content-Type: application/vnd.syncml.notification
 * Header: Well known: 0x2F -> X-Wap-Application-Id
 * Value: 0x07 -> x-wap-application:syncml.dm
 * Field length: 1
 * Body Length: 32
 */
static const struct push_test push_test_4 = {
	.pdu = push4,
	.len = sizeof(push4),
};

/*
 * CP Push
 * This PDU shows a CP push message with below content:
 * Overall Push Length: 115
 * TID: 196
 * Type: 6
 * Push Content + Header Length: 47
 * Content-Type: application/vnd.wap.connectivity-wbxml
 * Body Length: 65
 */
static const struct push_test push_test_5 = {
	.pdu = push5,
	.len = sizeof(push5),
};

static void test_decode_push(gconstpointer data)
{
	const struct push_test *test = data;
	const unsigned char *pdu = test->pdu;
	unsigned int len = test->len;
	unsigned int headerslen;
	const void *content_data;
	struct wsp_header_iter iter;
	gboolean ret;
	unsigned int nread;
	unsigned int consumed;
	unsigned int param_len;

	g_assert(pdu[1] == 0x06);

	/* Consume TID and Type */
	nread = 2;

	ret = wsp_decode_uintvar(pdu + nread, len, &headerslen, &consumed);
	g_assert(ret == TRUE);

	/* Consume uintvar bytes */
	nread += consumed;

	if (g_test_verbose()) {
		g_print("Overall Push Length: %d\n", len);
		g_print("TID: %d\n", pdu[0]);
		g_print("Type: %d\n", pdu[1]);
		g_print("Push Content + Header Length: %d\n", headerslen);
	}

	ret = wsp_decode_content_type(pdu + nread, headerslen, &content_data,
					&consumed, &param_len);
	g_assert(ret == TRUE);

	/* Consume Content Type bytes, including parameters */
	consumed += param_len;
	nread += consumed;

	if (g_test_verbose())
		g_print("Content-Type: %s\n", (const char *) content_data);

	wsp_header_iter_init(&iter, pdu + nread, headerslen - consumed, 0);

	while (wsp_header_iter_next(&iter)) {
		const void *hdr = wsp_header_iter_get_hdr(&iter);
		const void *val = wsp_header_iter_get_val(&iter);
		const unsigned char *wk;
		const void *urn;

		if (g_test_verbose())
			g_print("Header: ");

		switch (wsp_header_iter_get_hdr_type(&iter)) {
		case WSP_HEADER_TYPE_WELL_KNOWN:
			wk = hdr;

			if (g_test_verbose())
				g_print("Well known %02x\n", wk[0] & 0x7f);

			if ((wk[0] & 0x7f) == WSP_HEADER_TOKEN_APP_ID) {
				ret = wsp_decode_application_id(&iter, &urn);

				g_assert(ret == TRUE);

				if (g_test_verbose())
					g_print("app_id=%s\n",
							(const char *)urn);
			}
			break;
		case WSP_HEADER_TYPE_APPLICATION:
			if (g_test_verbose())
				g_print("Application: %s\n",
						(const char *) hdr);
			break;
		}

		if (g_test_verbose()) {
			g_print("Value: ");

			dump_field(wsp_header_iter_get_val_type(&iter), val,
					wsp_header_iter_get_val_len(&iter));
		}
	}

	if (g_test_verbose())
		g_print("Body Length: %d\n",
				len - nread - headerslen + consumed);
}

struct text_header_iter_test {
	const char *header;
	gboolean success;
	const char *key;
	const char *value;
	const char *dict[];
};

static const struct text_header_iter_test text_header_iter_1 = {
	.header = "Content-Type: \"text/html\"; charset=ISO-8859-4; q; bar",
	.success = TRUE,
	.key = "Content-Type",
	.value = "text/html",
	.dict = { "charset", "ISO-8859-4", "q", NULL, "bar", NULL, NULL, NULL },};

static void test_wsp_text_header_iter(gconstpointer data)
{
	const struct text_header_iter_test *test = data;
	struct wsp_text_header_iter iter;
	gboolean r;
	int i;

	r = wsp_text_header_iter_init(&iter, test->header);
	g_assert(r == test->success);

	if (r == FALSE)
		return;

	g_assert_cmpstr(test->key, ==, wsp_text_header_iter_get_key(&iter));
	g_assert_cmpstr(test->value, ==, wsp_text_header_iter_get_value(&iter));

	for (i = 0; test->dict[i] != NULL; i++) {
		r = wsp_text_header_iter_param_next(&iter);

		g_assert(r == TRUE);

		g_assert_cmpstr(test->dict[i++], ==,
					wsp_text_header_iter_get_key(&iter));

		g_assert_cmpstr(test->dict[i], ==,
				wsp_text_header_iter_get_value(&iter));
	}
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_data_func("/wsputil/Decode MMS Push 1", &push_test_1,
				test_decode_push);
	g_test_add_data_func("/wsputil/Decode MMS Push 2", &push_test_2,
				test_decode_push);
	g_test_add_data_func("/wsputil/Decode DRM Push", &push_test_3,
				test_decode_push);
	g_test_add_data_func("/wsputil/Decode DM Push", &push_test_4,
				test_decode_push);
	g_test_add_data_func("/wsputil/Decode CP Push", &push_test_5,
				test_decode_push);

	g_test_add_data_func("/wsputil/WSP Text Header Iter Test 1",
				&text_header_iter_1,
				test_wsp_text_header_iter);

	return g_test_run();
}

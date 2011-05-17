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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <glib.h>

#include "wsputil.h"

static const unsigned char mms_msg1[] = {
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

#define MMS_HDR_BCC			0x01
#define MMS_HDR_CC			0x02
#define MMS_HDR_CONTENT_LOCATION	0x03
#define MMS_HDR_CONTENT_TYPE		0x04
#define MMS_HDR_DATE			0x05
#define MMS_HDR_DELIVERY_REPORT		0x06
#define MMS_HDR_DELIVERY_TIME		0x07
#define MMS_HDR_EXPIRY			0x08
#define MMS_HDR_FROM			0x09
#define MMS_HDR_MESSAGE_CLASS		0x0a
#define MMS_HDR_MESSAGE_ID		0x0b
#define MMS_HDR_MESSAGE_TYPE		0x0c
#define MMS_HDR_MMS_VERSION		0x0d
#define MMS_HDR_MESSAGE_SIZE		0x0e
#define MMS_HDR_PRIORITY		0x0f
#define MMS_HDR_READ_REPLY		0x10
#define MMS_HDR_REPORT_ALLOWED		0x11
#define MMS_HDR_RESPONSE_STATUS		0x12
#define MMS_HDR_RESPONSE_TEXT		0x13
#define MMS_HDR_SENDER_VISIBILITY	0x14
#define MMS_HDR_STATUS			0x15
#define MMS_HDR_SUBJECT			0x16
#define MMS_HDR_TO			0x17
#define MMS_HDR_TRANSACTION_ID		0x18


static const char *mms_header[] = {
	NULL,
	"Bcc",
	"Cc",
	"X-Mms-Content-Location",
	"Content-Type",
	"Date",
	"X-Mms-Delivery-Report",
	"X-Mms-Delivery-Time",
	"X-Mms-Expiry",
	"From",
	"X-Mms-Message-Class",
	"Message-ID",
	"X-Mms-Message-Type",
	"X-Mms-MMS-Version",
	"X-Mms-Message-Size",
	"X-Mms-Priority",
	"X-Mms-Read-Reply",
	"X-Mms-Report-Allowed",
	"X-Mms-Response-Status",
	"X-Mms-Response-Text",
	"X-Mms-Sender-Visibility",
	"X-Mms-Status",
	"Subject",
	"To",
	"X-Mms-Transaction-Id",
};


static void decode_headers(struct wsp_header_iter *iter,
				const char *header_lut[], const char *prefix)
{
	while (wsp_header_iter_next(iter)) {
		const unsigned char *hdr = wsp_header_iter_get_hdr(iter);
		const unsigned char *val = wsp_header_iter_get_val(iter);
		enum wsp_value_type type = wsp_header_iter_get_val_type(iter);
		unsigned int len, i;

		switch (wsp_header_iter_get_hdr_type(iter)) {
		case WSP_HEADER_TYPE_WELL_KNOWN:
			printf("%s%s: ", prefix, header_lut[hdr[0] & 0x7f]);
			break;
		case WSP_HEADER_TYPE_APPLICATION:
			printf("%s%s: ", prefix, (const char *) hdr);
			break;
		}

		len = wsp_header_iter_get_val_len(iter);

		switch (type) {
		case WSP_VALUE_TYPE_TEXT:
			printf("%s", (const char *) val);
			break;
		default:
			for (i = 0; i < len; i++)
				printf("%02x ", val[i]);
			printf("(len %d, ", len);

			if (type == WSP_VALUE_TYPE_SHORT)
				printf("Short)");
			else
				printf("Long)");

			break;
		}

		printf("\n");
	}
}

static void decode_message(const unsigned char *data, unsigned int size)
{
	struct wsp_header_iter iter;
	struct wsp_multipart_iter mi;
	unsigned int flags = 0;
	const void *ct;
	unsigned int ct_len;
	const void *multipart_mimetype;
	unsigned int consumed;

	flags |= WSP_HEADER_ITER_FLAG_REJECT_CP;
	flags |= WSP_HEADER_ITER_FLAG_DETECT_MMS_MULTIPART;

	wsp_header_iter_init(&iter, data, size, flags);

	decode_headers(&iter, mms_header, "");

	if (wsp_header_iter_at_end(&iter) == TRUE)
		return;
}

static int open_file(const char *pathname)
{
	struct stat st;
	unsigned char *map;
	size_t size;
	int fd;

	fd = open(pathname, O_RDONLY);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}

	size = st.st_size;

	map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (!map || map == MAP_FAILED) {
		close(fd);
		return -1;
	}

	decode_message(map, size);

	munmap(map, size);

	close(fd);

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		decode_message(mms_msg1, sizeof(mms_msg1));
		return 0;
	}

	if (open_file(argv[1]) < 0) {
		fprintf(stderr, "Failed to open file\n");
		return 1;
	}

	return 0;
}

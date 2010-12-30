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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <glib.h>
#include <glib/gprintf.h>

#include "mmsutil.h"

static const char *message_type_to_string(enum mms_message_type type)
{
	switch (type) {
	case MMS_MESSAGE_TYPE_SEND_REQ:
		return "send-req";
	case MMS_MESSAGE_TYPE_SEND_CONF:
		return "send-conf";
	case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
		return "notification-ind";
	case MMS_MESSAGE_TYPE_NOTIFYRESP_IND:
		return "notifyresp-ind";
	case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
		return "retrieve-conf";
	case MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND:
		return "acknowledge-ind";
	case MMS_MESSAGE_TYPE_DELIVERY_IND:
		return "delivery-ind";
	}

	return NULL;
}

static void dump_notification_ind(struct mms_message *msg)
{
	char buf[128];

	strftime(buf, 127, "%Y-%m-%dT%H:%M:%S%z", localtime(&msg->ni.expiry));
	buf[127] = '\0';

	g_print("From: %s\n", msg->ni.from);
	g_print("Subject: %s\n", msg->ni.subject);
	g_print("Class: %s\n", msg->ni.cls);
	g_print("Size: %d\n", msg->ni.size);
	g_print("Expiry: %s\n", buf);
	g_print("Location: %s\n", msg->ni.location);
}

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

static const unsigned char mms_msg2[] = {
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

struct mms_test {
	const char *pathname;
	const unsigned char *pdu;
	unsigned int len;
};

static struct mms_test mms_notification_test_1 = {
	.pdu = mms_msg1,
	.len = sizeof(mms_msg1),
};

static struct mms_test mms_notification_test_2 = {
	.pdu = mms_msg2,
	.len = sizeof(mms_msg2),
};

static void test_decode_mms(gconstpointer data)
{
	const struct mms_test *test = data;
	struct mms_message msg;
	unsigned int len;
	gboolean ret;

	if (test->pathname != NULL) {
		struct stat st;
		unsigned char *pdu;
		int fd;

		fd = open(test->pathname, O_RDONLY);
		if (fd < 0) {
			g_printerr("Failed to open %s\n", test->pathname);
			return;
		}

		if (fstat(fd, &st) < 0) {
			g_printerr("Failed to stat %s\n", test->pathname);
			close(fd);
			return;
		}

		len = st.st_size;

		pdu = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
		if (!pdu || pdu == MAP_FAILED) {
			g_printerr("Failed to mmap %s\n", test->pathname);
			close(fd);
			return;
		}

		ret = mms_message_decode(pdu, len, &msg);

		munmap(pdu, len);

		close(fd);
	} else {
		const unsigned char *pdu = test->pdu;

		len = test->len;

		ret = mms_message_decode(pdu, len, &msg);
	}

	g_assert(ret == TRUE);

	if (g_test_verbose()) {
		g_print("Overall message size: %d\n", len);

		g_print("MMS message type: %s\n",
				message_type_to_string(msg.type));
		g_print("MMS transaction id: %s\n", msg.transaction_id);
		g_print("MMS version: %u.%u\n", (msg.version & 0x70) >> 4,
							msg.version & 0x0f);

		switch (msg.type) {
		case MMS_MESSAGE_TYPE_NOTIFICATION_IND:
			dump_notification_ind(&msg);
			break;
		default:
			break;
		}
	}

	mms_message_free(&msg);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_data_func("/mmsutil/Decode MMS Notification 1",
				&mms_notification_test_1, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS Notification 2",
				&mms_notification_test_2, test_decode_mms);

	return g_test_run();
}

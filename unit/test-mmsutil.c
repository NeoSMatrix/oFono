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

static const char *message_rsp_status_to_string(
					enum mms_message_rsp_status status)
{
	switch (status) {
	case MMS_MESSAGE_RSP_STATUS_OK:
		return "ok";
	case MMS_MESSAGE_RSP_STATUS_ERR_UNSUPPORTED_MESSAGE:
		return "error-unsupported-message";
	case MMS_MESSAGE_RSP_STATUS_ERR_TRANS_FAILURE:
		return "error-transient-failure";
	case MMS_MESSAGE_RSP_STATUS_ERR_TRANS_NETWORK_PROBLEM:
		return "error-transient-network-problem";
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_FAILURE:
		return "error-permanent-failure";
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_SERVICE_DENIED:
		return "error-permanent-service-denied";
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_MESSAGE_FORMAT_CORRUPT:
		return "error-permanent-message-format-corrupt";
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_SENDING_ADDRESS_UNRESOLVED:
		return "error-permanent-sending-address-unresolved";
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_CONTENT_NOT_ACCEPTED:
		return "error-permanent-content-not-accepted";
	case MMS_MESSAGE_RSP_STATUS_ERR_PERM_LACK_OF_PREPAID:
		return "error-permanent-lack-of-prepaid";
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

static void dump_attachment(gpointer data, gpointer user_data)
{
	struct mms_attachment *attach = data;

	g_print("Attachment:\n");
	g_print("\tFile: %s\n", attach->file);
	g_print("\tOffset: %zd\n", attach->offset);
	g_print("\tLength: %zd\n", attach->length);
	g_print("\tContent-type: %s\n", attach->content_type);
	g_print("\tContent-id: %s\n", attach->content_id);
}

static void dump_retrieve_conf(struct mms_message *msg)
{
	char buf[128];

	strftime(buf, 127, "%Y-%m-%dT%H:%M:%S%z", localtime(&msg->rc.date));
	buf[127] = '\0';

	g_print("From: %s\n", msg->rc.from);
	g_print("To: %s\n", msg->rc.to);
	g_print("Subject: %s\n", msg->rc.subject);
	g_print("Class: %s\n", msg->rc.cls);
	g_print("Priority: %s\n", msg->rc.priority);
	g_print("Msg-Id: %s\n", msg->rc.msgid);
	g_print("Date: %s\n", buf);

	g_slist_foreach(msg->attachments, dump_attachment, NULL);
}

static void dump_send_conf(struct mms_message *msg)
{
	g_print("Response-Status: %s\n",
			message_rsp_status_to_string(msg->sc.rsp_status));
	g_print("Msg-Id: %s\n", msg->sc.msgid);
}

static gboolean check_encoded_msg(const char *filename,
						const unsigned char *msg_pdu)
{
	struct stat st;
	unsigned char *pdu;
	int fd;
	int i;
	int ret;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		g_printerr("Failed to open %s\n", filename);
		return FALSE;
	}

	if (fstat(fd, &st) < 0) {
		g_printerr("Failed to stat %s\n", filename);
		close(fd);
		return FALSE;
	}

	pdu = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (!pdu || pdu == MAP_FAILED) {
		g_printerr("Failed to mmap %s\n", filename);
		close(fd);
		return FALSE;
	}

	if (g_test_verbose()) {
		for (i = 0; i < st.st_size; i++)
			g_print("%02x ", pdu[i]);
		g_print("\n");
	}

	ret = memcmp(msg_pdu, pdu, st.st_size);

	munmap(pdu, st.st_size);

	close(fd);

	return ret == 0;
}

/*
 * MMS M-Notify.Ind PDU 1
 * This PDU shows the decoding of a M-Notify.Ind PDU with below content:
 * Overall message size: 68
 * MMS message type: notification-ind
 * MMS transaction id: OgQKKB
 * MMS version: 1.0
 * From: Erotik
 * Subject: Pin-Ups
 * Class: Personal
 * Size: 16384
 * Expiry: 2011-05-19T10:56:340200
 * Location: http://eps3.de/O/Z9IZO
 */
static const unsigned char mms_m_notify_ind_1[] = {
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

/*
 * MMS M-Notify.Ind PDU 2
 * This PDU shows the decoding of a M-Notify.Ind PDU without "subject" field
 * and below content:
 * Overall message size: 93
 * MMS message type: notification-ind
 * MMS transaction id: wLJeT7THu
 * MMS version: 1.0
 * From: 15551230000/TYPE=PLMN
 * Subject: (null)
 * Class: Personal
 * Size: 23069
 * Expiry: 2011-05-19T14:32:320200
 * Location: http://mmsc11:10021/mmsc/1_1?wLJeT7THu
 */
static const unsigned char mms_m_notify_ind_2[] = {
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

/*
 * MMS M-Notify.Ind PDU 3
 * MMS-1.3-con-271: Long Subject field.
 * This PDU shows the decoding of a M-Notify.Ind PDU with a maximum length
 * "us-ascii" encoded "subject" field value (40 characters) and below content:
 * Overall message size: 121
 * MMS message type: notification-ind
 * MMS transaction id: OgQKKB
 * MMS version: 1.0
 * From: +44123989100/TYPE=PLMN
 * Subject: abcdefghijklmnopqrstuvwxyz0123456789/-+@
 * Class: Personal
 * Size: 23069
 * Expiry: 2011-05-27T10:39:58+0200
 * Location: http://eps3.de/O/Z9IZO
 */
static const char mms_m_notify_ind_3[] = "./unit/ni-mms-1-3-con-271.mms";

/*
 * MMS M-Notify.Ind PDU 4
 * MMS-1.3-con-272: Long X-Mms-Content-Location field in Notification.
 * This PDU shows the decoding of a M-Notify.Ind PDU with a maximum length
 * "X-Mms-Content-Location field value (100 characters) and below content:
 * Overall message size: 170
 * MMS message type: notification-ind
 * MMS transaction id: OgQKKB
 * MMS version: 1.0
 * From: +44123989100/TYPE=PLMN
 * Subject: MMS-1.3-con-272
 * Class: Personal
 * Size: 23069
 * Expiry: 2011-05-27T10:39:58+0200
 * Location: http://abcdefghi/abcdefghi/abcdefghi/abcdefghi/abcdefghi/abcdefghi
 * /abcdefghi/abcdefghi/abcdefghi.mms
 */
static const char mms_m_notify_ind_4[] = "./unit/ni-mms-1-3-con-272.mms";

/*
 * MMS M-Retrieve.Conf PDU 1
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with an "us-ascii"
 * encoded text "subject" field and below content:
 * Overall message size: 200
 * MMS message type: retrieve-conf
 * MMS transaction id: 1201657238
 * MMS version: 1.3
 * From: 49891000/TYPE=PLMN
 * To: (null)
 * Subject: MMS-1.3-con-212
 * Class: (null)
 * Priority: (null)
 * Msg-Id: mt-212
 * Date: 2008-01-30T02:40:380100
 */
static const unsigned char mms_m_retrieve_conf_1[] = {
				0x8C, 0x84, 0x98, 0x31, 0x32, 0x30, 0x31, 0x36,
				0x35, 0x37, 0x32, 0x33, 0x38, 0x00, 0x8D, 0x93,
				0x8B, 0x6D, 0x74, 0x2D, 0x32, 0x31, 0x32, 0x00,
				0x85, 0x04, 0x47, 0x9F, 0xD5, 0x96, 0x89, 0x15,
				0x80, 0x2B, 0x34, 0x39, 0x38, 0x39, 0x31, 0x30,
				0x30, 0x30, 0x2F, 0x54, 0x59, 0x50, 0x45, 0x3D,
				0x50, 0x4C, 0x4D, 0x4E, 0x00, 0x96, 0x11, 0x83,
				0x4D, 0x4D, 0x53, 0x2D, 0x31, 0x2E, 0x33, 0x2D,
				0x63, 0x6F, 0x6E, 0x2D, 0x32, 0x31, 0x32, 0x00,
				0x84, 0xA3, 0x01, 0x40, 0x3B, 0x14, 0x83, 0x85,
				0x54, 0x65, 0x78, 0x74, 0x5F, 0x75, 0x73, 0x2D,
				0x61, 0x73, 0x63, 0x69, 0x69, 0x2E, 0x74, 0x78,
				0x74, 0x00, 0x81, 0x83, 0xC0, 0x22, 0x3C, 0x54,
				0x65, 0x78, 0x74, 0x5F, 0x75, 0x73, 0x2D, 0x61,
				0x73, 0x63, 0x69, 0x69, 0x2E, 0x74, 0x78, 0x74,
				0x3E, 0x00, 0x8E, 0x54, 0x65, 0x78, 0x74, 0x5F,
				0x75, 0x73, 0x2D, 0x61, 0x73, 0x63, 0x69, 0x69,
				0x2E, 0x74, 0x78, 0x74, 0x00, 0x54, 0x68, 0x65,
				0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62,
				0x72, 0x6F, 0x77, 0x6E, 0x20, 0x66, 0x6F, 0x78,
				0x20, 0x6A, 0x75, 0x6D, 0x70, 0x65, 0x64, 0x20,
				0x6F, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65,
				0x20, 0x6C, 0x61, 0x7A, 0x79, 0x20, 0x64, 0x6F,
				0x67, 0x20, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
				0x37, 0x38, 0x39, 0x30, 0x2F, 0x21, 0x28, 0x29,
};

/*
 * MMS M-Retrieve.Conf PDU 2
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with multiple "To"
 * fields and below content:
 * Overall message size: 192
 * MMS message type: retrieve-conf
 * MMS transaction id: 1201657238
 * MMS version: 1.0
 * From: 1234567890/TYPE=PLMN
 * To: 1111111111/TYPE=PLMN,2222222222/TYPE=PLMN,3333333333/TYPE=PLMN
 * Subject: multito
 * Class: Personal
 * Priority: Normal
 * Msg-Id: (null)
 * Date: 2011-04-04T11:41:500200
 */
static const unsigned char mms_m_retrieve_conf_2[] = {
				0x8C, 0x84, 0x98, 0x31, 0x32, 0x30, 0x31, 0x36,
				0x35, 0x37, 0x32, 0x33, 0x38, 0x00, 0x8D, 0x90,
				0x85, 0x04, 0x4D, 0x99, 0x92, 0x5E, 0x96, 0x6D,
				0x75, 0x6C, 0x74, 0x69, 0x74, 0x6F, 0x00, 0x89,
				0x17, 0x80, 0x2B, 0x31, 0x32, 0x33, 0x34, 0x35,
				0x36, 0x37, 0x38, 0x39, 0x30, 0x2F, 0x54, 0x59,
				0x50, 0x45, 0x3D, 0x50, 0x4C, 0x4D, 0x4E, 0x00,
				0x97, 0x2B, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
				0x31, 0x31, 0x31, 0x31, 0x2F, 0x54, 0x59, 0x50,
				0x45, 0x3D, 0x50, 0x4C, 0x4D, 0x4E, 0x00, 0x97,
				0x2B, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
				0x32, 0x32, 0x32, 0x2F, 0x54, 0x59, 0x50, 0x45,
				0x3D, 0x50, 0x4C, 0x4D, 0x4E, 0x00, 0x97, 0x2B,
				0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
				0x33, 0x33, 0x2F, 0x54, 0x59, 0x50, 0x45, 0x3D,
				0x50, 0x4C, 0x4D, 0x4E, 0x00, 0x8A, 0x80, 0x8F,
				0x81, 0x94, 0x80, 0x86, 0x81, 0x90, 0x81, 0x84,
				0xA3, 0x01, 0x26, 0x0E, 0x83, 0xC0, 0x22, 0x3C,
				0x47, 0x65, 0x6E, 0x65, 0x72, 0x69, 0x63, 0x5F,
				0x54, 0x65, 0x78, 0x74, 0x2E, 0x74, 0x78, 0x74,
				0x3E, 0x00, 0x8E, 0x2F, 0x74, 0x6D, 0x70, 0x2F,
				0x70, 0x68, 0x70, 0x38, 0x76, 0x6C, 0x66, 0x79,
				0x42, 0x00, 0xEF, 0xBB, 0xBF, 0x48, 0x65, 0x6C,
				0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64
};

/*
 * MMS M-Retrieve.Conf PDU 3
 * Overall message size: 147
 * MMS message type: retrieve-conf
 * MMS transaction id: (null)
 * MMS version: 1.0
 * From: 1234567890/TYPE=PLMN
 * To: 6666666666/TYPE=PLMN
 * Subject: test without transaction ID
 * Class: Personal
 * Priority: Normal
 * Msg-Id: (null)
 * Date: 2011-04-08T12:27:050200
 */
static const unsigned char mms_m_retrieve_conf_3[] = {
				0x8C, 0x84, 0x8D, 0x90, 0x85, 0x04, 0x4D, 0x9E,
				0xE2, 0xF9, 0x96, 0x74, 0x65, 0x73, 0x74, 0x20,
				0x77, 0x69, 0x74, 0x68, 0x6F, 0x75, 0x74, 0x20,
				0x74, 0x72, 0x61, 0x6E, 0x73, 0x61, 0x63, 0x74,
				0x69, 0x6F, 0x6E, 0x20, 0x49, 0x44, 0x00, 0x89,
				0x17, 0x80, 0x2B, 0x31, 0x32, 0x33, 0x34, 0x35,
				0x36, 0x37, 0x38, 0x39, 0x30, 0x2F, 0x54, 0x59,
				0x50, 0x45, 0x3D, 0x50, 0x4C, 0x4D, 0x4E, 0x00,
				0x97, 0x2B, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
				0x36, 0x36, 0x36, 0x36, 0x2F, 0x54, 0x59, 0x50,
				0x45, 0x3D, 0x50, 0x4C, 0x4D, 0x4E, 0x00, 0x8A,
				0x80, 0x8F, 0x81, 0x94, 0x80, 0x86, 0x81, 0x90,
				0x81, 0x84, 0xA3, 0x01, 0x1F, 0x0E, 0x83, 0xC0,
				0x22, 0x3C, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x2E,
				0x74, 0x78, 0x74, 0x3E, 0x00, 0x8E, 0x2F, 0x74,
				0x6D, 0x70, 0x2F, 0x70, 0x68, 0x70, 0x32, 0x49,
				0x6E, 0x74, 0x53, 0x37, 0x00, 0x48, 0x65, 0x6C,
				0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64,
				0x20, 0x21, 0x0A
};

/*
 * MMS M-Retrieve.Conf PDU 4
 * MMS-1.3-con-210: Long Media Content-Location header field value.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU where a SMIL part
 * references an object using a long "Content-Location" field value.
 * Overall message size: 2767
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000210
 * MMS version: 1.3
 * From: +33611111111/TYPE=PLMN
 * To: +33622222222/TYPE=PLMN
 * Subject: MMS-1.3-con-210
 * Class: (null)
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-05-31T10:42:30+0200
 */
static const char mms_m_retrieve_conf_4[] = "./unit/rc-mms-1-3-con-210.mms";

/*
 * MMS M-Retrieve.Conf PDU 5
 * MMS-1.3-con-271: Long Subject field.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with a maximum length
 * "us-ascii" encoded "subject" field value (40 characters) and below content:
 * Overall message size: 556
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000271
 * MMS version: 1.3
 * From: +33622222222/TYPE=PLMN
 * To: +33666565565/TYPE=PLMN
 * Subject: abcdefghijklmnopqrstuvwxyz0123456789/-+@
 * Class: (null)
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-06-03T11:23:30+0200
 */
static const char mms_m_retrieve_conf_5[] = "./unit/rc-mms-1-3-con-271.mms";

/*
 * MMS M-Retrieve.Conf PDU 6
 * MMS-1.3-con-212: Text with US-ASCII encoding.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with a text object
 * with "us-ascii" encoding and below content:
 * Overall message size: 198
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000212
 * MMS version: 1.3
 * From: +33622222222/TYPE=PLMN
 * To: +33666565565/TYPE=PLMN
 * Subject: MMS-1.3-con-212
 * Class: (null)
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-06-03T11:45:21+0200
 */
static const char mms_m_retrieve_conf_6[] = "./unit/rc-mms-1-3-con-212.mms";

/*
 * MMS M-Retrieve.Conf PDU 7
 * MMS-1.3-con-213: Text with UTF-8 encoding.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with a text object
 * with "utf-8" encoding and below content:
 * Overall message size: 249
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000213
 * MMS version: 1.3
 * From: +33622222222/TYPE=PLMN
 * To: +33666565565/TYPE=PLMN
 * Subject: MMS-1.3-con-213
 * Class: (null)
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-06-03T11:52:45+0200
 */
static const char mms_m_retrieve_conf_7[] = "./unit/rc-mms-1-3-con-213.mms";

/*
 * MMS M-Retrieve.Conf PDU 8
 * MMS-1.3-con-214: Text with UTF-16 encoding.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with a text object
 * with "utf-16" encoding and below content:
 * Overall message size: 356
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000214
 * MMS version: 1.3
 * From: +33622222222/TYPE=PLMN
 * To: +33666565565/TYPE=PLMN
 * Subject: MMS-1.3-con-214
 * Class: (null)
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-06-03T14:41:16+0200
 */
static const char mms_m_retrieve_conf_8[] = "./unit/rc-mms-1-3-con-214.mms";

/*
 * MMS M-Retrieve.Conf PDU 9
 * MMS-1.3-con-216: JPG Image size 160x120.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with a 160x120 JPG
 * Image object and below content:
 * Overall message size: 114440
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000216
 * MMS version: 1.3
 * From: +33622222222/TYPE=PLMN
 * To: +33666565565/TYPE=PLMN
 * Subject: MMS-1.3-con-216
 * Class: (null)
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-06-03T15:08:09+0200
 */
static const char mms_m_retrieve_conf_9[] = "./unit/rc-mms-1-3-con-216.mms";

/*
 * MMS M-Retrieve.Conf PDU 10
 * MMS-1.3-con-220: GIF Image size 160x120.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with a 160x120 GIF87a
 * Image object and below content:
 * Overall message size: 4460
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000220
 * MMS version: 1.3
 * From: +33622222222/TYPE=PLMN
 * To: +33666565565/TYPE=PLMN
 * Subject: MMS-1.3-con-220
 * Class: (null)
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-06-03T15:27:27+0200
 */
static const char mms_m_retrieve_conf_10[] = "./unit/rc-mms-1-3-con-220.mms";

/*
 * MMS M-Retrieve.Conf PDU 11
 * MMS-1.3-con-224: Animated GIF Image size 160x120.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with a 160x120 animated
 * GIF87a Image object and below content:
 * Overall message size: 4265
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000224
 * MMS version: 1.3
 * From: +33622222222/TYPE=PLMN
 * To: +33666565565/TYPE=PLMN
 * Subject: MMS-1.3-con-224
 * Class: (null)
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-06-03T15:38:00+0200
 */
static const char mms_m_retrieve_conf_11[] = "./unit/rc-mms-1-3-con-224.mms";

/*
 * MMS M-Retrieve.Conf PDU 12
 * MMS-1.3-con-228: WBMP Image size 160x120.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with a 160x120 WBMP
 * Image object and below content:
 * Overall message size: 2921
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000228
 * MMS version: 1.3
 * From: +33622222222/TYPE=PLMN
 * To: +33666565565/TYPE=PLMN
 * Subject: MMS-1.3-con-228
 * Class: (null)
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-06-03T15:46:42+020
 */
static const char mms_m_retrieve_conf_12[] = "./unit/rc-mms-1-3-con-228.mms";

/*
 * MMS M-Retrieve.Conf PDU 13
 * MMS-1.3-con-211: Subject field with UTF8 encoding.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with Subject field
 * with UTF8 encoding and below content:
 * Overall message size: 544
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000211
 * MMS version: 1.3
 * From: +33622222222/TYPE=PLMN
 * To: +33666565565/TYPE=PLMN
 * Subject: Shõrt Téxt - ¥üëäÿ
 * Class: (null)
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-06-03T16:01:31+0200
 */
static const char mms_m_retrieve_conf_13[] = "./unit/rc-mms-1-3-con-211.mms";

/*
 * MMS M-Retrieve.Conf PDU 14
 * MMS-1.3-con-282: Receive recognised fields with unrecognised values.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with recognised field
 * but with an unrecognised value (X-Mms-Message-Class: "NewMessageClass") and
 * below content:
 * Overall message size: 6231
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000282
 * MMS version: 1.3
 * From: +33622222222/TYPE=PLMN
 * To: +33666565565/TYPE=PLMN
 * Subject: MMS-1.3-con-282
 * Class: NewMessageClass
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-06-03T16:25:07+0200
 */
static const char mms_m_retrieve_conf_14[] = "./unit/rc-mms-1-3-con-282.mms";

/*
 * MMS M-Retrieve.Conf PDU 15
 * MMS-1.3-con-281: Receive unrecognised header field.
 * This PDU shows the decoding of a M-Retrieve.Conf PDU with an unrecognised
 * header field (X-MMS-Unrecognised-Header-Field: "Yes") and below content:
 * Overall message size: 6250
 * MMS message type: retrieve-conf
 * MMS transaction id: 00000000281
 * MMS version: 1.3
 * From: +33622222222/TYPE=PLMN
 * To: +33666565565/TYPE=PLMN
 * Subject: MMS-1.3-con-281
 * Class: (null)
 * Priority: (null)
 * Msg-Id: (null)
 * Date: 2011-06-03T16:37:02+0200
 */
static const char mms_m_retrieve_conf_15[] = "./unit/rc-mms-1-3-con-281.mms";

/*
 * MMS M-Send.Conf PDU 1
 * This PDU shows the decoding of a M-Send.Conf PDU with an accepted "response
 * status" and a below content:
 * Overall message size: 28
 * MMS message type: send-conf
 * MMS transaction id: 31887
 * MMS version: 1.0
 * Response-Status: ok
 * Msg-Id: 4dc268d71438a
 */
static const unsigned char mms_m_send_conf_1[] = {
				0x8C, 0x81, 0x98, 0x33, 0x31, 0x38, 0x38, 0x37,
				0x00, 0x8D, 0x90, 0x92, 0x80, 0x8B, 0x34, 0x64,
				0x63, 0x32, 0x36, 0x38, 0x64, 0x37, 0x31, 0x34,
				0x33, 0x38, 0x61, 0x00
};

/*
 * MMS M-Send.Conf PDU 2
 * This PDU shows the decoding of a M-Send.Conf PDU with an rejected "response
 * status" and a below content:
 * Overall message size: 13
 * MMS message type: send-conf
 * MMS transaction id: 31888
 * MMS version: 1.0
 * Response-Status: error-permanent-message-format-corrupt
 * Msg-Id: (null)
 */
static const unsigned char mms_m_send_conf_2[] = {
				0x8C, 0x81, 0x98, 0x33, 0x31, 0x38, 0x38, 0x38,
				0x00, 0x8D, 0x90, 0x92, 0xE2
};

struct mms_test {
	const char *pathname;
	const unsigned char *pdu;
	unsigned int len;
};

static const struct mms_test mms_m_notify_ind_test_1 = {
	.pdu = mms_m_notify_ind_1,
	.len = sizeof(mms_m_notify_ind_1),
};

static const struct mms_test mms_m_notify_ind_test_2 = {
	.pdu = mms_m_notify_ind_2,
	.len = sizeof(mms_m_notify_ind_2),
};

static const struct mms_test mms_m_notify_ind_test_3 = {
	.pathname = mms_m_notify_ind_3,
};

static const struct mms_test mms_m_notify_ind_test_4 = {
	.pathname = mms_m_notify_ind_4,
};

static const struct mms_test mms_m_retrieve_conf_test_1 = {
	.pdu = mms_m_retrieve_conf_1,
	.len = sizeof(mms_m_retrieve_conf_1),
};

static const struct mms_test mms_m_retrieve_conf_test_2 = {
	.pdu = mms_m_retrieve_conf_2,
	.len = sizeof(mms_m_retrieve_conf_2),
};

static const struct mms_test mms_m_retrieve_conf_test_3 = {
	.pdu = mms_m_retrieve_conf_3,
	.len = sizeof(mms_m_retrieve_conf_3),
};

static const struct mms_test mms_m_retrieve_conf_test_4 = {
	.pathname = mms_m_retrieve_conf_4,
};

static const struct mms_test mms_m_retrieve_conf_test_5 = {
	.pathname = mms_m_retrieve_conf_5,
};

static const struct mms_test mms_m_retrieve_conf_test_6 = {
	.pathname = mms_m_retrieve_conf_6,
};

static const struct mms_test mms_m_retrieve_conf_test_7 = {
	.pathname = mms_m_retrieve_conf_7,
};

static const struct mms_test mms_m_retrieve_conf_test_8 = {
	.pathname = mms_m_retrieve_conf_8,
};

static const struct mms_test mms_m_retrieve_conf_test_9 = {
	.pathname = mms_m_retrieve_conf_9,
};

static const struct mms_test mms_m_retrieve_conf_test_10 = {
	.pathname = mms_m_retrieve_conf_10,
};

static const struct mms_test mms_m_retrieve_conf_test_11 = {
	.pathname = mms_m_retrieve_conf_11,
};

static const struct mms_test mms_m_retrieve_conf_test_12 = {
	.pathname = mms_m_retrieve_conf_12,
};

static const struct mms_test mms_m_retrieve_conf_test_13 = {
	.pathname = mms_m_retrieve_conf_13,
};

static const struct mms_test mms_m_retrieve_conf_test_14 = {
	.pathname = mms_m_retrieve_conf_14,
};

static const struct mms_test mms_m_retrieve_conf_test_15 = {
	.pathname = mms_m_retrieve_conf_15,
};

static const struct mms_test mms_m_send_conf_test_1 = {
	.pdu = mms_m_send_conf_1,
	.len = sizeof(mms_m_send_conf_1),
};

static const struct mms_test mms_m_send_conf_test_2 = {
	.pdu = mms_m_send_conf_2,
	.len = sizeof(mms_m_send_conf_2),
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
		case MMS_MESSAGE_TYPE_RETRIEVE_CONF:
			dump_retrieve_conf(&msg);
			break;
		case MMS_MESSAGE_TYPE_SEND_CONF:
			dump_send_conf(&msg);
			break;
		default:
			break;
		}
	}

	mms_message_free(&msg);
}

struct mms_encode_test {
	struct mms_message msg;
	const unsigned char pdu[];
};

static const struct mms_encode_test mms_m_notifyresp_ind_test_1 = {
	.msg = {
		.type = MMS_MESSAGE_TYPE_NOTIFYRESP_IND,
		.uuid = NULL,
		.path = NULL,
		.transaction_id = "0123456789abcdef",
		.version = MMS_MESSAGE_VERSION_1_2,
		.attachments = NULL,
		{.nri = {
			.notify_status = MMS_MESSAGE_NOTIFY_STATUS_RETRIEVED,
		} }
	},
	.pdu = {	0x8C, 0x83, 0x98, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
			0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65,
			0x66, 0x00, 0x8D, 0x92, 0x95, 0x81
	}
};

static void test_encode_mms(gconstpointer data)
{
	struct mms_encode_test *test_msg = (struct mms_encode_test *) data;
	char *filepath;
	gboolean ret;
	int fd;

	filepath = g_strdup_printf("%s/.mms/mms_XXXXXX.tmp",
							g_get_home_dir());
	if (filepath == NULL)
		return;

	fd = g_mkstemp_full(filepath, O_WRONLY | O_CREAT, S_IWUSR | S_IRUSR);
	if (fd < 0) {
		g_free(filepath);
		return;
	}

	if (g_test_verbose())
		g_print("tmp filename : %s\n", filepath);

	ret = mms_message_encode(&test_msg->msg, fd);

	close(fd);

	if (ret == TRUE)
		ret = check_encoded_msg(filepath, test_msg->pdu);

	unlink(filepath);

	g_free(filepath);

	g_assert(ret == TRUE);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_data_func("/mmsutil/Decode MMS M-Notify.Ind PDU 1",
				&mms_m_notify_ind_test_1, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Notify.Ind PDU 2",
				&mms_m_notify_ind_test_2, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Notify.Ind PDU 3",
				&mms_m_notify_ind_test_3, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Notify.Ind PDU 4",
				&mms_m_notify_ind_test_4, test_decode_mms);

	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 1",
				&mms_m_retrieve_conf_test_1, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 2",
				&mms_m_retrieve_conf_test_2, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 3",
				&mms_m_retrieve_conf_test_3, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 4",
				&mms_m_retrieve_conf_test_4, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 5",
				&mms_m_retrieve_conf_test_5, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 6",
				&mms_m_retrieve_conf_test_6, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 7",
				&mms_m_retrieve_conf_test_7, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 8",
				&mms_m_retrieve_conf_test_8, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 9",
				&mms_m_retrieve_conf_test_9, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 10",
				&mms_m_retrieve_conf_test_10, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 11",
				&mms_m_retrieve_conf_test_11, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 12",
				&mms_m_retrieve_conf_test_12, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 13",
				&mms_m_retrieve_conf_test_13, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 14",
				&mms_m_retrieve_conf_test_14, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Retrieve.Conf PDU 15",
				&mms_m_retrieve_conf_test_15, test_decode_mms);

	g_test_add_data_func("/mmsutil/Decode MMS M-Send.Conf PDU 1",
				&mms_m_send_conf_test_1, test_decode_mms);
	g_test_add_data_func("/mmsutil/Decode MMS M-Send.Conf PDU 2",
				&mms_m_send_conf_test_2, test_decode_mms);

	g_test_add_data_func("/mmsutil/Encode MMS M-NotifyResp.Ind 1",
				&mms_m_notifyresp_ind_test_1, test_encode_mms);

	return g_test_run();
}

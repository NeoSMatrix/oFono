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

enum mms_message_type {
	MMS_MESSAGE_TYPE_SEND_REQ =			128,
	MMS_MESSAGE_TYPE_SEND_CONF =			129,
	MMS_MESSAGE_TYPE_NOTIFICATION_IND =		130,
	MMS_MESSAGE_TYPE_NOTIFYRESP_IND =		131,
	MMS_MESSAGE_TYPE_RETRIEVE_CONF =		132,
	MMS_MESSAGE_TYPE_ACKNOWLEDGE_IND =		133,
	MMS_MESSAGE_TYPE_DELIVERY_IND =			134,
};

enum mms_message_status {
	MMS_MESSAGE_STATUS_DOWNLOADED,
	MMS_MESSAGE_STATUS_RECEIVED,
	MMS_MESSAGE_STATUS_READ,
	MMS_MESSAGE_STATUS_SENT,
	MMS_MESSAGE_STATUS_DRAFT,
};

enum mms_message_rsp_status {
	MMS_MESSAGE_RSP_STATUS_OK =					128,
	MMS_MESSAGE_RSP_STATUS_ERR_UNSUPPORTED_MESSAGE =		136,
	MMS_MESSAGE_RSP_STATUS_ERR_TRANS_FAILURE =			192,
	MMS_MESSAGE_RSP_STATUS_ERR_TRANS_NETWORK_PROBLEM =		195,
	MMS_MESSAGE_RSP_STATUS_ERR_PERM_FAILURE =			224,
	MMS_MESSAGE_RSP_STATUS_ERR_PERM_SERVICE_DENIED =		225,
	MMS_MESSAGE_RSP_STATUS_ERR_PERM_MESSAGE_FORMAT_CORRUPT =	226,
	MMS_MESSAGE_RSP_STATUS_ERR_PERM_SENDING_ADDRESS_UNRESOLVED =	227,
	MMS_MESSAGE_RSP_STATUS_ERR_PERM_CONTENT_NOT_ACCEPTED =		229,
	MMS_MESSAGE_RSP_STATUS_ERR_PERM_LACK_OF_PREPAID =		235,
};

enum mms_message_notify_status {
	MMS_MESSAGE_NOTIFY_STATUS_RETRIEVED =		129,
	MMS_MESSAGE_NOTIFY_STATUS_REJECTED =		130,
	MMS_MESSAGE_NOTIFY_STATUS_DEFERRED =		131,
	MMS_MESSAGE_NOTIFY_STATUS_UNRECOGNISED =	132,
};

enum mms_message_delivery_status {
	MMS_MESSAGE_DELIVERY_STATUS_EXPIRED =		128,
	MMS_MESSAGE_DELIVERY_STATUS_RETRIEVED =		129,
	MMS_MESSAGE_DELIVERY_STATUS_REJECTED =		130,
	MMS_MESSAGE_DELIVERY_STATUS_DEFERRED =		131,
	MMS_MESSAGE_DELIVERY_STATUS_UNRECOGNISED =	132,
	MMS_MESSAGE_DELIVERY_STATUS_INDETERMINATE =	133,
	MMS_MESSAGE_DELIVERY_STATUS_FORWARDED =		134,
	MMS_MESSAGE_DELIVERY_STATUS_UNREACHABLE =	135,
};

enum mms_message_sender_visibility {
	MMS_MESSAGE_SENDER_VISIBILITY_HIDE =		128,
	MMS_MESSAGE_SENDER_VISIBILITY_SHOW =		129,
};

enum mms_message_version {
	MMS_MESSAGE_VERSION_1_0 =	0x90,
	MMS_MESSAGE_VERSION_1_1 =	0x91,
	MMS_MESSAGE_VERSION_1_2 =	0x92,
	MMS_MESSAGE_VERSION_1_3 =	0x93,
};

struct mms_notification_ind {
	char *from;
	char *subject;
	char *cls;
	unsigned int size;
	time_t expiry;
	char *location;
};

struct mms_retrieve_conf {
	enum mms_message_status status;
	char *from;
	char *to;
	char *subject;
	char *cls;
	char *priority;
	char *msgid;
	time_t date;
};

struct mms_send_req {
	enum mms_message_status status;
	char *to;
	time_t date;
	char *content_type;
	gboolean dr;
};

struct mms_send_conf {
	enum mms_message_rsp_status rsp_status;
	char *msgid;
};

struct mms_notification_resp_ind {
	enum mms_message_notify_status notify_status;
};

struct mms_attachment {
	unsigned char *data;
	size_t offset;
	size_t length;
	char *content_type;
	char *content_id;
};

struct mms_message {
	enum mms_message_type type;
	char *uuid;
	char *path;
	char *transaction_id;
	unsigned char version;
	GSList *attachments;
	union {
		struct mms_notification_ind ni;
		struct mms_retrieve_conf rc;
		struct mms_send_req sr;
		struct mms_send_conf sc;
		struct mms_notification_resp_ind nri;
	};
};

char *mms_content_type_get_param_value(const char *content_type,
						const char *param_name);
gboolean mms_message_decode(const unsigned char *pdu,
				unsigned int len, struct mms_message *out);
gboolean mms_message_encode(struct mms_message *msg, int fd);
void mms_message_free(struct mms_message *msg);
const char *mms_message_status_get_string(enum mms_message_status status);

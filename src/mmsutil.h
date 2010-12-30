/*
 *
 *  Multimedia Messagin	Service
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
 *  alon	with this program; if not, write to the Free Software
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

struct mms_notification_ind {
	char *from;
	char *subject;
	char *cls;
	unsigned int size;
	time_t expiry;
	char *location;
};

struct mms_message {
	enum mms_message_type type;
	char *transaction_id;
	unsigned char version;
	union {
		struct mms_notification_ind ni;
	};
};

gboolean mms_message_decode(const unsigned char *pdu,
				unsigned int len, struct mms_message *out);
void mms_message_free(struct mms_message *msg);

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

gboolean mms_decode(const unsigned char *pdu,
				unsigned int len, struct mms *out)
{
	return FALSE;
}

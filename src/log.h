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

void mms_info(const char *format, ...)
				__attribute__((format(printf, 1, 2)));
void mms_warn(const char *format, ...)
				__attribute__((format(printf, 1, 2)));
void mms_error(const char *format, ...)
				__attribute__((format(printf, 1, 2)));
void mms_debug(const char *format, ...)
				__attribute__((format(printf, 1, 2)));

struct mms_debug_desc {
	const char *name;
	const char *file;
#define MMS_DEBUG_FLAG_DEFAULT (0)
#define MMS_DEBUG_FLAG_PRINT   (1 << 0)
	unsigned int flags;
} __attribute__((aligned(8)));

#define DBG(fmt, arg...) do { \
	static struct mms_debug_desc __mms_debug_desc \
	__attribute__((used, section("__debug"), aligned(8))) = { \
		.file = __FILE__, .flags = MMS_DEBUG_FLAG_DEFAULT, \
	}; \
	if (__mms_debug_desc.flags & MMS_DEBUG_FLAG_PRINT) \
		mms_debug("%s:%s() " fmt, \
					__FILE__, __FUNCTION__ , ## arg); \
} while (0)

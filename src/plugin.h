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

struct mms_plugin_desc {
	const char *name;
	int (*init) (void);
	void (*exit) (void);
};

#ifdef MMS_PLUGIN_BUILTIN
#define MMS_PLUGIN_DEFINE(name, init, exit) \
		struct mms_plugin_desc __mms_builtin_ ## name = { \
			#name, init, exit \
		};
#else
#define MMS_PLUGIN_DEFINE(name, init, exit) \
		extern struct mms_plugin_desc mms_plugin_desc \
				__attribute__ ((visibility("default"))); \
		struct mms_plugin_desc mms_plugin_desc = { \
			#name, init, exit \
		};
#endif

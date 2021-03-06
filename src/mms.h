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

#include <glib.h>

#include "log.h"

int __mms_log_init(const char *debug, gboolean detach);
void __mms_log_cleanup(void);

#include "plugin.h"

int __mms_plugin_init(void);
void __mms_plugin_cleanup(void);

#include "dbus.h"

void __mms_dbus_set_connection(DBusConnection *conn);

#include "service.h"

int __mms_service_init(void);
void __mms_service_cleanup(void);

#include "push.h"

int __mms_push_config_files_init(void);
void __mms_push_config_files_cleanup(void);

#include "store.h"

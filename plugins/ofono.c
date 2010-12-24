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

#include <errno.h>

#include <glib.h>
#include <gdbus.h>

#include "plugin.h"
#include "log.h"

static gboolean ofono_running = FALSE;

static void ofono_connect(DBusConnection *conn, void *user_data)
{
	DBG("");

	ofono_running = TRUE;
}

static void ofono_disconnect(DBusConnection *conn, void *user_data)
{
	DBG("");

	ofono_running = FALSE;
}

static DBusConnection *connection;
static guint ofono_watch;

static int ofono_init(void)
{
	connection = g_dbus_setup_private(DBUS_BUS_SYSTEM, NULL, NULL);
	if (connection == NULL)
		return -EPERM;

	ofono_watch = g_dbus_add_service_watch(connection, "org.ofono",
				ofono_connect, ofono_disconnect, NULL, NULL);

	return 0;
}

static void ofono_exit(void)
{
	if (ofono_watch > 0)
		g_dbus_remove_watch(connection, ofono_watch);

	if (ofono_running == TRUE)
		ofono_disconnect(connection, NULL);

	dbus_connection_unref(connection);
}

MMS_PLUGIN_DEFINE(ofono, ofono_init, ofono_exit)

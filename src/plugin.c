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

#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/stat.h>

#include <glib.h>

#include "mms.h"

static GSList *plugins = NULL;

struct mms_plugin {
	void *handle;
	struct mms_plugin_desc *desc;
};

static gboolean add_plugin(void *handle, struct mms_plugin_desc *desc)
{
	struct mms_plugin *plugin;

	if (desc->init == NULL)
		return FALSE;

	plugin = g_try_new0(struct mms_plugin, 1);
	if (plugin == NULL)
		return FALSE;

	plugin->handle = handle;
	plugin->desc = desc;

	if (desc->init() < 0) {
		g_free(plugin);
		return FALSE;
	}

	plugins = g_slist_append(plugins, plugin);
	DBG("Plugin %s loaded", desc->name);

	return TRUE;
}

#include "builtin.h"

int __mms_plugin_init(void)
{
	GDir *dir;
	const char *file;
	unsigned int i;

	if (strlen(PLUGINDIR) == 0)
		return -EINVAL;

	DBG("");

	for (i = 0; __mms_builtin[i]; i++)
		add_plugin(NULL, __mms_builtin[i]);

	dir = g_dir_open(PLUGINDIR, 0, NULL);
	if (dir == NULL)
		return -EIO;

	while ((file = g_dir_read_name(dir)) != NULL) {
		struct mms_plugin_desc *desc;
		void *handle;
		char *filename;

		if (g_str_has_prefix(file, "lib") == TRUE ||
				g_str_has_suffix(file, ".so") == FALSE)
			continue;

		filename = g_build_filename(PLUGINDIR, file, NULL);

		handle = dlopen(filename, RTLD_NOW);
		if (handle == NULL) {
			mms_error("Can't load plugin %s: %s",
							filename, dlerror());
			g_free(filename);
			continue;
		}

		g_free(filename);

		desc = dlsym(handle, "mms_plugin_desc");
		if (desc == NULL) {
			mms_error("Can't load plugin description: %s",
								dlerror());
			dlclose(handle);
			continue;
		}

		if (add_plugin(handle, desc) == FALSE)
				dlclose(handle);
	}

	g_dir_close(dir);

	return 0;
}

void __mms_plugin_cleanup(void)
{
	GSList *list;

	DBG("");

	for (list = plugins; list; list = list->next) {
		struct mms_plugin *plugin = list->data;

		if (plugin->desc->exit)
			plugin->desc->exit();

		if (plugin->handle != NULL)
			dlclose(plugin->handle);

		g_free(plugin);
	}

	g_slist_free(plugins);
}

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

#include "mms.h"

struct mms_service {
	gint refcount;
	gboolean registered;
	char *identity;
};

struct mms_service *mms_service_create(void)
{
	struct mms_service *service;

	service = g_try_new0(struct mms_service, 1);
	if (service == NULL)
		return NULL;

	service->refcount = 1;

	DBG("service %p", service);

	return service;
}

struct mms_service *mms_service_ref(struct mms_service *service)
{
	if (service == NULL)
		return NULL;

	g_atomic_int_inc(&service->refcount);

	return service;
}

void mms_service_unref(struct mms_service *service)
{
	if (service == NULL)
		return;

	if (g_atomic_int_dec_and_test(&service->refcount) == FALSE)
		return;

	DBG("service %p", service);

	g_free(service->identity);
	g_free(service);
}

int mms_service_register(struct mms_service *service)
{
	DBG("service %p", service);

	if (service == NULL)
		return -EINVAL;

	if (service->identity == NULL)
		return -EINVAL;

	service->registered = TRUE;

	return 0;
}

int mms_service_unregister(struct mms_service *service)
{
	DBG("service %p", service);

	if (service == NULL)
		return -EINVAL;

	service->registered = FALSE;

	return 0;
}

int mms_service_set_identity(struct mms_service *service,
					const char *identity)
{
	DBG("service %p identity %s", service, identity);

	if (service == NULL)
		return -EINVAL;

	if (service->registered == TRUE)
		return -EBUSY;

	g_free(service->identity);
	service->identity = g_strdup(identity);

	return 0;
}

void mms_service_push_notify(struct mms_service *service,
					unsigned char *data, int len)
{
	DBG("service %p data %p len %d", service, data, len);

	mms_push_notify(data, len);
}

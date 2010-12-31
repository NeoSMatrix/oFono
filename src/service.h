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

#include "types.h"

struct mms_service;

struct mms_service *mms_service_create(void);
struct mms_service *mms_service_ref(struct mms_service *service);
void mms_service_unref(struct mms_service *service);

int mms_service_register(struct mms_service *service);
int mms_service_unregister(struct mms_service *service);

int mms_service_set_identity(struct mms_service *service,
					const char *identity);
int mms_service_set_mmsc(struct mms_service *service, const char *mmsc);

void mms_service_push_notify(struct mms_service *service,
					unsigned char *data, int len);

void mms_service_bearer_notify(struct mms_service *service, mms_bool_t active,
				const char *interface, const char *proxy);

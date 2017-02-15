/*
 * Copyright (C) 2016 prpl Foundation
 * Written by Felix Fietkau <nbd@nbd.name>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef __SCALD_H
#define __SCALD_H

#define SCALD_UBUS_PREFIX	"scald"

#include <libubox/avl.h>
#include <libubus.h>
#include "scapi.h"

struct scald_model {
	struct avl_node avl;
	struct scapi_model scapi;
	struct ubus_object ubus;

	int n_plugins;
	struct scapi_plugin **plugins;
	void **plugin_priv;
};

enum scapi_ptr_type {
	SCAPI_PTR_PLUGIN,
	SCAPI_PTR_OBJ,
	SCAPI_PTR_OBJ_ENTRY,
	SCAPI_PTR_PARAM,
	SCAPI_PTR_PARAM_VALUE,
};

extern const char *ubus_prefix;
extern struct ubus_context *ubus_ctx;
extern struct ubus_object main_object;

int scald_ubus_init(const char *path);
void scald_plugin_load(const char *path);
struct scald_model *scald_model_new(const char *name);
void scald_status_models_dump(struct blob_buf *buf);
void scald_plugin_add_option(char *arg);

struct blob_buf *scald_event_new(struct ubus_object *obj);
void scald_event_add_ptr(struct blob_buf *buf, struct scapi_ptr *ptr,
			 enum scapi_ptr_type type);
void scald_event_notify(const char *type, struct scapi_ptr *ptr,
			enum scapi_ptr_type ptr_type);

void scald_acl_init(struct ubus_context *ctx);

void scald_acl_req_init(struct ubus_request_data *req, const char *method);
int scald_acl_req_check(struct scapi_ptr *ptr, enum scapi_ptr_type type);
void scald_acl_req_done(void);

#endif

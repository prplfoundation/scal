/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
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

#include <libubox/blobmsg.h>
#include "scald.h"

struct ubus_context *ubus_ctx;
static const char *ubus_path;
static struct blob_buf b;

static int
scald_handle_status(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	void *c;

	blob_buf_init(&b, 0);
	c = blobmsg_open_table(&b, "models");
	scald_status_models_dump(&b);
	blobmsg_close_table(&b, c);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static struct ubus_method main_object_methods[] = {
	{ "status", scald_handle_status },
};

static struct ubus_object_type main_object_type =
	UBUS_OBJECT_TYPE("scald", main_object_methods);

static struct ubus_object main_object = {
	.name = "scald",
	.type = &main_object_type,
	.methods = main_object_methods,
	.n_methods = ARRAY_SIZE(main_object_methods),
};

int scald_ubus_init(const char *path)
{
	ubus_path = path;
	ubus_ctx = ubus_connect(path);
	if (!ubus_ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	ubus_add_uloop(ubus_ctx);
	ubus_add_object(ubus_ctx, &main_object);
	return 0;
}

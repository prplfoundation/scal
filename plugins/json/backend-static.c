/*
 * Copyright (C) 2016 prpl Foundation
 * Written by Felix Fietkau <nbd@nbd.name>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <libubox/blobmsg_json.h>
#include <ctype.h>
#include "scapi_json.h"

static int static_param_get(struct sj_session *ctx, struct blob_attr *data, struct blob_buf *buf)
{
	static const struct blobmsg_policy policy = { "value", BLOBMSG_TYPE_UNSPEC };
	struct blob_attr *val;

	blobmsg_parse(&policy, 1, &val, blobmsg_data(data), blobmsg_data_len(data));
	if (!val)
		return SC_ERR_INVALID_DATA;

	blobmsg_add_blob(buf, val);
	return 0;
}

static struct sj_backend static_backend = {
	.get = static_param_get,
};

static void __constructor sj_static_init(void)
{
	sj_backend_add(&static_backend, "static");
}

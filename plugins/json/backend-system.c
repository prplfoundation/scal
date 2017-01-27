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
#include "scapi_json.h"

static int current_time_get(struct blob_buf *buf, const char *param, const char *type)
{
	time_t now = time(NULL);
	char *str;
	size_t len = 64;

	if (!type)
		return SC_ERR_INVALID_ARGUMENT;

	if (!strcmp(type, "xsd")) {
		str = blobmsg_alloc_string_buffer(buf, "value", len + 1);
		len = strftime(str, len, "%Y-%m-%dT%H:%M:%S%z", localtime(&now));
		memmove(str + len - 1, str + len - 2, 3);
		str[len - 2] = ':';
		blobmsg_add_string_buffer(buf);
		return 0;
	}

	return SC_ERR_INVALID_ARGUMENT;
}

static const struct {
	const char *name;
	int (*get)(struct blob_buf *buf, const char *param, const char *type);
} parameters[] = {
	{ "current_time", current_time_get },
};

static int system_param_get(struct sj_session *ctx, struct blob_attr *data, struct blob_buf *buf)
{
	enum {
		DATA_PARAM,
		DATA_TYPE,
		__DATA_MAX
	};
	static const struct blobmsg_policy policy[__DATA_MAX] = {
		[DATA_PARAM] = { "parameter", BLOBMSG_TYPE_STRING },
		[DATA_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__DATA_MAX];
	const char *name;
	const char *type = NULL;
	int i;

	blobmsg_parse(policy, __DATA_MAX, tb, blobmsg_data(data), blobmsg_data_len(data));

	if (!tb[DATA_PARAM])
		return SC_ERR_INVALID_ARGUMENT;

	name = blobmsg_data(tb[DATA_PARAM]);
	if (tb[DATA_TYPE])
		type = blobmsg_data(tb[DATA_TYPE]);

	for (i = 0; i < ARRAY_SIZE(parameters); i++) {
		if (strcmp(parameters[i].name, name) != 0)
			continue;

		return parameters[i].get(buf, name, type);
	}

	return SC_ERR_INVALID_ARGUMENT;
}

static struct sj_backend system_backend = {
	.get = system_param_get,
};

static void __constructor sj_system_init(void)
{
	sj_backend_add(&system_backend, "system");
}

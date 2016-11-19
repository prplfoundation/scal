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

static int file_param_get_json(struct blob_buf *buf, const char *file,
			       struct blob_attr *key, const char *select)
{
	static struct blob_buf b;
	int ret = SC_ERR_NOT_FOUND;

	blob_buf_init(&b, 0);
	if (blobmsg_add_json_from_file(&b, file))
		ret = sj_filter_json(buf, b.head, key, select);
	blob_buf_free(&b);

	return ret;
}

static int file_param_get_string(struct blob_buf *buf, const char *file)
{
	char *str;
	FILE *f;
	int offset = 0;

	f = fopen(file, "r");
	if (!f)
		return SC_ERR_NOT_FOUND;

	str = blobmsg_alloc_string_buffer(buf, "value", offset + 256);
	while (!feof(f)) {
		int len = fread(str + offset, 1, 255, f);

		offset += len;
		if (!len)
			break;

		if (offset > 65536)
			break;
	};

	while (offset > 0 && isspace(str[offset - 1]))
		offset--;

	str[offset] = 0;

	fclose(f);
	blobmsg_add_string_buffer(buf);
	return 0;
}

static int file_param_get(struct sj_session *ctx, struct blob_attr *data, struct blob_buf *buf)
{
	enum {
		DATA_FILE,
		DATA_TYPE,
		DATA_KEY,
		DATA_SELECT,
		__DATA_MAX
	};
	static const struct blobmsg_policy policy[__DATA_MAX] = {
		[DATA_FILE] = { "file", BLOBMSG_TYPE_STRING },
		[DATA_TYPE] = { "type", BLOBMSG_TYPE_STRING },
		[DATA_KEY] = { "key", BLOBMSG_TYPE_UNSPEC },
		[DATA_SELECT] = { "select", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__DATA_MAX];
	struct blob_attr *cur;
	const char *type = "json";
	const char *file;
	const char *select = NULL;

	blobmsg_parse(policy, __DATA_MAX, tb, blobmsg_data(data), blobmsg_data_len(data));

	if (!tb[DATA_FILE])
		return SC_ERR_INVALID_ARGUMENT;

	if (tb[DATA_SELECT])
		select = blobmsg_data(tb[DATA_SELECT]);

	file = blobmsg_data(tb[DATA_FILE]);
	if ((cur = tb[DATA_TYPE]) != NULL)
		type = blobmsg_data(cur);

	if (!strcmp(type, "json"))
		return file_param_get_json(buf, file, tb[DATA_KEY], select);

	if (!strcmp(type, "string"))
		return file_param_get_string(buf, file);

	return SC_ERR_INVALID_ARGUMENT;
}

static struct sj_backend file_backend = {
	.get = file_param_get,
};

static void __constructor sj_file_init(void)
{
	sj_backend_add(&file_backend, "file");
}

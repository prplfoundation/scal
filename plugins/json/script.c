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

static void
sj_handle_script_command(struct json_script_ctx *script, const char *name,
			 struct blob_attr *cmd, struct blob_attr *vars)
{
	static const struct blobmsg_policy policy[2] = {
		{ NULL, BLOBMSG_TYPE_STRING },
		{ NULL, BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[2];
	struct sj_model *ctx = container_of(script, struct sj_model, script);
	const char *value = NULL;

	blobmsg_parse_array(policy, ARRAY_SIZE(policy), tb,
			    blobmsg_data(cmd), blobmsg_data_len(cmd));

	if (!strcmp(name, "get_current_key")) {
		value = ctx->script_obj->instance;

		if (!tb[0])
			goto invalid_arg;

		goto store_value;
	} else if (!strcmp(name, "get_param")) {
		struct sj_object_param *par;
		struct blob_attr *val;
		const char *name;

		name = blobmsg_get_string(tb[1]);
		par = avl_find_element(&ctx->script_obj->script_params,
				       name, par, avl);
		if (!par)
			goto invalid_arg;

		par->script = true;

		if (sj_param_get(ctx, par, &val))
			return;

		if (!val || blobmsg_type(val) != BLOBMSG_TYPE_STRING)
			return;

		value = blobmsg_get_string(val);
		goto store_value;
	} else {
		cb->log_msg(&plugin, SCAPI_LOG_ERROR,
			    "Unknown command: %s\n", name);
	}
	return;

store_value:
	if (value)
		kvlist_set(&ctx->script_vars, (const char *) blobmsg_data(tb[0]),
			   value);
	return;

invalid_arg:
	cb->log_msg(&plugin, SCAPI_LOG_ERROR,
		    "Invalid argument to command %s\n", name);
}

static const char *
sj_handle_script_var(struct json_script_ctx *script, const char *name,
		     struct blob_attr *v)
{
	struct sj_model *ctx = container_of(script, struct sj_model, script);

	return kvlist_get(&ctx->script_vars, name);
}

void sj_model_script_init(struct sj_model *model)
{
	json_script_init(&model->script);
	model->script.handle_var = sj_handle_script_var;
	model->script.handle_command = sj_handle_script_command;
}

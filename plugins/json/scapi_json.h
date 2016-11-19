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
#ifndef __SCAPI_JSON_H
#define __SCAPI_JSON_H

#include <libubox/json_script.h>
#include <libubox/kvlist.h>
#include <libubox/avl.h>

#include "../../scapi.h"

extern const struct scapi_cb *cb;
extern struct avl_tree filters;
extern struct avl_tree backends;
struct sj_object;

struct sj_model {
	struct json_script_ctx script;
	struct kvlist script_vars;
	struct sj_object *script_obj;
	struct avl_tree objects;
	struct blob_attr *script_data;
};

struct sj_filter {
	struct avl_node avl;

	int (*get)(struct sj_filter *f, struct blob_attr *data,
		   struct blob_attr *val, struct blob_buf *buf);
	int (*set)(struct sj_filter *f, struct blob_attr *data,
		   const char *val, struct blob_buf *buf);
};

struct sj_object_param {
	struct scapi_parameter scapi;

	struct avl_node avl;

	struct sj_object *obj;
	const char *type;

	struct sj_backend *backend;
	struct blob_attr *backend_data;

	struct sj_filter *filter;
	struct blob_attr *filter_data;

	bool readonly;
	bool hidden;
	bool script;

	void *priv;
};

struct sj_instance_list {
	struct list_head list;

	struct blob_attr *data;
	const char *path[];
};

struct sj_object {
	struct scapi_object scapi;

	struct avl_node avl;
	struct sj_object *parent;

	struct avl_tree objects;
	struct avl_tree params;
	struct avl_tree script_params;
	int n_params;

	struct sj_object_param *get_instance_keys;
	struct json_script_file *data_script;

	/* runtime state */
	struct list_head instances;
	const char *instance;

	void *priv;
};

struct sj_session {
	struct list_head list;

	struct sj_backend *backend;
};

struct sj_backend {
	struct avl_node avl;

	struct sj_session *default_session;

	struct sj_session *(*session_alloc)(struct sj_backend *ctx);
	void (*session_free)(struct sj_backend *ctx, struct sj_session *s);

	int (*get)(struct sj_session *s, struct blob_attr *data, struct blob_buf *buf);
	int (*set)(struct sj_session *s, struct blob_attr *data, const char *value);

	int (*validate)(struct sj_session *s);
	int (*commit)(struct sj_session *s);
};

void sj_model_init(struct sj_model *m);
int sj_model_load_json(struct sj_model *ctx, const char *path);
void sj_parser_free_data(void);

int sj_filter_json(struct blob_buf *buf, struct blob_attr *data,
		   const struct blob_attr *key, const char *select);
void sj_script_eval_list(struct sj_model *model, struct blob_buf *buf,
			 struct blob_attr *data);

void sj_object_run_script(struct sj_model *model, struct sj_object *obj);
int sj_object_set_instance(struct sj_model *model, struct sj_object *obj, const char *name);
int sj_object_get_instances(struct sj_model *model, struct sj_object *obj,
			    struct blob_attr **val);

int sj_param_get(struct sj_model *model, struct sj_object_param *par,
		 struct blob_attr **data);

static inline struct sj_filter *
sj_filter_get(const char *name)
{
	struct sj_filter *f;
	if (!name)
		return NULL;
	return avl_find_element(&filters, name, f, avl);
}

static inline struct sj_backend *
sj_backend_get(const char *name)
{
	struct sj_backend *b;
	if (!name)
		return NULL;
	return avl_find_element(&backends, name, b, avl);
}

static inline void
sj_backend_add(struct sj_backend *b, const char *name)
{
	b->avl.key = name;
	avl_insert(&backends, &b->avl);
}

static inline const char *
sj_object_name(struct sj_object *obj)
{
	return obj->avl.key;
}

static inline const char *
sj_object_param_name(struct sj_object_param *par)
{
	return par->avl.key;
}

#endif

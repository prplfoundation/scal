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
#ifndef __SCAPI_H
#define __SCAPI_H

#include <libubox/blobmsg.h>
#include <libubox/list.h>
#include <stdbool.h>

struct scapi_model;
struct scapi_object;
struct scapi_parameter;
struct scapi_list_ctx;

typedef void (*scapi_object_cb)(struct scapi_list_ctx *ctx,
				struct scapi_object *obj);

typedef void (*scapi_param_cb)(struct scapi_list_ctx *ctx,
				struct scapi_parameter *par);

struct scapi_ptr {
	struct scapi_plugin *plugin;
	struct scapi_model *model;
	void *model_priv;

	struct blob_attr *path;
	struct scapi_object *obj;
	struct scapi_parameter *par;
};

struct scapi_plugin {
	const char *name;

	/*
	 * Free plugin
	 */
	void (*free)(void);

	/*
	 * Free model
	 */
	void (*model_free)(struct scapi_model *model, void *priv);

	/*
	 * Fetch a list of child objects by path
	 *
	 * ptr: reference to plugin, data model and the path
	 * fill: callback for passing objects to the caller
	 * ctx: opaque data structure used by scald, passed to fill()
	 *
	 * Lifetime of struct scapi_object items is controlled by
	 * the plugin and needs to be guaranteed only until the end
	 * of the object_list call.
	 * The plugin may re-use and overwrite the data from the
	 * previous fill call
	 */
	int (*object_list)(struct scapi_ptr *ptr, scapi_object_cb fill,
			   struct scapi_list_ctx *ctx);

	/* 
	 * Fetch a reference to an object by path
	 *
	 * ptr: reference to plugin, data model and the path
	 *
	 * The pointer to the object is stored inside ptr
	 *
	 * Lifetime of the object is controlled by the plugin and
	 * must be guaranteed until the next call to object_get,
	 * object_list or free
	 */
	int (*object_get)(struct scapi_ptr *ptr);

	/*
	 * List parameters belonging to an object
	 *
	 * ptr: reference to plugin, data model and object
	 *      (provided by .object_list or .object_get)
	 * fill: callback for passing paramters to the caller
	 * ctx: opaque data structure used by scald, passed to fill()
	 *
	 * Lifetime of struct scapi_parameter items is controlled by
	 * the plugin and needs to be guaranteed only until the end
	 * of the param_list call.
	 * The plugin may re-use and overwrite the data from the
	 * previous fill call
	 */
	int (*param_list)(struct scapi_ptr *ptr, scapi_param_cb fill,
			  struct scapi_list_ctx *ctx);

	/*
	 * Get a parameter belonging to an object
	 *
	 * ptr: reference to plugin, data model and object
	 *      (provided by .object_list or .object_get)
	 * name: name of the parameter
	 * par: destination for storing the parameter reference
	 *
	 * The pointer to the parameter is stored inside ptr
	 *
	 * Lifetime of the parameter is controlled by the plugin and
	 * must be guaranteed until the next call to param_get,
	 * param_list or free
	 */
	int (*param_get)(struct scapi_ptr *ptr, const char *name);

	/*
	 * Get a parameter value
	 *
	 * ptr: reference to plugin, data model, object
	 *      (provided by .object_list or .object_get) and parameter
	 *      (provided by .param_list or .param_get)
	 * buf: blob_buf to store the value.
	 *
	 * When the storing the value inside the blob_buf,
	 * it must be named 'value'
	 */
	int (*param_read)(struct scapi_ptr *ptr, struct blob_buf *buf);

	/*
	 * Set a parameter value
	 *
	 * ptr: reference to plugin, data model, object
	 *      (provided by .object_list or .object_get) and parameter
	 *      (provided by .param_list or .param_get)
	 * val: new value
	 */
	int (*param_write)(struct scapi_ptr *ptr, struct blob_attr *val);
};

struct scapi_model {
	const char *name;
};

struct scapi_object {
	const char *name;
	bool multi_instance;
};

struct scapi_parameter {
	const char *name;
	bool readonly;
};

enum scald_log_level {
	SCAPI_LOG_ERROR,
	SCAPI_LOG_WARNING,
	SCAPI_LOG_INFO,
	SCAPI_LOG_DEBUG,
};

/* scald callbacks that can be called from scapi plugins */
struct scapi_cb {
	/* Initialize a plugin */
	void (*plugin_add) (struct scapi_plugin *p);

	/* Add a new data model (or return an existing one with the same name) */
	struct scapi_model *(*model_add)(struct scapi_plugin *p, const char *name, void *priv);

	/* Get an scald command line option specified via -x */
	const char *(*option_get)(const char *name);

	void (*log_msg)(struct scapi_plugin *p, enum scald_log_level level, const char *fmt, ...);
};

/* Defined by scapi plugin */
void scapi_module_init(const struct scapi_cb *cb);

#endif

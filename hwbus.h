/*
 * Sbus interfaces for XRadio drivers
 *
 * Copyright (c) 2013, XRadio
 * Author: XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#ifndef __HWBUS_H
#define __HWBUS_H

#include <linux/version.h>
#include <linux/module.h>
/*
 * hwbus priv forward definition.
 * Implemented and instantiated in particular modules.
 */

struct cw1200_common;
/*sdio bus private struct*/
#define SDIO_UNLOAD   0
#define SDIO_LOAD     1

typedef void (*hwbus_irq_handler)(void *priv);
struct hwbus_priv {
	struct sdio_func     *func;
	spinlock_t            lock;
	hwbus_irq_handler      irq_handler;
	void                 *irq_priv;
	wait_queue_head_t     init_wq;
	int                   load_state;
};

struct hwbus_ops {
	int (*hwbus_data_read)(struct hwbus_priv *self, unsigned int addr,
					void *dst, int count);
	int (*hwbus_data_write)(struct hwbus_priv *self, unsigned int addr,
					const void *src, int count);
	void (*lock)(struct hwbus_priv *self);
	void (*unlock)(struct hwbus_priv *self);
	size_t (*align_size)(struct hwbus_priv *self, size_t size);
	int (*set_block_size)(struct hwbus_priv *self, size_t size);
	int (*irq_subscribe)(struct hwbus_priv *self, 
	      hwbus_irq_handler handler, void *priv);
	int (*irq_unsubscribe)(struct hwbus_priv *self);
	int (*power_mgmt)(struct hwbus_priv *self, bool suspend);
	int (*reset)(struct hwbus_priv *self);
};

//hwbus init functions
struct device * hwbus_sdio_init(struct hwbus_ops  **sdio_ops, 
                               struct hwbus_priv **sdio_priv);
void  hwbus_sdio_deinit(void);

#endif /* __HWBUS_H */

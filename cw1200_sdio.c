/*
 * SDIO driver for XRadio drivers
 *
 * Copyright (c) 2013, XRadio
 * Author: XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/gpio.h>
#include <linux/regulator/consumer.h>
#include <linux/delay.h>
#include <linux/mmc/host.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/card.h>
#include <linux/mmc/sdio.h>
#include <linux/spinlock.h>
#include <asm/mach-types.h>
#include <net/mac80211.h>

#include "platform.h"
#include "cw1200.h"
#include "hwbus.h"

/* sdio vendor id and device id*/
#define SDIO_VENDOR_ID_XRADIO 0x0020
#define SDIO_DEVICE_ID_XRADIO 0x2281
static const struct sdio_device_id cw1200_sdio_ids[] = {
	{ SDIO_DEVICE(SDIO_VENDOR_ID_XRADIO, SDIO_DEVICE_ID_XRADIO) },
	//{ SDIO_DEVICE(SDIO_ANY_ID, SDIO_ANY_ID) },
	{ /* end: all zeroes */			},
};

/* hwbus_ops implemetation */
static int sdio_data_read(struct hwbus_priv *self, unsigned int addr,
                          void *dst, int count)
{
	return sdio_memcpy_fromio(self->func, dst, addr, count);
}

static int sdio_data_write(struct hwbus_priv *self, unsigned int addr,
                           const void *src, int count)
{
	return sdio_memcpy_toio(self->func, addr, (void *)src, count);
}

static void sdio_lock(struct hwbus_priv *self)
{
	sdio_claim_host(self->func);
}

static void sdio_unlock(struct hwbus_priv *self)
{
	sdio_release_host(self->func);
}

static size_t sdio_align_len(struct hwbus_priv *self, size_t size)
{
	return sdio_align_size(self->func, size);
}

static int sdio_set_blk_size(struct hwbus_priv *self, size_t size)
{
	return sdio_set_block_size(self->func, size);
}

#ifndef CONFIG_XRADIO_USE_GPIO_IRQ
static void sdio_irq_handler(struct sdio_func *func)
{
	struct hwbus_priv *self = sdio_get_drvdata(func);
	unsigned long flags;
	hwbus_printk(XRADIO_DBG_TRC, "%s\n", __FUNCTION__);

	BUG_ON(!self);
	spin_lock_irqsave(&self->lock, flags);
	if (self->irq_handler)
		self->irq_handler(self->irq_priv);
	spin_unlock_irqrestore(&self->lock, flags);
}
#endif

static int sdio_irq_subscribe(struct hwbus_priv *self,
				     hwbus_irq_handler handler,
				     void *priv)
{
	int ret = 0;
	unsigned long flags;
	

	if (!handler)
		return -EINVAL;
	hwbus_printk(XRADIO_DBG_TRC, "%s\n", __FUNCTION__);

	spin_lock_irqsave(&self->lock, flags);
	self->irq_priv = priv;
	self->irq_handler = handler;
	spin_unlock_irqrestore(&self->lock, flags);

	sdio_claim_host(self->func);
#ifndef CONFIG_XRADIO_USE_GPIO_IRQ
	ret = sdio_claim_irq(self->func, sdio_irq_handler);
#else
	ret = cw1200_request_gpio_irq(&(self->func->dev), self);
	if (!ret) {
		/* Hack to access Fuction-0 */
		u8 cccr;
		int func_num = self->func->num;
		self->func->num = 0;
		cccr = sdio_readb(self->func, SDIO_CCCR_IENx, &ret);
		cccr |= BIT(0);         /* Master interrupt enable ... */
		cccr |= BIT(func_num);  /* ... for our function */
		sdio_writeb(self->func, cccr, SDIO_CCCR_IENx, &ret);
		if (ret) {
			cw1200_free_gpio_irq(&(self->func->dev), self);
			if (MCI_CHECK_READY(self->func->card->host, 1000) != 0)
				hwbus_printk(XRADIO_DBG_ERROR, "%s:MCI_CHECK_READY timeout\n", __func__);
		}
		/* Restore the WLAN function number */
		self->func->num = func_num;
	}
#endif
	sdio_release_host(self->func);

	return ret;
}

static int sdio_irq_unsubscribe(struct hwbus_priv *self)
{
	int ret = 0;
	unsigned long flags;

	hwbus_printk(XRADIO_DBG_TRC, "%s\n", __FUNCTION__);

	if (!self->irq_handler) {
		hwbus_printk(XRADIO_DBG_ERROR, "%s:irq_handler is NULL!\n", __FUNCTION__);
		return 0;
	}

#ifndef CONFIG_XRADIO_USE_GPIO_IRQ
	sdio_claim_host(self->func);
	ret = sdio_release_irq(self->func);
	sdio_release_host(self->func);
#else
	cw1200_free_gpio_irq(&(self->func->dev), self);
#endif  //CONFIG_XRADIO_USE_GPIO_IRQ

	spin_lock_irqsave(&self->lock, flags);
	self->irq_priv = NULL;
	self->irq_handler = NULL;
	spin_unlock_irqrestore(&self->lock, flags);

	return ret;
}

static int sdio_pm(struct hwbus_priv *self, bool  suspend)
{
	int ret = 0;
	if (suspend) {
		/* Notify SDIO that XRADIO will remain powered during suspend */
		ret = sdio_set_host_pm_flags(self->func, MMC_PM_KEEP_POWER);
		if (ret)
			hwbus_printk(XRADIO_DBG_ERROR,
				    "Error setting SDIO pm flags: %i\n", ret);
	}

	return ret;
}

static int sdio_reset(struct hwbus_priv *self)
{
	return 0;
}

static struct hwbus_ops sdio_hwbus_ops = {
	.hwbus_data_read     = sdio_data_read,
	.hwbus_data_write    = sdio_data_write,
	.lock               = sdio_lock,
	.unlock             = sdio_unlock,
	.align_size         = sdio_align_len,
	.set_block_size     = sdio_set_blk_size,
	.irq_subscribe      = sdio_irq_subscribe,
	.irq_unsubscribe    = sdio_irq_unsubscribe,
	.power_mgmt         = sdio_pm,
	.reset              = sdio_reset,
};
static struct hwbus_priv sdio_self;

//for sdio debug  2015-5-26 11:01:21
#if (defined(CONFIG_XRADIO_DEBUGFS))
u32 dbg_sdio_clk = 0;
static int sdio_set_clk(struct sdio_func *func, u32 clk)
{
	if (func) {
		if (func->card->host->ops->set_ios && clk >= 1000000) {  //set min to 1M
			sdio_claim_host(func);
			func->card->host->ios.clock = (clk < 50000000) ? clk : 50000000;
			func->card->host->ops->set_ios(func->card->host, &func->card->host->ios);
			sdio_release_host(func);
			hwbus_printk(XRADIO_DBG_ALWY, "%s:change mmc clk=%d\n", __func__, 
			            func->card->host->ios.clock);
		} else {
			hwbus_printk(XRADIO_DBG_ALWY, "%s:fail change mmc clk=%d\n", __func__, clk);
		}
	}
	return 0;
	hwbus_printk(XRADIO_DBG_TRC, "%s\n", __FUNCTION__);
}
#endif

/* Probe Function to be called by SDIO stack when device is discovered */
static int sdio_probe(struct sdio_func *func,
                      const struct sdio_device_id *id)
{
	hwbus_printk(XRADIO_DBG_ALWY, "XRadio Device:sdio clk=%d\n",
	            func->card->host->ios.clock);
	hwbus_printk(XRADIO_DBG_NIY, "sdio func->class=%x\n", func->class);
	hwbus_printk(XRADIO_DBG_NIY, "sdio_vendor: 0x%04x\n", func->vendor);
	hwbus_printk(XRADIO_DBG_NIY, "sdio_device: 0x%04x\n", func->device);
	hwbus_printk(XRADIO_DBG_NIY, "Function#: 0x%04x\n",   func->num);

#if (defined(CONFIG_XRADIO_DEBUGFS))
	if (dbg_sdio_clk)
		sdio_set_clk(func, dbg_sdio_clk);
#endif

#if 0  //for odly and sdly debug.
{
	u32 sdio_param = 0;
	sdio_param = readl(__io_address(0x01c20088));
	sdio_param &= ~(0xf<<8);
	sdio_param |= 3<<8;
	sdio_param &= ~(0xf<<20);
	sdio_param |= s_dly<<20;
	writel(sdio_param, __io_address(0x01c20088));
	hwbus_printk(XRADIO_DBG_ALWY, "%s: 0x01c20088=0x%08x\n", __func__, sdio_param);
}
#endif

	sdio_self.func = func;
	sdio_self.func->card->quirks |= MMC_QUIRK_BROKEN_BYTE_MODE_512;
	sdio_set_drvdata(func, &sdio_self);
	sdio_claim_host(func);
	sdio_enable_func(func);
	sdio_release_host(func);

	sdio_self.load_state = SDIO_LOAD;
	wake_up(&sdio_self.init_wq);

	return 0;
}
/* Disconnect Function to be called by SDIO stack when
 * device is disconnected */
static void sdio_remove(struct sdio_func *func)
{
	struct hwbus_priv *self = sdio_get_drvdata(func);
	sdio_claim_host(func);
	sdio_disable_func(func);
	sdio_release_host(func);
	sdio_set_drvdata(func, NULL);
	if (self) {
		self->func = NULL;
	}
}

static int sdio_suspend(struct device *dev)
{
	int ret = 0;
	/*
	struct sdio_func *func = dev_to_sdio_func(dev);
	ret = sdio_set_host_pm_flags(func, MMC_PM_KEEP_POWER);
	if (ret)
		hwbus_printk(XRADIO_DBG_ERROR, "set MMC_PM_KEEP_POWER error\n");
	*/
	return ret;
}

static int sdio_resume(struct device *dev)
{
	return 0;
}

static const struct dev_pm_ops sdio_pm_ops = {
	.suspend = sdio_suspend,
	.resume  = sdio_resume,
};

static struct sdio_driver sdio_driver = {
	.name     = "cw1200_wlan",
	.id_table = cw1200_sdio_ids,
	.probe    = sdio_probe,
	.remove   = sdio_remove,
	.drv = {
		.pm = &sdio_pm_ops,
	}
};

/* Init Module function -> Called by insmod */
struct device * hwbus_sdio_init(struct hwbus_ops  **sdio_ops, 
                               struct hwbus_priv **sdio_priv)
{
	int ret = 0;
	struct device * sdio_dev = NULL;
	hwbus_printk(XRADIO_DBG_TRC, "%s\n", __FUNCTION__);
	
	//initialize hwbus_priv.
	if (sdio_self.load_state == SDIO_UNLOAD) {
		spin_lock_init(&sdio_self.lock);
		init_waitqueue_head(&sdio_self.init_wq);

		//setup sdio driver.
		ret = sdio_register_driver(&sdio_driver);
		if (ret) {
			hwbus_printk(XRADIO_DBG_ERROR,"sdio_register_driver failed!\n");
			return NULL;
		}

		//module power up.
		cw1200_wlan_power(1);
		//detect sdio card.
		cw1200_sdio_detect(1);
		if (wait_event_interruptible_timeout(sdio_self.init_wq,
			sdio_self.load_state == SDIO_LOAD, 2*HZ) <= 0) {
			sdio_unregister_driver(&sdio_driver);
			sdio_self.load_state = SDIO_UNLOAD;

			cw1200_wlan_power(0); //power down.
			cw1200_sdio_detect(0);
			hwbus_printk(XRADIO_DBG_ERROR,"sdio probe timeout!\n");
			return NULL;
		}
	}

	//register hwbus.
	sdio_dev   = &(sdio_self.func->dev);
	*sdio_ops  = &sdio_hwbus_ops;
	*sdio_priv = &sdio_self;

	return sdio_dev;
}

/* SDIO Driver Unloading */
void hwbus_sdio_deinit()
{
	hwbus_printk(XRADIO_DBG_TRC, "%s\n", __FUNCTION__);
	if (sdio_self.load_state != SDIO_UNLOAD) {
		sdio_unregister_driver(&sdio_driver);
		memset(&sdio_self, 0, sizeof(sdio_self));
		sdio_self.load_state = SDIO_UNLOAD;

		cw1200_wlan_power(0);  //power down.
		cw1200_sdio_detect(0);
		mdelay(10);
	}
}

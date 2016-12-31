/*
 * platform interfaces for XRadio drivers
 *
 * Implemented by platform vendor(such as AllwinnerTech).
 *
 * Copyright (c) 2013, XRadio
 * Author: XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#ifndef XRADIO_PLAT_H_INCLUDED
#define XRADIO_PLAT_H_INCLUDED

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/mmc/host.h>

/* Select hardware platform.*/
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0))
#define PLAT_ALLWINNER_SUNXI
#define MCI_RESCAN_CARD(id, ins)  sunxi_mci_rescan_card(id, ins)
#define MCI_CHECK_READY(h, t)     sunxi_mci_check_r1_ready(h, t)

extern void sunxi_mci_rescan_card(unsigned id, unsigned insert);
extern int sunxi_mci_check_r1_ready(struct mmc_host* mmc, unsigned ms);

#else
#define PLAT_ALLWINNER_SUN6I
#define MCI_RESCAN_CARD(id, ins)  sw_mci_rescan_card(id, ins)
#define MCI_CHECK_READY(h, t)     sw_mci_check_r1_ready(h, t)

extern void sw_mci_rescan_card(unsigned id, unsigned insert);
extern int sw_mci_check_r1_ready(struct mmc_host* mmc, unsigned ms);
#endif
/* the rf_pm api */
extern int wifi_pm_gpio_ctrl(char *name, int level);
/* platform interfaces */
int  cw1200_plat_init(void);
void cw1200_plat_deinit(void);
int  cw1200_sdio_detect(int enable);
int  cw1200_request_gpio_irq(struct device *dev, void *sbus_priv);
void cw1200_free_gpio_irq(struct device *dev, void *sbus_priv);
int  cw1200_wlan_power(int on);

#endif /* XRADIO_PLAT_H_INCLUDED */

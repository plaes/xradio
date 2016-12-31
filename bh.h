/*
 * Device handling thread interface for mac80211 ST-Ericsson CW1200 drivers
 *
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
 * Copyright (c) 2013, XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef CW1200_BH_H
#define CW1200_BH_H

/* extern */ struct cw1200_common;

int cw1200_register_bh(struct cw1200_common *priv);
void cw1200_unregister_bh(struct cw1200_common *priv);
void cw1200_irq_handler(struct cw1200_common *priv);
void cw1200_bh_wakeup(struct cw1200_common *priv);
int cw1200_bh_suspend(struct cw1200_common *priv);
int cw1200_bh_resume(struct cw1200_common *priv);
/* Must be called from BH thread. */
void cw1200_enable_powersave(struct cw1200_vif *priv,
			     bool enable);
int wsm_release_tx_buffer(struct cw1200_common *priv, int count);

/* API changes:
 * cw1200_enable_powersave: cw1200_common -> cw1200_vif
 **/

/* Only in XRadio Driver */
#define CW1200_BH_THREAD   "cw1200_bh"
#define SDIO_BLOCK_SIZE (528)
int wsm_release_vif_tx_buffer(struct cw1200_common *priv, int if_id,
                              int count);
int cw1200_init_resv_skb(struct cw1200_common *priv);
void cw1200_deinit_resv_skb(struct cw1200_common *priv);
int cw1200_realloc_resv_skb(struct cw1200_common *priv, struct sk_buff *skb);
#endif /* CW1200_BH_H */

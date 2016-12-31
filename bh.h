/*
 * Data Transmission thread for XRadio drivers
 *
 * Copyright (c) 2013, XRadio
 * Author: XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef XRADIO_BH_H
#define XRADIO_BH_H

#define XRADIO_BH_THREAD   "cw1200_bh"

/* extern */ struct cw1200_common;

#define SDIO_BLOCK_SIZE (528)

int cw1200_register_bh(struct cw1200_common *hw_priv);
void cw1200_unregister_bh(struct cw1200_common *hw_priv);
void cw1200_irq_handler(struct cw1200_common *hw_priv);
void cw1200_bh_wakeup(struct cw1200_common *hw_priv);
int cw1200_bh_suspend(struct cw1200_common *hw_priv);
int cw1200_bh_resume(struct cw1200_common *hw_priv);
/* Must be called from BH thread. */
void cw1200_enable_powersave(struct cw1200_vif *priv, bool enable);
int wsm_release_tx_buffer(struct cw1200_common *hw_priv, int count);
int wsm_release_vif_tx_buffer(struct cw1200_common *hw_priv, int if_id,
                              int count);
int cw1200_init_resv_skb(struct cw1200_common *hw_priv);
void cw1200_deinit_resv_skb(struct cw1200_common *hw_priv);
int cw1200_realloc_resv_skb(struct cw1200_common *hw_priv,
							struct sk_buff *skb);
#endif /* XRADIO_BH_H */

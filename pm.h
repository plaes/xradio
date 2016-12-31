/*
 * power management interfaces for XRadio drivers
 *
 * Copyright (c) 2013, XRadio
 * Author: XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#ifndef PM_H_INCLUDED
#define PM_H_INCLUDED

/* ******************************************************************** */
/* mac80211 API */

#ifdef CONFIG_PM

#define XRADIO_PM_DEVICE   "cw1200_pm"
#define XRADIO_WAKE_LOCK   "cw1200_wlan"

/* extern */   struct cw1200_common; 
 /* private */ struct cw1200_suspend_state;

struct cw1200_pm_state {
	struct timer_list stay_awake;
	struct platform_device *pm_dev;
	spinlock_t lock;
	long expires_save;
};

struct cw1200_pm_state_vif {
	struct cw1200_suspend_state *suspend_state;
};

#ifdef CONFIG_XRADIO_SUSPEND_POWER_OFF
enum suspend_state {
	XRADIO_RESUME = 0,
	XRADIO_CONNECT_SUSP,
	XRADIO_DISCONNECT_SUSP,
	XRADIO_POWEROFF_SUSP
};
#endif
int cw1200_pm_init(struct cw1200_pm_state *pm, struct cw1200_common *priv);
void cw1200_pm_deinit(struct cw1200_pm_state *pm);
void cw1200_pm_stay_awake(struct cw1200_pm_state *pm, unsigned long tmo);
void cw1200_pm_lock_awake(struct cw1200_pm_state *pm);
void cw1200_pm_unlock_awake(struct cw1200_pm_state *pm);
int cw1200_wow_suspend(struct ieee80211_hw *hw, struct cfg80211_wowlan *wowlan);
int cw1200_wow_resume(struct ieee80211_hw *hw);

#endif /* CONFIG_PM */

#endif

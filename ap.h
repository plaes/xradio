/*
 * STA and AP APIs for XRadio drivers
 *
 * Copyright (c) 2013, XRadio
 * Author: XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef AP_H_INCLUDED
#define AP_H_INCLUDED

#define XRADIO_NOA_NOTIFICATION_DELAY 10

#ifdef AP_HT_CAP_UPDATE
#define HT_INFO_OFFSET 4
#define HT_INFO_MASK 0x0011
#define HT_INFO_IE_LEN 22
#endif

int cw1200_set_tim(struct ieee80211_hw *dev, struct ieee80211_sta *sta,
		   bool set);
int cw1200_sta_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta);
int cw1200_sta_remove(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		      struct ieee80211_sta *sta);
void cw1200_sta_notify(struct ieee80211_hw *dev, struct ieee80211_vif *vif,
		       enum sta_notify_cmd notify_cmd,
		       struct ieee80211_sta *sta);
void cw1200_bss_info_changed(struct ieee80211_hw *dev,
			     struct ieee80211_vif *vif,
			     struct ieee80211_bss_conf *info,
			     u32 changed);
int cw1200_ampdu_action(struct ieee80211_hw *hw,
			struct ieee80211_vif *vif,
			enum ieee80211_ampdu_mlme_action action,
			struct ieee80211_sta *sta, u16 tid, u16 *ssn,
			u8 buf_size);

void cw1200_suspend_resume(struct cw1200_vif *priv,
			  struct wsm_suspend_resume *arg);
void cw1200_set_tim_work(struct work_struct *work);
void cw1200_set_cts_work(struct work_struct *work);
void cw1200_multicast_start_work(struct work_struct *work);
void cw1200_multicast_stop_work(struct work_struct *work);
void cw1200_mcast_timeout(unsigned long arg);
int cw1200_find_link_id(struct cw1200_vif *priv, const u8 *mac);
int cw1200_alloc_link_id(struct cw1200_vif *priv, const u8 *mac);
void cw1200_link_id_work(struct work_struct *work);
void cw1200_link_id_gc_work(struct work_struct *work);
#if defined(CONFIG_XRADIO_USE_EXTENSIONS)
/*in linux3.4 mac,it does't have the noa pass*/
//void cw1200_notify_noa(struct cw1200_vif *priv, int delay);
#endif
int xrwl_unmap_link(struct cw1200_vif *priv, int link_id);
#ifdef AP_HT_CAP_UPDATE
void cw1200_ht_info_update_work(struct work_struct *work);
#endif

#endif

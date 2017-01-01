/*
 * Mac80211 STA interface for ST-Ericsson CW1200 mac80211 drivers
 *
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
 * Copyright (c) 2013, XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef STA_H_INCLUDED
#define STA_H_INCLUDED


#ifdef XRADIO_USE_LONG_KEEP_ALIVE_PERIOD
#define XRADIO_KEEP_ALIVE_PERIOD         (28)
#else
/*For Samsung, it is defined as 4*/
#define XRADIO_KEEP_ALIVE_PERIOD         (4)
#endif

#ifdef XRADIO_USE_LONG_DTIM_PERIOD
#define XRADIO_BSS_LOSS_THOLD_DEF  30
#define XRADIO_LINK_LOSS_THOLD_DEF 50
#else
#define XRADIO_BSS_LOSS_THOLD_DEF  20
#define XRADIO_LINK_LOSS_THOLD_DEF 40
#endif

#define XRADIO_NOA_NOTIFICATION_DELAY 10

#ifdef AP_HT_CAP_UPDATE
#define HT_INFO_OFFSET 4
#define HT_INFO_MASK 0x0011
#define HT_INFO_IE_LEN 22
#endif

/*in linux3.4 mac,it does't have the noa pass*/
//void cw1200_notify_noa(struct cw1200_vif *priv, int delay);
int xrwl_unmap_link(struct cw1200_vif *priv, int link_id);
#ifdef AP_HT_CAP_UPDATE
void cw1200_ht_info_update_work(struct work_struct *work);
#endif


/* ******************************************************************** */
/* mac80211 API								*/

int cw1200_start(struct ieee80211_hw *dev);
void cw1200_stop(struct ieee80211_hw *dev);
int cw1200_add_interface(struct ieee80211_hw *dev,
			 struct ieee80211_vif *vif);
void cw1200_remove_interface(struct ieee80211_hw *dev,
			     struct ieee80211_vif *vif);
int cw1200_change_interface(struct ieee80211_hw *dev,
			    struct ieee80211_vif *vif,
			    enum nl80211_iftype new_type,
			    bool p2p);
int cw1200_config(struct ieee80211_hw *dev, u32 changed);
void cw1200_configure_filter(struct ieee80211_hw *dev,
			     unsigned int changed_flags,
			     unsigned int *total_flags,
			     u64 multicast);
int cw1200_conf_tx(struct ieee80211_hw *dev, struct ieee80211_vif *vif,
		   u16 queue, const struct ieee80211_tx_queue_params *params);
int cw1200_get_stats(struct ieee80211_hw *dev,
		     struct ieee80211_low_level_stats *stats);
/* Not more a part of interface?
int cw1200_get_tx_stats(struct ieee80211_hw *dev,
			struct ieee80211_tx_queue_stats *stats);
*/
int cw1200_set_key(struct ieee80211_hw *dev, enum set_key_cmd cmd,
		   struct ieee80211_vif *vif, struct ieee80211_sta *sta,
		   struct ieee80211_key_conf *key);

int cw1200_set_rts_threshold(struct ieee80211_hw *hw, u32 value);

/* TODO: extra parameters in mainline driver */
void cw1200_flush(struct ieee80211_hw *hw,
		bool drop);


u64 cw1200_prepare_multicast(struct ieee80211_hw *hw,
			     struct netdev_hw_addr_list *mc_list);

int cw1200_set_pm(struct cw1200_vif *priv, const struct wsm_set_pm *arg);

int cw1200_remain_on_channel(struct ieee80211_hw *hw,
                             struct ieee80211_channel *chan,
                             enum nl80211_channel_type channel_type,
                             int duration);
int cw1200_cancel_remain_on_channel(struct ieee80211_hw *hw);
int cw1200_set_arpreply(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
void cw1200_set_data_filter(struct ieee80211_hw *hw,
                            struct ieee80211_vif *vif,
                            void *data,
                            int len);

/* ******************************************************************** */
/* WSM callbacks							*/

/* void cw1200_set_pm_complete_cb(struct cw1200_common *hw_priv,
	struct wsm_set_pm_complete *arg); */
void cw1200_channel_switch_cb(struct cw1200_common *hw_priv);

/* ******************************************************************** */
/* WSM events								*/

void cw1200_free_event_queue(struct cw1200_common *priv);
void cw1200_event_handler(struct work_struct *work);
void cw1200_bss_loss_work(struct work_struct *work);
void cw1200_connection_loss_work(struct work_struct *work);
void cw1200_keep_alive_work(struct work_struct *work);
void cw1200_tx_failure_work(struct work_struct *work);

/* ******************************************************************** */
/* Internal API								*/

int cw1200_setup_mac(struct cw1200_common *priv);
void cw1200_join_timeout(struct work_struct *work);
void cw1200_unjoin_work(struct work_struct *work);
void cw1200_offchannel_work(struct work_struct *work);
void cw1200_wep_key_work(struct work_struct *work);

void cw1200_update_filtering(struct cw1200_vif *priv);
void cw1200_update_filtering_work(struct work_struct *work);
void cw1200_set_beacon_wakeup_period_work(struct work_struct *work);
int cw1200_enable_listening(struct cw1200_vif *priv, struct ieee80211_channel *chan);
int cw1200_disable_listening(struct cw1200_vif *priv);
int cw1200_set_uapsd_param(struct cw1200_vif *priv,
				const struct wsm_edca_params *arg);
void cw1200_ba_work(struct work_struct *work);
void cw1200_ba_timer(unsigned long arg);

/* AP stuffs */
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



int __cw1200_flush(struct cw1200_common *hw_priv, bool drop, int if_id);
void cw1200_join_work(struct work_struct *work);

const u8 *cw1200_get_ie(u8 *start, size_t len, u8 ie);
int cw1200_vif_setup(struct cw1200_vif *priv);
int cw1200_setup_mac_pvif(struct cw1200_vif *priv);
void cw1200_iterate_vifs(void *data, u8 *mac, struct ieee80211_vif *vif);
void cw1200_rem_chan_timeout(struct work_struct *work);
int cw1200_set_macaddrfilter(struct cw1200_common *hw_priv, struct cw1200_vif *priv, u8 *data);
#ifdef ROAM_OFFLOAD
int cw1200_testmode_event(struct wiphy *wiphy, const u32 msg_id,
                          const void *data, int len, gfp_t gfp);
#endif /*ROAM_OFFLOAD*/
#ifdef IPV6_FILTERING
int cw1200_set_na(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
#endif /*IPV6_FILTERING*/
#ifdef CONFIG_XRADIO_TESTMODE
void cw1200_device_power_calc(struct cw1200_common *priv,
                              s16 max_output_power, s16 fe_cor, u32 band);
int cw1200_testmode_cmd(struct ieee80211_hw *hw, void *data, int len);
int cw1200_tesmode_event(struct wiphy *wiphy, const u32 msg_id,
                         const void *data, int len, gfp_t gfp);
int cw1200_get_tx_power_range(struct ieee80211_hw *hw);
int cw1200_get_tx_power_level(struct ieee80211_hw *hw);
#endif /* CONFIG_XRADIO_TESTMODE */

#endif

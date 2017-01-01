/*
 * STA APIs for XRadio drivers
 *
 * Copyright (c) 2013, XRadio
 * Author: XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/firmware.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <net/ndisc.h>

#include "cw1200.h"
#include "sta.h"
#include "fwio.h"
#include "bh.h"
#include "wsm.h"
#ifdef ROAM_OFFLOAD
#include <net/netlink.h>
#endif /*ROAM_OFFLOAD*/
#ifdef CONFIG_XRADIO_TESTMODE
#include "nl80211_testmode_msg_copy.h"
#include <net/netlink.h>
#endif /* CONFIG_XRADIO_TESTMODE */

#include "net/mac80211.h"

#ifdef TES_P2P_0002_ROC_RESTART
#include <linux/time.h>
#endif

#define XRADIO_LINK_ID_GC_TIMEOUT        ((unsigned long)(10 * HZ))
#define XRADIO_ENABLE_ARP_FILTER_OFFLOAD  3

#ifndef ERP_INFO_BYTE_OFFSET
#define ERP_INFO_BYTE_OFFSET 2
#endif

#ifdef IPV6_FILTERING
#define XRADIO_ENABLE_NDP_FILTER_OFFLOAD	3
#endif /*IPV6_FILTERING*/

static int cw1200_upload_beacon(struct cw1200_vif *priv);
#ifdef PROBE_RESP_EXTRA_IE
static int cw1200_upload_proberesp(struct cw1200_vif *priv);
#endif
static int cw1200_upload_pspoll(struct cw1200_vif *priv);
static int cw1200_upload_null(struct cw1200_vif *priv);
static int cw1200_upload_qosnull(struct cw1200_vif *priv);
static int cw1200_start_ap(struct cw1200_vif *priv);
static int cw1200_update_beaconing(struct cw1200_vif *priv);
/*
static int cw1200_enable_beaconing(struct cw1200_vif *priv,
				   bool enable);
*/
static void __cw1200_sta_notify(struct cw1200_vif *priv,
				enum sta_notify_cmd notify_cmd,
				int link_id);


#define WEP_ENCRYPT_HDR_SIZE    4
#define WEP_ENCRYPT_TAIL_SIZE   4
#define WPA_ENCRYPT_HDR_SIZE    8
#define WPA_ENCRYPT_TAIL_SIZE   12
#define WPA2_ENCRYPT_HDR_SIZE   8
#define WPA2_ENCRYPT_TAIL_SIZE  8
#define WAPI_ENCRYPT_HDR_SIZE   18
#define WAPI_ENCRYPT_TAIL_SIZE  16
#define MAX_ARP_REPLY_TEMPLATE_SIZE     120
#ifdef CONFIG_XRADIO_TESTMODE
const int cw1200_1d_to_ac[8] = {
	IEEE80211_AC_BE,
	IEEE80211_AC_BK,
	IEEE80211_AC_BK,
	IEEE80211_AC_BE,
	IEEE80211_AC_VI,
	IEEE80211_AC_VI,
	IEEE80211_AC_VO,
	IEEE80211_AC_VO
};

/**
 * enum cw1200_ac_numbers - AC numbers as used in cw1200
 * @XRADIO_AC_VO: voice
 * @XRADIO_AC_VI: video
 * @XRADIO_AC_BE: best effort
 * @XRADIO_AC_BK: background
 */
enum cw1200_ac_numbers {
	XRADIO_AC_VO	= 0,
	XRADIO_AC_VI	= 1,
	XRADIO_AC_BE	= 2,
	XRADIO_AC_BK	= 3,
};
#endif /*CONFIG_XRADIO_TESTMODE*/

#ifdef IPV6_FILTERING
#define MAX_NEIGHBOR_ADVERTISEMENT_TEMPLATE_SIZE 144
#endif /*IPV6_FILTERING*/

static inline void __cw1200_free_event_queue(struct list_head *list)
{
	while (!list_empty(list)) {
		struct cw1200_wsm_event *event =
			list_first_entry(list, struct cw1200_wsm_event,link);
		list_del(&event->link);
		kfree(event);
	}
}

#ifdef CONFIG_XRADIO_TESTMODE
/* User priority to WSM queue mapping */
const int cw1200_priority_to_queueId[8] = {
	WSM_QUEUE_BEST_EFFORT,
	WSM_QUEUE_BACKGROUND,
	WSM_QUEUE_BACKGROUND,
	WSM_QUEUE_BEST_EFFORT,
	WSM_QUEUE_VIDEO,
	WSM_QUEUE_VIDEO,
	WSM_QUEUE_VOICE,
	WSM_QUEUE_VOICE
};
#endif /*CONFIG_XRADIO_TESTMODE*/
static inline void __cw1200_bf_configure(struct cw1200_vif *priv)
{
	priv->bf_table.numOfIEs = __cpu_to_le32(3);
	priv->bf_table.entry[0].ieId = WLAN_EID_VENDOR_SPECIFIC;
	priv->bf_table.entry[0].actionFlags = 
	                        WSM_BEACON_FILTER_IE_HAS_CHANGED       |
	                        WSM_BEACON_FILTER_IE_NO_LONGER_PRESENT |
	                        WSM_BEACON_FILTER_IE_HAS_APPEARED;

	priv->bf_table.entry[0].oui[0] = 0x50;
	priv->bf_table.entry[0].oui[1] = 0x6F;
	priv->bf_table.entry[0].oui[2] = 0x9A;

	priv->bf_table.entry[1].ieId = WLAN_EID_ERP_INFO;
	priv->bf_table.entry[1].actionFlags = 
	                        WSM_BEACON_FILTER_IE_HAS_CHANGED       |
	                        WSM_BEACON_FILTER_IE_NO_LONGER_PRESENT |
	                        WSM_BEACON_FILTER_IE_HAS_APPEARED;

	priv->bf_table.entry[2].ieId = WLAN_EID_HT_INFORMATION;
	priv->bf_table.entry[2].actionFlags = 
	                        WSM_BEACON_FILTER_IE_HAS_CHANGED       |
	                        WSM_BEACON_FILTER_IE_NO_LONGER_PRESENT |
	                        WSM_BEACON_FILTER_IE_HAS_APPEARED;

	priv->bf_control.enabled = WSM_BEACON_FILTER_ENABLE;
}

/* ******************************************************************** */
/* STA API								*/

int cw1200_start(struct ieee80211_hw *dev)
{
	struct cw1200_common *hw_priv = dev->priv;
	int ret = 0;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	if (wait_event_interruptible_timeout(hw_priv->wsm_startup_done,
				hw_priv->driver_ready, 3*HZ) <= 0) {
		sta_printk(XRADIO_DBG_ERROR,"%s driver is not ready!\n", __func__);
		return -ETIMEDOUT;
	}

	mutex_lock(&hw_priv->conf_mutex);

#ifdef CONFIG_XRADIO_TESTMODE
	spin_lock_bh(&hw_priv->tsm_lock);
	memset(&hw_priv->tsm_stats, 0, sizeof(struct xr_tsm_stats));
	memset(&hw_priv->tsm_info, 0, sizeof(struct cw1200_tsm_info));
	spin_unlock_bh(&hw_priv->tsm_lock);
#endif /*CONFIG_XRADIO_TESTMODE*/
	memcpy(hw_priv->mac_addr, dev->wiphy->perm_addr, ETH_ALEN);
	hw_priv->softled_state = 0;

	ret = cw1200_setup_mac(hw_priv);
	if (WARN_ON(ret)) {
		sta_printk(XRADIO_DBG_ERROR,"%s, cw1200_setup_mac failed(%d)\n", 
		           __func__, ret);
		goto out;
	}

out:
	mutex_unlock(&hw_priv->conf_mutex);
	return ret;
}

void cw1200_stop(struct ieee80211_hw *dev)
{
	struct cw1200_common *hw_priv = dev->priv;
	struct cw1200_vif *priv = NULL;
	LIST_HEAD(list);
	int i;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	wsm_lock_tx(hw_priv);
	while (down_trylock(&hw_priv->scan.lock)) {
		/* Scan is in progress. Force it to stop. */
		hw_priv->scan.req = NULL;
		schedule();
	}
	up(&hw_priv->scan.lock);

	cancel_delayed_work_sync(&hw_priv->scan.probe_work);
	cancel_delayed_work_sync(&hw_priv->scan.timeout);
#ifdef CONFIG_XRADIO_TESTMODE
	cancel_delayed_work_sync(&hw_priv->advance_scan_timeout);
#endif
	flush_workqueue(hw_priv->workqueue);
	del_timer_sync(&hw_priv->ba_timer);

	mutex_lock(&hw_priv->conf_mutex);

	hw_priv->softled_state = 0;
	/* cw1200_set_leds(hw_priv); */

	spin_lock(&hw_priv->event_queue_lock);
	list_splice_init(&hw_priv->event_queue, &list);
	spin_unlock(&hw_priv->event_queue_lock);
	__cw1200_free_event_queue(&list);

	for (i = 0; i < 4; i++)
		cw1200_queue_clear(&hw_priv->tx_queue[i], XRWL_ALL_IFS);

	/* HACK! */
	if (atomic_xchg(&hw_priv->tx_lock, 1) != 1)
		sta_printk(XRADIO_DBG_WARN, "TX is force-unlocked due to stop request.\n");

	cw1200_for_each_vif(hw_priv, priv, i) {
		if (!priv)
			continue;
		priv->mode = NL80211_IFTYPE_UNSPECIFIED;
		priv->listening = false;
		priv->delayed_link_loss = 0;
		priv->join_status = XRADIO_JOIN_STATUS_PASSIVE;
		cancel_delayed_work_sync(&priv->join_timeout);
		cancel_delayed_work_sync(&priv->bss_loss_work);
		cancel_delayed_work_sync(&priv->connection_loss_work);
		cancel_delayed_work_sync(&priv->link_id_gc_work);
		del_timer_sync(&priv->mcast_timeout);
	}

	wsm_unlock_tx(hw_priv);

	mutex_unlock(&hw_priv->conf_mutex);
}

int cw1200_add_interface(struct ieee80211_hw *dev,
			 struct ieee80211_vif *vif)
{
	int ret;
	struct cw1200_common *hw_priv = dev->priv;
	struct cw1200_vif *priv;
	struct cw1200_vif **drv_priv = (void *)vif->drv_priv;
#ifndef P2P_MULTIVIF
	int i;
	if (atomic_read(&hw_priv->num_vifs) >= XRWL_MAX_VIFS)
		return -EOPNOTSUPP;
#endif

	if (wait_event_interruptible_timeout(hw_priv->wsm_startup_done,
				hw_priv->driver_ready, 3*HZ) <= 0) {
		sta_printk(XRADIO_DBG_ERROR,"%s driver is not ready!\n", __func__);
		return -ETIMEDOUT;
	}

	/* fix the problem that when connected,then deauth */
	vif->driver_flags = vif->driver_flags | IEEE80211_VIF_BEACON_FILTER;
	priv = xrwl_get_vif_from_ieee80211(vif);
	atomic_set(&priv->enabled, 0);

	*drv_priv = priv;
	/* __le32 auto_calibration_mode = __cpu_to_le32(1); */

	mutex_lock(&hw_priv->conf_mutex);

	priv->mode = vif->type;

	spin_lock(&hw_priv->vif_list_lock);
	if (atomic_read(&hw_priv->num_vifs) < XRWL_MAX_VIFS) {
#ifdef P2P_MULTIVIF
		if (!memcmp(vif->addr, hw_priv->addresses[0].addr, ETH_ALEN)) {
			priv->if_id = 0;
		} else if (!memcmp(vif->addr, hw_priv->addresses[1].addr,
			ETH_ALEN)) {
			priv->if_id = 2;
		} else if (!memcmp(vif->addr, hw_priv->addresses[2].addr,
			ETH_ALEN)) {
			priv->if_id = 1;
		}
		sta_printk(XRADIO_DBG_MSG, "%s: if_id %d mac %pM\n",
		           __func__, priv->if_id, vif->addr);
#else
		for (i = 0; i < XRWL_MAX_VIFS; i++)
			if (!memcmp(vif->addr, hw_priv->addresses[i].addr, ETH_ALEN))
				break;
		if (i == XRWL_MAX_VIFS) {
			spin_unlock(&hw_priv->vif_list_lock);
			mutex_unlock(&hw_priv->conf_mutex);
			return -EINVAL;
		}
		priv->if_id = i;
#endif
		hw_priv->if_id_slot |= BIT(priv->if_id);
		priv->hw_priv = hw_priv;
		priv->hw      = dev;
		priv->vif     = vif;
		hw_priv->vif_list[priv->if_id] = vif;
		atomic_inc(&hw_priv->num_vifs);
	} else {
		spin_unlock(&hw_priv->vif_list_lock);
		mutex_unlock(&hw_priv->conf_mutex);
		return -EOPNOTSUPP;
	}
	spin_unlock(&hw_priv->vif_list_lock);
	/* TODO:COMBO :Check if MAC address matches the one expected by FW */
	memcpy(hw_priv->mac_addr, vif->addr, ETH_ALEN);

	/* Enable auto-calibration */
	/* Exception in subsequent channel switch; disabled.
	WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_SET_AUTO_CALIBRATION_MODE,
		&auto_calibration_mode, sizeof(auto_calibration_mode)));
	*/
	sta_printk(XRADIO_DBG_MSG, "Interface ID:%d of type:%d added\n",
	           priv->if_id, priv->mode);
	mutex_unlock(&hw_priv->conf_mutex);

	cw1200_vif_setup(priv);

	ret = WARN_ON(cw1200_setup_mac_pvif(priv));

	return ret;
}

void cw1200_remove_interface(struct ieee80211_hw *dev,
			     struct ieee80211_vif *vif)
{
	struct cw1200_common *hw_priv = dev->priv;
	struct cw1200_vif *priv = xrwl_get_vif_from_ieee80211(vif);
	struct wsm_reset reset = {
		.reset_statistics = true,
	};
	int i;
	bool is_htcapie = false;
	struct cw1200_vif *tmp_priv;
	struct wsm_operational_mode mode = {
		.power_mode = wsm_power_mode_quiescent,
		.disableMoreFlagUsage = true,
	};
	sta_printk(XRADIO_DBG_WARN, "!!! %s: vif_id=%d\n", __func__, priv->if_id);
	atomic_set(&priv->enabled, 0);
	down(&hw_priv->scan.lock);
	if(priv->join_status == XRADIO_JOIN_STATUS_STA){
		if (atomic_xchg(&priv->delayed_unjoin, 0)) {
			wsm_unlock_tx(hw_priv);
			sta_printk(XRADIO_DBG_ERROR, "%s:delayed_unjoin exist!\n", __func__);
		}
		cancel_work_sync(&priv->unjoin_work);
		wsm_lock_tx(hw_priv);
		cw1200_unjoin_work(&priv->unjoin_work);
	}
	mutex_lock(&hw_priv->conf_mutex);
	cw1200_tx_queues_lock(hw_priv);
	wsm_lock_tx(hw_priv);
	switch (priv->join_status) {
	case XRADIO_JOIN_STATUS_AP:
		for (i = 0; priv->link_id_map; ++i) {
			if (priv->link_id_map & BIT(i)) {
				xrwl_unmap_link(priv, i);
				priv->link_id_map &= ~BIT(i);
			}
		}
		memset(priv->link_id_db, 0,
				sizeof(priv->link_id_db));
		priv->sta_asleep_mask = 0;
		priv->enable_beacon = false;
		priv->tx_multicast = false;
		priv->aid0_bit_set = false;
		priv->buffered_multicasts = false;
		priv->pspoll_mask = 0;
		reset.link_id = 0;
		wsm_reset(hw_priv, &reset, priv->if_id);
		WARN_ON(wsm_set_operational_mode(hw_priv, &mode, priv->if_id));
		cw1200_for_each_vif(hw_priv, tmp_priv, i) {
#ifdef P2P_MULTIVIF
			if ((i == (XRWL_MAX_VIFS - 1)) || !tmp_priv)
#else
			if (!tmp_priv)
#endif
				continue;
			if ((tmp_priv->join_status == XRADIO_JOIN_STATUS_STA) && tmp_priv->htcap)
				is_htcapie = true;
		}

		if (is_htcapie) {
			hw_priv->vif0_throttle = XRWL_HOST_VIF0_11N_THROTTLE;
			hw_priv->vif1_throttle = XRWL_HOST_VIF1_11N_THROTTLE;
			sta_printk(XRADIO_DBG_NIY, "AP REMOVE HTCAP 11N %d\n",hw_priv->vif0_throttle);
		} else {
			hw_priv->vif0_throttle = XRWL_HOST_VIF0_11BG_THROTTLE;
			hw_priv->vif1_throttle = XRWL_HOST_VIF1_11BG_THROTTLE;
			sta_printk(XRADIO_DBG_NIY, "AP REMOVE 11BG %d\n",hw_priv->vif0_throttle);
		}
		break;
	case XRADIO_JOIN_STATUS_MONITOR:
		cw1200_disable_listening(priv);
		break;
	default:
		break;
	}
	/* TODO:COMBO: Change Queue Module */
	__cw1200_flush(hw_priv, false, priv->if_id);

	cancel_delayed_work_sync(&priv->bss_loss_work);
	cancel_delayed_work_sync(&priv->connection_loss_work);
	cancel_delayed_work_sync(&priv->link_id_gc_work);
	cancel_delayed_work_sync(&priv->join_timeout);
	cancel_delayed_work_sync(&priv->set_cts_work);
	cancel_delayed_work_sync(&priv->pending_offchanneltx_work);

	del_timer_sync(&priv->mcast_timeout);
	/* TODO:COMBO: May be reset of these variables "delayed_link_loss and
	 * join_status to default can be removed as dev_priv will be freed by
	 * mac80211 */
	priv->delayed_link_loss = 0;
	priv->join_status = XRADIO_JOIN_STATUS_PASSIVE;
	wsm_unlock_tx(hw_priv);

	if ((priv->if_id ==1) && (priv->mode == NL80211_IFTYPE_AP
		|| priv->mode == NL80211_IFTYPE_P2P_GO)) {
		hw_priv->is_go_thru_go_neg = false;
	}
	spin_lock(&hw_priv->vif_list_lock);
	spin_lock(&priv->vif_lock);
	hw_priv->vif_list[priv->if_id] = NULL;
	hw_priv->if_id_slot &= (~BIT(priv->if_id));
	atomic_dec(&hw_priv->num_vifs);
	if (atomic_read(&hw_priv->num_vifs) == 0) {
		cw1200_free_keys(hw_priv);
		memset(hw_priv->mac_addr, 0, ETH_ALEN);
	}
	spin_unlock(&priv->vif_lock);
	spin_unlock(&hw_priv->vif_list_lock);
	priv->listening = false;

	cw1200_debug_release_priv(priv);

	cw1200_tx_queues_unlock(hw_priv);
	mutex_unlock(&hw_priv->conf_mutex);

	if (atomic_read(&hw_priv->num_vifs) == 0)
		flush_workqueue(hw_priv->workqueue);
	memset(priv, 0, sizeof(struct cw1200_vif));
	up(&hw_priv->scan.lock);
}

int cw1200_change_interface(struct ieee80211_hw *dev,
				struct ieee80211_vif *vif,
				enum nl80211_iftype new_type,
				bool p2p)
{
	int ret = 0;
	sta_printk(XRADIO_DBG_WARN, "%s: new type=%d(%d), p2p=%d(%d)\n",
	           __func__, new_type, vif->type, p2p, vif->p2p);
	if (new_type != vif->type || vif->p2p != p2p) {
		cw1200_remove_interface(dev, vif);
		vif->type = new_type;
		vif->p2p = p2p;
		ret = cw1200_add_interface(dev, vif);
	}

	return ret;
}

int cw1200_config(struct ieee80211_hw *dev, u32 changed)
{
	int ret = 0;
	struct cw1200_common *hw_priv = dev->priv;
	struct ieee80211_conf *conf = &dev->conf;
#ifdef CONFIG_XRADIO_TESTMODE
	int max_power_level = 0;
	int min_power_level = 0;
#endif
	/* TODO:COMBO: adjust to multi vif interface
	 * IEEE80211_CONF_CHANGE_IDLE is still handled per cw1200_vif*/
	int if_id = 0;
	struct cw1200_vif *priv;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	if (changed &
		(IEEE80211_CONF_CHANGE_MONITOR|IEEE80211_CONF_CHANGE_IDLE)) {
		/* TBD: It looks like it's transparent
		 * there's a monitor interface present -- use this
		 * to determine for example whether to calculate
		 * timestamps for packets or not, do not use instead
		 * of filter flags! */
		sta_printk(XRADIO_DBG_NIY, "ignore IEEE80211_CONF_CHANGE_MONITOR (%d)"
		           "IEEE80211_CONF_CHANGE_IDLE (%d)\n",
		           (changed & IEEE80211_CONF_CHANGE_MONITOR) ? 1 : 0,
		           (changed & IEEE80211_CONF_CHANGE_IDLE) ? 1 : 0);
		return ret;
	}

	down(&hw_priv->scan.lock);
	mutex_lock(&hw_priv->conf_mutex);
	priv = __xrwl_hwpriv_to_vifpriv(hw_priv, hw_priv->scan.if_id);
	/* TODO: IEEE80211_CONF_CHANGE_QOS */
	/* TODO:COMBO:Change when support is available mac80211*/
	if (changed & IEEE80211_CONF_CHANGE_POWER) {
		/*hw_priv->output_power = conf->power_level;*/
		hw_priv->output_power = 20;
#ifdef CONFIG_XRADIO_TESTMODE
		/* Testing if Power Level to set is out of device power range */
		if (conf->chan_conf->channel->band == IEEE80211_BAND_2GHZ) {
			max_power_level = hw_priv->txPowerRange[0].max_power_level;
			min_power_level = hw_priv->txPowerRange[0].min_power_level;
		} else {
			max_power_level = hw_priv->txPowerRange[1].max_power_level;
			min_power_level = hw_priv->txPowerRange[1].min_power_level;
		}
		if (hw_priv->output_power > max_power_level)
			hw_priv->output_power = max_power_level;
		else if (hw_priv->output_power < min_power_level)
			hw_priv->output_power = min_power_level;
#endif /* CONFIG_XRADIO_TESTMODE */

		sta_printk(XRADIO_DBG_NIY, "Config Tx power=%d, but real=%d\n",
		           conf->power_level, hw_priv->output_power);
		WARN_ON(wsm_set_output_power(hw_priv, hw_priv->output_power * 10, if_id));
	}

	if ((changed & IEEE80211_CONF_CHANGE_CHANNEL) &&
	    (hw_priv->channel != conf->channel)) {
		/* Switch Channel commented for CC Mode */
		struct ieee80211_channel *ch = conf->channel;
		sta_printk(XRADIO_DBG_WARN, "Freq %d (wsm ch: %d).\n",
		           ch->center_freq, ch->hw_value);
		/* Earlier there was a call to __cw1200_flush().
		   Removed as deemed unnecessary */
			hw_priv->channel = ch;
			hw_priv->channel_changed = 1;
	}

	mutex_unlock(&hw_priv->conf_mutex);
	up(&hw_priv->scan.lock);
	return ret;
}

void cw1200_update_filtering(struct cw1200_vif *priv)
{
	int ret;
	bool bssid_filtering = !priv->rx_filter.bssid;
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	static struct wsm_beacon_filter_control bf_disabled = {
		.enabled = 0,
		.bcn_count = 1,
	};
	bool ap_mode = 0;
	static struct wsm_beacon_filter_table bf_table_auto = {
		.numOfIEs = __cpu_to_le32(2),
		.entry[0].ieId = WLAN_EID_VENDOR_SPECIFIC,
		.entry[0].actionFlags = WSM_BEACON_FILTER_IE_HAS_CHANGED |
					WSM_BEACON_FILTER_IE_NO_LONGER_PRESENT |
					WSM_BEACON_FILTER_IE_HAS_APPEARED,
		.entry[0].oui[0] = 0x50,
		.entry[0].oui[1] = 0x6F,
		.entry[0].oui[2] = 0x9A,

		.entry[1].ieId = WLAN_EID_HT_INFORMATION,
		.entry[1].actionFlags = WSM_BEACON_FILTER_IE_HAS_CHANGED |
					WSM_BEACON_FILTER_IE_NO_LONGER_PRESENT |
					WSM_BEACON_FILTER_IE_HAS_APPEARED,
	};
	static struct wsm_beacon_filter_control bf_auto = {
		.enabled = WSM_BEACON_FILTER_ENABLE |
			WSM_BEACON_FILTER_AUTO_ERP,
		.bcn_count = 1,
	};
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	bf_auto.bcn_count = priv->bf_control.bcn_count;

	if (priv->join_status == XRADIO_JOIN_STATUS_PASSIVE)
		return;
	else if (priv->join_status == XRADIO_JOIN_STATUS_MONITOR)
		bssid_filtering = false;

	if (priv->vif && (priv->vif->type == NL80211_IFTYPE_AP))
		ap_mode = true;
	/*
	* When acting as p2p client being connected to p2p GO, in order to
	* receive frames from a different p2p device, turn off bssid filter.
	*
	* WARNING: FW dependency!
	* This can only be used with FW WSM371 and its successors.
	* In that FW version even with bssid filter turned off,
	* device will block most of the unwanted frames.
	*/
	if (priv->vif && priv->vif->p2p)
		bssid_filtering = false;

	ret = wsm_set_rx_filter(hw_priv, &priv->rx_filter, priv->if_id);
	if (!ret && !ap_mode) {
		if (priv->vif) {
			if (priv->vif->p2p || NL80211_IFTYPE_STATION != priv->vif->type)
				ret = wsm_set_beacon_filter_table(hw_priv, &priv->bf_table, priv->if_id);
			else
				ret = wsm_set_beacon_filter_table(hw_priv, &bf_table_auto, priv->if_id);
		} else
			WARN_ON(1);
	}
	if (!ret && !ap_mode) {
		if (priv->disable_beacon_filter)
			ret = wsm_beacon_filter_control(hw_priv, &bf_disabled, priv->if_id);
		else {
			if (priv->vif) {
				if (priv->vif->p2p || NL80211_IFTYPE_STATION != priv->vif->type)
					ret = wsm_beacon_filter_control(hw_priv, &priv->bf_control,
					                                 priv->if_id);
				else
					ret = wsm_beacon_filter_control(hw_priv, &bf_auto, priv->if_id);
			} else
				WARN_ON(1);
		}
	}

	if (!ret)
		ret = wsm_set_bssid_filtering(hw_priv, bssid_filtering, priv->if_id);
#if 0
	if (!ret) {
		ret = wsm_set_multicast_filter(hw_priv, &priv->multicast_filter, priv->if_id);
	}
#endif
	if (ret)
		sta_printk(XRADIO_DBG_ERROR, "%s: Update filtering failed: %d.\n",
		           __func__, ret);
	return;
}

void cw1200_update_filtering_work(struct work_struct *work)
{
	struct cw1200_vif *priv =
		container_of(work, struct cw1200_vif,
		update_filtering_work);

	cw1200_update_filtering(priv);
}

void cw1200_set_beacon_wakeup_period_work(struct work_struct *work)
{
	
	struct cw1200_vif *priv = 
	       container_of(work, struct cw1200_vif, set_beacon_wakeup_period_work);
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

#ifdef XRADIO_USE_LONG_DTIM_PERIOD
{
	int join_dtim_period_extend;
	if (priv->join_dtim_period <= 3) {
		join_dtim_period_extend = priv->join_dtim_period * 3;
	} else if (priv->join_dtim_period <= 5) {
		join_dtim_period_extend = priv->join_dtim_period * 2;
	} else {
		join_dtim_period_extend = priv->join_dtim_period;
	}
	WARN_ON(wsm_set_beacon_wakeup_period(priv->hw_priv,
	         priv->beacon_int * join_dtim_period_extend >
	         MAX_BEACON_SKIP_TIME_MS ? 1 : join_dtim_period_extend, 
	         0, priv->if_id));
}
#else
	WARN_ON(wsm_set_beacon_wakeup_period(priv->hw_priv,
	         priv->beacon_int * priv->join_dtim_period >
	         MAX_BEACON_SKIP_TIME_MS ? 1 :priv->join_dtim_period, 
	         0, priv->if_id));
#endif
}

u64 cw1200_prepare_multicast(struct ieee80211_hw *hw,
							struct netdev_hw_addr_list *mc_list)
{
	struct cw1200_common *hw_priv = hw->priv;
	struct cw1200_vif *priv = NULL;
	static u8 broadcast_ipv6[ETH_ALEN] = {
		0x33, 0x33, 0x00, 0x00, 0x00, 0x01
	};
	static u8 broadcast_ipv4[ETH_ALEN] = {
		0x01, 0x00, 0x5e, 0x00, 0x00, 0x01
	};
	
	int i= 0;
	cw1200_for_each_vif(hw_priv,priv,i) {
		struct netdev_hw_addr *ha = NULL;
		int count = 0;
		if ((!priv))
			continue;
#ifdef P2P_MULTIVIF
		if (priv->if_id ==XRWL_GENERIC_IF_ID)
			return netdev_hw_addr_list_count(mc_list);
#endif		

		/* Disable multicast filtering */
		priv->has_multicast_subscription = false;
		memset(&priv->multicast_filter, 0x00, sizeof(priv->multicast_filter));
		if (netdev_hw_addr_list_count(mc_list) > WSM_MAX_GRP_ADDRTABLE_ENTRIES)
			return 0;

		/* Enable if requested */
		netdev_hw_addr_list_for_each(ha, mc_list) {
			sta_printk(XRADIO_DBG_MSG, "multicast: %pM\n", ha->addr);
			memcpy(&priv->multicast_filter.macAddress[count], ha->addr, ETH_ALEN);
			if (memcmp(ha->addr, broadcast_ipv4, ETH_ALEN) &&
		    	memcmp(ha->addr, broadcast_ipv6, ETH_ALEN))
				priv->has_multicast_subscription = true;
			count++;
		}
		if (count) {
			priv->multicast_filter.enable = __cpu_to_le32(1);
			priv->multicast_filter.numOfAddresses = __cpu_to_le32(count);
		}
	}
	return netdev_hw_addr_list_count(mc_list);
}

void cw1200_configure_filter(struct ieee80211_hw *hw,
                             unsigned int changed_flags,
                             unsigned int *total_flags,
                             u64 multicast)
{
	struct cw1200_common *hw_priv = hw->priv;
	struct cw1200_vif *priv = NULL;
	int i = 0;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);
	/* delete umac warning */
	if (hw_priv->vif_list[0] == NULL && hw_priv->vif_list[1] == NULL &&
		hw_priv->vif_list[2] == NULL)
		*total_flags &= ~(1<<31);
		
	cw1200_for_each_vif(hw_priv, priv, i) {
		if(NULL == priv)
			continue;
#ifdef P2P_MULTIVIF
		if (priv->if_id == XRWL_GENERIC_IF_ID) {
			*total_flags &= ~(1<<31);
			continue;
		}
#endif

#if 0
		bool listening = !!(*total_flags &
	                     	(FIF_PROMISC_IN_BSS      |
	                      	FIF_OTHER_BSS           |
	                      	FIF_BCN_PRBRESP_PROMISC |
	                      	FIF_PROBE_REQ));
#endif

		*total_flags &= FIF_PROMISC_IN_BSS |
	                	FIF_OTHER_BSS      |
	                	FIF_FCSFAIL        |
	                	FIF_BCN_PRBRESP_PROMISC |
	                	FIF_PROBE_REQ;

		down(&hw_priv->scan.lock);
		mutex_lock(&hw_priv->conf_mutex);

		priv->rx_filter.promiscuous = (*total_flags & FIF_PROMISC_IN_BSS)? 1 : 0;
		priv->rx_filter.bssid = (*total_flags & 
	                         	(FIF_OTHER_BSS | FIF_PROBE_REQ)) ? 1 : 0;
		priv->rx_filter.fcs = (*total_flags & FIF_FCSFAIL) ? 1 : 0;
		priv->bf_control.bcn_count = (*total_flags &
	                              	(FIF_BCN_PRBRESP_PROMISC |
	                               	FIF_PROMISC_IN_BSS |
	                               	FIF_PROBE_REQ)) ? 1 : 0;

		/*add for handle ap FIF_PROBE_REQ message,*/
		priv->rx_filter.promiscuous = 0;
		priv->rx_filter.fcs = 0;
		if(NL80211_IFTYPE_AP == priv->vif->type){
			priv->bf_control.bcn_count = 1;
			priv->rx_filter.bssid = 1; 	
		}else{
			priv->bf_control.bcn_count = 0;
			priv->rx_filter.bssid = 0; 
		}
#if 0
		if (priv->listening ^ listening) {
			priv->listening = listening;
			wsm_lock_tx(hw_priv);
			cw1200_update_listening(priv, listening);
			wsm_unlock_tx(hw_priv);
		}
#endif
		cw1200_update_filtering(priv);
		mutex_unlock(&hw_priv->conf_mutex);
		up(&hw_priv->scan.lock);
	}
}

int cw1200_conf_tx(struct ieee80211_hw *dev, struct ieee80211_vif *vif,
                   u16 queue, const struct ieee80211_tx_queue_params *params)
{
	struct cw1200_common *hw_priv = dev->priv;
	struct cw1200_vif *priv = xrwl_get_vif_from_ieee80211(vif);
	int ret = 0;
	/* To prevent re-applying PM request OID again and again*/
	bool old_uapsdFlags;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	if (WARN_ON(!priv))
		return -EOPNOTSUPP;

#ifdef P2P_MULTIVIF
	if (priv->if_id == XRWL_GENERIC_IF_ID)
		return 0;
#endif

	mutex_lock(&hw_priv->conf_mutex);

	if (queue < dev->queues) {
		old_uapsdFlags = priv->uapsd_info.uapsdFlags;

		WSM_TX_QUEUE_SET(&priv->tx_queue_params, queue, 0, 0, 0);
		ret = wsm_set_tx_queue_params(hw_priv,
		                              &priv->tx_queue_params.params[queue],
		                              queue, priv->if_id);
		if (ret) {
			sta_printk(XRADIO_DBG_ERROR,"%s:wsm_set_tx_queue_params failed!\n", __func__);
			ret = -EINVAL;
			goto out;
		}

		WSM_EDCA_SET(&priv->edca, queue, params->aifs, 
		              params->cw_min, params->cw_max, 
		              params->txop, 0xc8, params->uapsd);
		/* sta role is not support  the uapsd */ 
		if (priv->mode == NL80211_IFTYPE_STATION || 
				priv->mode == NL80211_IFTYPE_P2P_CLIENT)
			priv->edca.params[queue].uapsdEnable = 0;

		ret = wsm_set_edca_params(hw_priv, &priv->edca, priv->if_id);
		if (ret) {
			sta_printk(XRADIO_DBG_ERROR,"%s:wsm_set_edca_params failed!\n", __func__);
			ret = -EINVAL;
			goto out;
		}

		if (priv->mode == NL80211_IFTYPE_STATION) {
			ret = cw1200_set_uapsd_param(priv, &priv->edca);
			if (!ret && priv->setbssparams_done &&
			    (priv->join_status == XRADIO_JOIN_STATUS_STA) &&
			    (old_uapsdFlags != priv->uapsd_info.uapsdFlags))
				cw1200_set_pm(priv, &priv->powersave_mode);
		}
	} else {
		sta_printk(XRADIO_DBG_ERROR,"%s:queue is to large!\n", __func__);
		ret = -EINVAL;
	}

out:
	mutex_unlock(&hw_priv->conf_mutex);
	return ret;
}

int cw1200_get_stats(struct ieee80211_hw *dev,
		     struct ieee80211_low_level_stats *stats)
{
	struct cw1200_common *hw_priv = dev->priv;

	memcpy(stats, &hw_priv->stats, sizeof(*stats));
	return 0;
}

/*
int cw1200_get_tx_stats(struct ieee80211_hw *dev,
			struct ieee80211_tx_queue_stats *stats)
{
	int i;
	struct cw1200_common *priv = dev->priv;

	for (i = 0; i < dev->queues; ++i)
		cw1200_queue_get_stats(&priv->tx_queue[i], &stats[i]);

	return 0;
}
*/

/* for ps debug */
#ifdef CONFIG_XRADIO_DEBUGFS
u8 ps_disable      = 0;
u8 ps_idleperiod   = 0;
u8 ps_changeperiod = 0;
#endif

int cw1200_set_pm(struct cw1200_vif *priv, const struct wsm_set_pm *arg)
{
	struct wsm_set_pm pm = *arg;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

#ifdef CONFIG_XRADIO_DEBUGFS
	if (ps_disable)
		pm.pmMode = WSM_PSM_ACTIVE;
	if (ps_idleperiod) {
		pm.fastPsmIdlePeriod = ps_idleperiod << 1;
		pm.apPsmChangePeriod = ps_changeperiod << 1;
	}
#endif

	if (priv->uapsd_info.uapsdFlags != 0)
		pm.pmMode &= ~WSM_PSM_FAST_PS_FLAG;

	if (memcmp(&pm, &priv->firmware_ps_mode, sizeof(struct wsm_set_pm))) {
		priv->firmware_ps_mode = pm;
		return wsm_set_pm(priv->hw_priv, &pm, priv->if_id);
	} else {
		return 0;
	}
}

int cw1200_set_key(struct ieee80211_hw *dev, enum set_key_cmd cmd,
                   struct ieee80211_vif *vif, struct ieee80211_sta *sta,
                   struct ieee80211_key_conf *key)
{
	int ret = -EOPNOTSUPP;
	struct cw1200_common *hw_priv = dev->priv;
	struct cw1200_vif *priv = xrwl_get_vif_from_ieee80211(vif);
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

#ifdef P2P_MULTIVIF
	WARN_ON(priv->if_id == XRWL_GENERIC_IF_ID);
#endif
	mutex_lock(&hw_priv->conf_mutex);

	if (cmd == SET_KEY) {
		u8 *peer_addr = NULL;
		int pairwise = (key->flags & IEEE80211_KEY_FLAG_PAIRWISE) ? 1 : 0;
		int idx = cw1200_alloc_key(hw_priv);
		struct wsm_add_key *wsm_key = &hw_priv->keys[idx];

		if (idx < 0) {
			sta_printk(XRADIO_DBG_ERROR,"%s:cw1200_alloc_key failed!\n",
			           __func__);
			ret = -EINVAL;
			goto finally;
		}

		BUG_ON(pairwise && !sta);
		if (sta)
			peer_addr = sta->addr;

		key->flags |= IEEE80211_KEY_FLAG_PUT_IV_SPACE;

		priv->cipherType = key->cipher;
		switch (key->cipher) {
		case WLAN_CIPHER_SUITE_WEP40:
		case WLAN_CIPHER_SUITE_WEP104:
			if (key->keylen > 16) {
				cw1200_free_key(hw_priv, idx);
				sta_printk(XRADIO_DBG_ERROR,"%s: keylen too long=%d!\n",
			               __func__, key->keylen);
				ret = -EINVAL;
				goto finally;
			}

			if (pairwise) {
				wsm_key->type = WSM_KEY_TYPE_WEP_PAIRWISE;
				memcpy(wsm_key->wepPairwiseKey.peerAddress, peer_addr, ETH_ALEN);
				memcpy(wsm_key->wepPairwiseKey.keyData, &key->key[0], key->keylen);
				wsm_key->wepPairwiseKey.keyLength = key->keylen;
				sta_printk(XRADIO_DBG_NIY,"%s: WEP_PAIRWISE keylen=%d!\n",
			               __func__, key->keylen);
			} else {
				wsm_key->type = WSM_KEY_TYPE_WEP_DEFAULT;
				memcpy(wsm_key->wepGroupKey.keyData, &key->key[0], key->keylen);
				wsm_key->wepGroupKey.keyLength = key->keylen;
				wsm_key->wepGroupKey.keyId     = key->keyidx;
				sta_printk(XRADIO_DBG_NIY,"%s: WEP_GROUP keylen=%d!\n",
			               __func__, key->keylen);
			}
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			if (pairwise) {
				wsm_key->type = WSM_KEY_TYPE_TKIP_PAIRWISE;
				memcpy(wsm_key->tkipPairwiseKey.peerAddress, peer_addr, ETH_ALEN);
				memcpy(wsm_key->tkipPairwiseKey.tkipKeyData, &key->key[0], 16);
				memcpy(wsm_key->tkipPairwiseKey.txMicKey, &key->key[16], 8);
				memcpy(wsm_key->tkipPairwiseKey.rxMicKey, &key->key[24], 8);
				sta_printk(XRADIO_DBG_NIY,"%s: TKIP_PAIRWISE keylen=%d!\n",
			               __func__, key->keylen);
			} else {
				size_t mic_offset = (priv->mode == NL80211_IFTYPE_AP) ? 16 : 24;
				wsm_key->type = WSM_KEY_TYPE_TKIP_GROUP;
				memcpy(wsm_key->tkipGroupKey.tkipKeyData,&key->key[0],  16);
				memcpy(wsm_key->tkipGroupKey.rxMicKey, &key->key[mic_offset], 8);

				/* TODO: Where can I find TKIP SEQ? */
				memset(wsm_key->tkipGroupKey.rxSeqCounter, 0, 8);
				wsm_key->tkipGroupKey.keyId = key->keyidx;
				sta_printk(XRADIO_DBG_NIY,"%s: TKIP_GROUP keylen=%d!\n",
			               __func__, key->keylen);
			}
			break;
		case WLAN_CIPHER_SUITE_CCMP:
			if (pairwise) {
				wsm_key->type = WSM_KEY_TYPE_AES_PAIRWISE;
				memcpy(wsm_key->aesPairwiseKey.peerAddress, peer_addr, ETH_ALEN);
				memcpy(wsm_key->aesPairwiseKey.aesKeyData, &key->key[0], 16);
				sta_printk(XRADIO_DBG_NIY,"%s: CCMP_PAIRWISE keylen=%d!\n",
			               __func__, key->keylen);
			} else {
				wsm_key->type = WSM_KEY_TYPE_AES_GROUP;
				memcpy(wsm_key->aesGroupKey.aesKeyData, &key->key[0], 16);
				/* TODO: Where can I find AES SEQ? */
				memset(wsm_key->aesGroupKey.rxSeqCounter, 0, 8);
				wsm_key->aesGroupKey.keyId = key->keyidx;
				sta_printk(XRADIO_DBG_NIY,"%s: CCMP_GROUP keylen=%d!\n",
			               __func__, key->keylen);
			}
			break;
		case WLAN_CIPHER_SUITE_SMS4:
			if (pairwise) {
				wsm_key->type = WSM_KEY_TYPE_WAPI_PAIRWISE;
				memcpy(wsm_key->wapiPairwiseKey.peerAddress, peer_addr, ETH_ALEN);
				memcpy(wsm_key->wapiPairwiseKey.wapiKeyData, &key->key[0],  16);
				memcpy(wsm_key->wapiPairwiseKey.micKeyData, &key->key[16], 16);
				wsm_key->wapiPairwiseKey.keyId = key->keyidx;
			} else {
				wsm_key->type = WSM_KEY_TYPE_WAPI_GROUP;
				memcpy(wsm_key->wapiGroupKey.wapiKeyData, &key->key[0],  16);
				memcpy(wsm_key->wapiGroupKey.micKeyData,  &key->key[16], 16);
				wsm_key->wapiGroupKey.keyId = key->keyidx;
			}
			break;
		default:
			pr_warn("Unhandled key type %d\n", key->cipher);
			cw1200_free_key(hw_priv, idx);
			ret = -EOPNOTSUPP;
			goto finally;
		}
		ret = WARN_ON(wsm_add_key(hw_priv, wsm_key, priv->if_id));
		if (!ret)
			key->hw_key_idx = idx;
		else
			cw1200_free_key(hw_priv, idx);

		if (!ret && (pairwise || wsm_key->type == WSM_KEY_TYPE_WEP_DEFAULT) && 
		    (priv->filter4.enable & 0x2))
			cw1200_set_arpreply(dev, vif);
#ifdef IPV6_FILTERING
		if (!ret && (pairwise || wsm_key->type == WSM_KEY_TYPE_WEP_DEFAULT) && 
		    (priv->filter6.enable & 0x2))
			cw1200_set_na(dev, vif);
#endif /*IPV6_FILTERING*/

	} else if (cmd == DISABLE_KEY) {
		struct wsm_remove_key wsm_key = {
			.entryIndex = key->hw_key_idx,
		};

		if (wsm_key.entryIndex > WSM_KEY_MAX_IDX) {
			ret = -EINVAL;
			goto finally;
		}

		cw1200_free_key(hw_priv, wsm_key.entryIndex);
		ret = wsm_remove_key(hw_priv, &wsm_key, priv->if_id);
	} else {
		sta_printk(XRADIO_DBG_ERROR, "%s: Unsupported command", __func__);
	}

finally:
	mutex_unlock(&hw_priv->conf_mutex);
	return ret;
}

void cw1200_wep_key_work(struct work_struct *work)
{
	struct cw1200_vif *priv = container_of(work, struct cw1200_vif , wep_key_work);
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	u8 queueId = cw1200_queue_get_queue_id(hw_priv->pending_frame_id);
	struct cw1200_queue *queue = &hw_priv->tx_queue[queueId];
	__le32 wep_default_key_id = __cpu_to_le32(priv->wep_default_key_id);
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	BUG_ON(queueId >= 4);

	sta_printk(XRADIO_DBG_MSG, "Setting default WEP key: %d\n", 
	           priv->wep_default_key_id);

	wsm_flush_tx(hw_priv);
	WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DOT11_WEP_DEFAULT_KEY_ID,
	                       &wep_default_key_id, sizeof(wep_default_key_id),
	                       priv->if_id));

#ifdef CONFIG_XRADIO_TESTMODE
	cw1200_queue_requeue(hw_priv, queue, hw_priv->pending_frame_id, true);
#else
	cw1200_queue_requeue(queue, hw_priv->pending_frame_id, true);
#endif
	wsm_unlock_tx(hw_priv);
}

int cw1200_set_rts_threshold(struct ieee80211_hw *hw, u32 value)
{
	struct cw1200_common *hw_priv = hw->priv;
	int ret = 0;
	__le32 val32;
	struct cw1200_vif *priv = NULL;
	int i =0;
	int if_id;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	cw1200_for_each_vif(hw_priv,priv,i) {
		if (!priv)
			continue;
		if_id = priv->if_id;
#ifdef P2P_MULTIVIF
		WARN_ON(priv->if_id == XRWL_GENERIC_IF_ID);
#endif

		if (value != (u32) -1)
			val32 = __cpu_to_le32(value);
		else
			val32 = 0; /* disabled */

		/* mutex_lock(&priv->conf_mutex); */
		ret = WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DOT11_RTS_THRESHOLD,
			&val32, sizeof(val32), if_id));
		/* mutex_unlock(&priv->conf_mutex); */
	}
	return ret;
}

/* TODO: COMBO: Flush only a particular interface specific parts */
int __cw1200_flush(struct cw1200_common *hw_priv, bool drop, int if_id)
{
	int i, ret;
	struct cw1200_vif *priv =
		__xrwl_hwpriv_to_vifpriv(hw_priv, if_id);
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	for (;;) {
		/* TODO: correct flush handling is required when dev_stop.
		 * Temporary workaround: 2s
		 */
		if (drop) {
			for (i = 0; i < 4; ++i)
				cw1200_queue_clear(&hw_priv->tx_queue[i],if_id);
		} else if(!hw_priv->bh_error){
			ret = wait_event_timeout(
				hw_priv->tx_queue_stats.wait_link_id_empty,
				cw1200_queue_stats_is_empty(&hw_priv->tx_queue_stats, -1, if_id),
				2 * HZ);
		} else { //add by yangfh, don't wait when bh error
			sta_printk(XRADIO_DBG_ERROR, " %s:bh_error occur.\n", __func__);
			ret = -1;
			break;
		}

		if (!drop && unlikely(ret <= 0)) {
			sta_printk(XRADIO_DBG_ERROR, " %s: timeout...\n", __func__);
			ret = -ETIMEDOUT;
			break;
		} else {
			ret = 0;
		}

		wsm_vif_lock_tx(priv);
		if (unlikely(!cw1200_queue_stats_is_empty(&hw_priv->tx_queue_stats,
			          -1, if_id))) {
			/* Highly unlekely: WSM requeued frames. */
			wsm_unlock_tx(hw_priv);
			continue;
		}
		wsm_unlock_tx(hw_priv);
		break;
	}
	return ret;
}

void cw1200_flush(struct ieee80211_hw *hw, bool drop)
{
	struct cw1200_vif *priv = NULL;
	struct cw1200_common *hw_priv = hw->priv;
	int i = 0;
	//struct cw1200_vif *priv = xrwl_get_vif_from_ieee80211(vif);

	/*TODO:COMBO: reenable this part of code when flush callback
	 * is implemented per vif */
	/*switch (hw_priv->mode) {
	case NL80211_IFTYPE_MONITOR:
		drop = true;
		break;
	case NL80211_IFTYPE_AP:
		if (!hw_priv->enable_beacon)
			drop = true;
		break;
	}*/

	//if (!(hw_priv->if_id_slot & BIT(priv->if_id)))
	//	return;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);
	cw1200_for_each_vif(hw_priv, priv, i) {
		if(NULL == priv)
			continue;
		if ((hw_priv->if_id_slot & BIT(priv->if_id)))
			__cw1200_flush(hw_priv, drop, priv->if_id);
	}
	return;
}

int cw1200_remain_on_channel(struct ieee80211_hw *hw,
			     struct ieee80211_channel *chan,
			     enum nl80211_channel_type channel_type,
			     int duration)
{
	int ret = 0;
	struct cw1200_common *hw_priv = hw->priv;
	struct cw1200_vif *priv = NULL;
	int i = 0;
	int if_id;
#ifdef	TES_P2P_0002_ROC_RESTART
	struct timeval TES_P2P_0002_tmval;
#endif
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

#ifdef	TES_P2P_0002_ROC_RESTART
	do_gettimeofday(&TES_P2P_0002_tmval);
	TES_P2P_0002_roc_dur  = (s32)duration;
	TES_P2P_0002_roc_sec  = (s32)TES_P2P_0002_tmval.tv_sec;
	TES_P2P_0002_roc_usec = (s32)TES_P2P_0002_tmval.tv_usec;
#endif

	down(&hw_priv->scan.lock);
	mutex_lock(&hw_priv->conf_mutex);
	cw1200_for_each_vif(hw_priv, priv, i) {
		if(NULL == priv)
			continue;
		if_id = priv->if_id;

#ifdef ROC_DEBUG
		sta_printk(XRADIO_DBG_WARN, "ROC IN %d ch %d\n", 
		           priv->if_id, chan->hw_value);
#endif
		/* default only p2p interface if_id can remain on */
		if((priv->if_id == 0) || (priv->if_id == 1))
			continue;
		hw_priv->roc_if_id = priv->if_id;
		ret = WARN_ON(__cw1200_flush(hw_priv, false, if_id));
		cw1200_enable_listening(priv, chan);

		if (!ret) {
			atomic_set(&hw_priv->remain_on_channel, 1);
			queue_delayed_work(hw_priv->workqueue, &hw_priv->rem_chan_timeout,
			                   duration * HZ / 1000);
			priv->join_status = XRADIO_JOIN_STATUS_MONITOR;
			ieee80211_ready_on_channel(hw);
		} else {
			hw_priv->roc_if_id = -1;
			up(&hw_priv->scan.lock);
		}

#ifdef ROC_DEBUG
		sta_printk(XRADIO_DBG_WARN, "ROC OUT %d\n", priv->if_id);
#endif
			}
		/* set the channel to supplied ieee80211_channel pointer, if it
	        is not set. This is to remove the crash while sending a probe res
	        in listen state. Later channel will updated on
	        IEEE80211_CONF_CHANGE_CHANNEL event*/
		if(!hw_priv->channel) {
			hw_priv->channel = chan;
		}
		mutex_unlock(&hw_priv->conf_mutex);
	return ret;
}

int cw1200_cancel_remain_on_channel(struct ieee80211_hw *hw)
{
	struct cw1200_common *hw_priv = hw->priv;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	sta_printk(XRADIO_DBG_NIY, "Cancel remain on channel\n");
#ifdef TES_P2P_0002_ROC_RESTART
	if (TES_P2P_0002_state == TES_P2P_0002_STATE_GET_PKTID) {
		TES_P2P_0002_state = TES_P2P_0002_STATE_IDLE;
		sta_printk(XRADIO_DBG_WARN, "[ROC_RESTART_STATE_IDLE][Cancel ROC]\n");
	}
#endif

	if (atomic_read(&hw_priv->remain_on_channel))
		cancel_delayed_work_sync(&hw_priv->rem_chan_timeout);

	if (atomic_read(&hw_priv->remain_on_channel))
		cw1200_rem_chan_timeout(&hw_priv->rem_chan_timeout.work);

	return 0;
}

/* ******************************************************************** */
/* WSM callbacks							*/

void cw1200_channel_switch_cb(struct cw1200_common *hw_priv)
{
	wsm_unlock_tx(hw_priv);
}

void cw1200_free_event_queue(struct cw1200_common *hw_priv)
{
	LIST_HEAD(list);
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	spin_lock(&hw_priv->event_queue_lock);
	list_splice_init(&hw_priv->event_queue, &list);
	spin_unlock(&hw_priv->event_queue_lock);

	__cw1200_free_event_queue(&list);
}

void cw1200_event_handler(struct work_struct *work)
{
	struct cw1200_common *hw_priv =
		container_of(work, struct cw1200_common, event_handler);
	struct cw1200_vif *priv;
	struct cw1200_wsm_event *event;
	LIST_HEAD(list);
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	spin_lock(&hw_priv->event_queue_lock);
	list_splice_init(&hw_priv->event_queue, &list);
	spin_unlock(&hw_priv->event_queue_lock);

	mutex_lock(&hw_priv->conf_mutex);
	list_for_each_entry(event, &list, link) {
		priv = __xrwl_hwpriv_to_vifpriv(hw_priv, event->if_id);
		if (!priv) {
			sta_printk(XRADIO_DBG_WARN, "[CQM] Event for non existing "
			           "interface, ignoring.\n");
			continue;
		}
		switch (event->evt.eventId) {
			case WSM_EVENT_ERROR:
				/* I even don't know what is it about.. */
				//STUB();
				break;
			case WSM_EVENT_BSS_LOST:
			{
				spin_lock(&priv->bss_loss_lock);
				if (priv->bss_loss_status > XRADIO_BSS_LOSS_NONE) {
					spin_unlock(&priv->bss_loss_lock);
					break;
				}
				priv->bss_loss_status = XRADIO_BSS_LOSS_CHECKING;
				spin_unlock(&priv->bss_loss_lock);
				sta_printk(XRADIO_DBG_WARN, "[CQM] BSS lost, Beacon miss=%d, event=%x.\n",
				           (event->evt.eventData>>8)&0xff, event->evt.eventData&0xff);

				cancel_delayed_work_sync(&priv->bss_loss_work);
				cancel_delayed_work_sync(&priv->connection_loss_work);
				if (!down_trylock(&hw_priv->scan.lock)) {
					up(&hw_priv->scan.lock);
					priv->delayed_link_loss = 0;
					queue_delayed_work(hw_priv->workqueue,
							&priv->bss_loss_work, HZ/10); //100ms
				} else {
					/* Scan is in progress. Delay reporting. */
					/* Scan complete will trigger bss_loss_work */
					priv->delayed_link_loss = 1;
					/* Also we're starting watchdog. */
					queue_delayed_work(hw_priv->workqueue,
							&priv->bss_loss_work, 10 * HZ);
				}
				break;
			}
			case WSM_EVENT_BSS_REGAINED:
			{
				sta_printk(XRADIO_DBG_WARN, "[CQM] BSS regained.\n");
				priv->delayed_link_loss = 0;
				spin_lock(&priv->bss_loss_lock);
				priv->bss_loss_status = XRADIO_BSS_LOSS_NONE;
				spin_unlock(&priv->bss_loss_lock);
				cancel_delayed_work_sync(&priv->bss_loss_work);
				cancel_delayed_work_sync(&priv->connection_loss_work);
				break;
			}
			case WSM_EVENT_RADAR_DETECTED:
				//STUB();
				break;
			case WSM_EVENT_RCPI_RSSI:
			{
				/* RSSI: signed Q8.0, RCPI: unsigned Q7.1
				 * RSSI = RCPI / 2 - 110 */
				int rcpiRssi = (int)(event->evt.eventData & 0xFF);
				int cqm_evt;
				if (priv->cqm_use_rssi)
					rcpiRssi = (s8)rcpiRssi;
				else
					rcpiRssi =  rcpiRssi / 2 - 110;

				cqm_evt = (rcpiRssi <= priv->cqm_rssi_thold) ?
					NL80211_CQM_RSSI_THRESHOLD_EVENT_LOW :
					NL80211_CQM_RSSI_THRESHOLD_EVENT_HIGH;
				sta_printk(XRADIO_DBG_NIY, "[CQM] RSSI event: %d", rcpiRssi);
				ieee80211_cqm_rssi_notify(priv->vif, cqm_evt,
									GFP_KERNEL);
				break;
			}
			case WSM_EVENT_BT_INACTIVE:
				//STUB();
				break;
			case WSM_EVENT_BT_ACTIVE:
				//STUB();
				break;
			case WSM_EVENT_INACTIVITY:
			{
				int link_id = ffs((u32)(event->evt.eventData)) - 1;
				struct sk_buff *skb;
			        struct ieee80211_mgmt *deauth;
			        struct cw1200_link_entry *entry = NULL;

				sta_printk(XRADIO_DBG_WARN, "Inactivity Event Recieved for "
						"link_id %d\n", link_id);
				skb = xr_alloc_skb(sizeof(struct ieee80211_mgmt) + 64);
				if (!skb)
					break;
				skb_reserve(skb, 64);
				xrwl_unmap_link(priv, link_id);
				deauth = (struct ieee80211_mgmt *)skb_put(skb, sizeof(struct ieee80211_mgmt));
	                        WARN_ON(!deauth);
	                        entry = &priv->link_id_db[link_id - 1];
	                        deauth->duration = 0;
	                        memcpy(deauth->da, priv->vif->addr, ETH_ALEN);
	                        memcpy(deauth->sa, entry->mac/*priv->link_id_db[i].mac*/, ETH_ALEN);
	                        memcpy(deauth->bssid, priv->vif->addr, ETH_ALEN);
				deauth->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
	                                                                    IEEE80211_STYPE_DEAUTH |
	                                                                    IEEE80211_FCTL_TODS);
	                        deauth->u.deauth.reason_code = WLAN_REASON_DEAUTH_LEAVING;
	                        deauth->seq_ctrl = 0;
	                        ieee80211_rx_irqsafe(priv->hw, skb);
				sta_printk(XRADIO_DBG_WARN, " Inactivity Deauth Frame sent for MAC SA %pM \t and DA %pM\n", deauth->sa, deauth->da);
				queue_work(priv->hw_priv->workqueue, &priv->set_tim_work);
				break;
			}
		case WSM_EVENT_PS_MODE_ERROR:
			{
				if (!priv->uapsd_info.uapsdFlags &&
					(priv->user_pm_mode != WSM_PSM_PS))
				{
					struct wsm_set_pm pm = priv->powersave_mode;
					int ret = 0;

					priv->powersave_mode.pmMode = WSM_PSM_ACTIVE;
					ret = cw1200_set_pm (priv, &priv->powersave_mode);
					if(ret)
						priv->powersave_mode = pm;
				}
                                break;
			}
		}
	}
	mutex_unlock(&hw_priv->conf_mutex);
	__cw1200_free_event_queue(&list);
}

void cw1200_bss_loss_work(struct work_struct *work)
{
	struct cw1200_vif *priv =
		container_of(work, struct cw1200_vif, bss_loss_work.work);
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	int timeout; /* in beacons */
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	timeout = priv->cqm_link_loss_count - priv->cqm_beacon_loss_count;
	/* Skip the confimration procedure in P2P case */
	if (priv->vif->p2p)
		goto report;

	spin_lock(&priv->bss_loss_lock);
	if (priv->bss_loss_status == XRADIO_BSS_LOSS_CONFIRMING) {
		//do loss report next time.
		priv->bss_loss_status = XRADIO_BSS_LOSS_CONFIRMED;
		spin_unlock(&priv->bss_loss_lock);
		//wait for more 1s to loss confirm.
		queue_delayed_work(hw_priv->workqueue, &priv->bss_loss_work, 1 * HZ);
		return;
	} else if (priv->bss_loss_status == XRADIO_BSS_LOSS_NONE) {
		spin_unlock(&priv->bss_loss_lock);
		//link is alive.
		cancel_delayed_work_sync(&priv->connection_loss_work);
		return; 
	} else if (priv->bss_loss_status == XRADIO_BSS_LOSS_CHECKING) {
		/* it mean no confirming packets, just report loss. */
	}
	spin_unlock(&priv->bss_loss_lock);

report:
	if (priv->cqm_beacon_loss_count) {
		sta_printk(XRADIO_DBG_WARN, "[CQM] Beacon loss.\n");
		if (timeout <= 0)
			timeout = 0;
		// Extensions
		//ieee80211_cqm_beacon_miss_notify(priv->vif, GFP_KERNEL);
	} else {
		timeout = 0;
	}

	cancel_delayed_work_sync(&priv->connection_loss_work);
	queue_delayed_work(hw_priv->workqueue, &priv->connection_loss_work,
	                   timeout * HZ / 10);

	spin_lock(&priv->bss_loss_lock);
	priv->bss_loss_status = XRADIO_BSS_LOSS_NONE;
	spin_unlock(&priv->bss_loss_lock);
}

void cw1200_connection_loss_work(struct work_struct *work)
{
	struct cw1200_vif *priv =
	  container_of(work, struct cw1200_vif, connection_loss_work.work);
	sta_printk(XRADIO_DBG_ERROR, "[CQM] if%d Reporting connection loss.\n", 
	           priv->if_id);
	ieee80211_connection_loss(priv->vif);
}

void cw1200_tx_failure_work(struct work_struct *work)
{
	//struct cw1200_vif *priv =
	//	container_of(work, struct cw1200_vif, tx_failure_work);
	sta_printk(XRADIO_DBG_WARN, "[CQM] Reporting TX failure.\n");
	//ieee80211_cqm_tx_fail_notify(priv->vif, GFP_KERNEL);
}

#ifdef CONFIG_XRADIO_TESTMODE
/**
 * cw1200_device_power_calc- Device power calculation
 * from values fetch from SDD File.
 *
 * @priv: the private structure
 * @Max_output_power: Power fetch from SDD
 * @fe_cor: front-end loss correction
 * @band: Either 2GHz or 5GHz
 *
 */
void cw1200_device_power_calc(struct cw1200_common *hw_priv,
		s16 max_output_power, s16 fe_cor, u32 band)
{
	s16 power_calc;

	power_calc = max_output_power - fe_cor;
	if ((power_calc % 16) != 0)
		power_calc += 16;

	hw_priv->txPowerRange[band].max_power_level = power_calc/16;
	/*
	 * 12dBm is control range supported by firmware.
	 * This means absolute min power is
	 * max_power_level - 12.
	 */
	hw_priv->txPowerRange[band].min_power_level =
		hw_priv->txPowerRange[band].max_power_level - 12;
	hw_priv->txPowerRange[band].stepping = 1;

}
#endif
/* ******************************************************************** */
#ifdef CONFIG_XRADIO_TESTMODE
#define SDD_MAX_OUTPUT_POWER_2G4_ELT_ID 0xE3
#define SDD_MAX_OUTPUT_POWER_5G_ELT_ID  0xE4
#define SDD_FE_COR_2G4_ELT_ID   0x30
#define SDD_FE_COR_5G_ELT_ID    0x31
#define MIN(x, y, z) (x < y ? (x < z ? x : z) : (y < z ? y : z))
static int cw1200_test_pwrlevel(struct cw1200_common *hw_priv)
{
	int ret = -1;
	int parsedLength = 0;
	struct cw1200_sdd *pElement = (struct cw1200_sdd *)hw_priv->sdd->data;

	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	parsedLength += (FIELD_OFFSET(struct cw1200_sdd, data) + pElement->length);
	pElement = FIND_NEXT_ELT(pElement);

	while (parsedLength <= hw_priv->sdd->size) {
		switch (pElement->id) {
		case SDD_MAX_OUTPUT_POWER_2G4_ELT_ID:
			max_output_power_2G = *((s16 *)pElement->data);
			break;
		case SDD_FE_COR_2G4_ELT_ID:
			fe_cor_2G = *((s16 *)pElement->data);
			break;
		case SDD_MAX_OUTPUT_POWER_5G_ELT_ID:
			max_output_power_5G = *((s16 *)(pElement->data + 4));
			break;
		case SDD_FE_COR_5G_ELT_ID:
			fe_cor_5G = MIN(*((s16 *)pElement->data), 
			                *((s16 *)(pElement->data + 2)), 
			                *((s16 *)(pElement->data + 4)));
			fe_cor_5G = MIN(fe_cor_5G, 
			                *((s16 *)(pElement->data + 6)),
			                *((s16 *)(pElement->data + 8)));
			break;
		default:
			break;
		}
		parsedLength += (FIELD_OFFSET(struct cw1200_sdd, data) + pElement->length);
		pElement = FIND_NEXT_ELT(pElement);
	}

	/* Max/Min Power Calculation for 2.4G */
	cw1200_device_power_calc(hw_priv, max_output_power_2G, fe_cor_2G, IEEE80211_BAND_2GHZ);
	/* Max/Min Power Calculation for 5G */
	cw1200_device_power_calc(hw_priv, max_output_power_5G, fe_cor_5G, IEEE80211_BAND_5GHZ);
	for (i = 0; i < 2; ++i) {
		sta_printk(XRADIO_DBG_MSG, "Power Values Read from SDD %s:"
			"min_power_level[%d]: %d max_power_level[%d]:"
			"%d stepping[%d]: %d\n", __func__, i,
			hw_priv->txPowerRange[i].min_power_level, i,
			hw_priv->txPowerRange[i].max_power_level, i,
			hw_priv->txPowerRange[i].stepping);
	}
	return 0;
}
#endif

/* Internal API								*/
int cw1200_setup_mac(struct cw1200_common *hw_priv)
{
	int ret = 0, if_id;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	if (hw_priv->sdd) {
		struct wsm_configuration cfg = {
			.dot11StationId = &hw_priv->mac_addr[0],
			.dpdData      = hw_priv->sdd->data,
			.dpdData_size = hw_priv->sdd->size,
		};
		for (if_id = 0; if_id < xrwl_get_nr_hw_ifaces(hw_priv);
		     if_id++) {
			/* Set low-power mode. */
			ret |= WARN_ON(wsm_configuration(hw_priv, &cfg,
				       if_id));
		}
#ifdef CONFIG_XRADIO_TESTMODE
		/* Parse SDD file for power level test */
		cw1200_test_pwrlevel(hw_priv);
#endif
		/* wsm_configuration only once, so release it */
		release_firmware(hw_priv->sdd);
		hw_priv->sdd = NULL;
	}

	/* BUG:TX output power is not set untill config_cw1200 is called.
	 * This would lead to 0 power set in fw and would effect scan & p2p-find
	 * Setting to default value here from sdd which would be overwritten when
	 * we make connection to AP.This value is used only during scan & p2p-ops
	 * untill AP connection is made */
	/*BUG:TX output power: Hardcoding to 20dbm if CCX is not enabled*/
	/*TODO: This might change*/
	if (!hw_priv->output_power)
		hw_priv->output_power=20;
	sta_printk(XRADIO_DBG_MSG, "%s output power %d\n",__func__,hw_priv->output_power);

	return ret;
}

void cw1200_pending_offchanneltx_work(struct work_struct *work)
{
	struct cw1200_vif *priv =
	container_of(work, struct cw1200_vif, pending_offchanneltx_work.work);
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	mutex_lock(&hw_priv->conf_mutex);
#ifdef ROC_DEBUG
	sta_printk(XRADIO_DBG_WARN, "OFFCHAN PEND IN\n");
#endif
	cw1200_disable_listening(priv);
	hw_priv->roc_if_id = -1;
#ifdef ROC_DEBUG
	sta_printk(XRADIO_DBG_WARN, "OFFCHAN PEND OUT\n");
#endif
	up(&hw_priv->scan.lock);
	mutex_unlock(&hw_priv->conf_mutex);
}

void cw1200_offchannel_work(struct work_struct *work)
{
	struct cw1200_vif *priv =
		container_of(work, struct cw1200_vif, offchannel_work);
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	u8 queueId = cw1200_queue_get_queue_id(hw_priv->pending_frame_id);
	struct cw1200_queue *queue = &hw_priv->tx_queue[queueId];
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	BUG_ON(queueId >= 4);
	BUG_ON(!hw_priv->channel);

	if (unlikely(down_trylock(&hw_priv->scan.lock))) {
		int ret;
		sta_printk(XRADIO_DBG_ERROR, "cw1200_offchannel_work***** drop frame\n");
#ifdef CONFIG_XRADIO_TESTMODE
		cw1200_queue_remove(hw_priv, queue,
				hw_priv->pending_frame_id);
#else
		ret = cw1200_queue_remove(queue, hw_priv->pending_frame_id);
#endif
		if (ret)
			sta_printk(XRADIO_DBG_ERROR, "cw1200_offchannel_work: "
				       "queue_remove failed %d\n", ret);
		wsm_unlock_tx(hw_priv);
		//workaround by yangfh
		LOG_FILE(1, "cw1200_offchannel_work error\n");
		up(&hw_priv->scan.lock);
		ieee80211_connection_loss(priv->vif);
		sta_printk(XRADIO_DBG_ERROR,"lock %d\n", hw_priv->scan.lock.count);
		
		return;
	}
	mutex_lock(&hw_priv->conf_mutex);
#ifdef ROC_DEBUG
	sta_printk(XRADIO_DBG_WARN, "OFFCHAN WORK IN %d\n", priv->if_id);
#endif
	hw_priv->roc_if_id = priv->if_id;
	if (likely(!priv->join_status)) {
		wsm_vif_flush_tx(priv);
		cw1200_enable_listening(priv, hw_priv->channel);
		/* cw1200_update_filtering(priv); */
	}
	if (unlikely(!priv->join_status))
#ifdef CONFIG_XRADIO_TESTMODE
		cw1200_queue_remove(hw_priv, queue,
				hw_priv->pending_frame_id);
#else
		cw1200_queue_remove(queue, hw_priv->pending_frame_id);
#endif /*CONFIG_XRADIO_TESTMODE*/
	else
#ifdef CONFIG_XRADIO_TESTMODE
		cw1200_queue_requeue(hw_priv, queue,
			hw_priv->pending_frame_id, false);
#else
		cw1200_queue_requeue(queue, hw_priv->pending_frame_id, false);
#endif

	queue_delayed_work(hw_priv->workqueue,
			&priv->pending_offchanneltx_work, 204 * HZ/1000);
#ifdef ROC_DEBUG
	sta_printk(XRADIO_DBG_WARN, "OFFCHAN WORK OUT %d\n", priv->if_id);
#endif
	mutex_unlock(&hw_priv->conf_mutex);
	wsm_unlock_tx(hw_priv);
}

void cw1200_join_work(struct work_struct *work)
{
	struct cw1200_vif *priv =
		container_of(work, struct cw1200_vif, join_work);
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	u8 queueId = cw1200_queue_get_queue_id(hw_priv->pending_frame_id);
	struct cw1200_queue *queue = &hw_priv->tx_queue[queueId];
	const struct cw1200_txpriv *txpriv = NULL;
	struct sk_buff *skb = NULL;
	const struct wsm_tx *wsm;
	const struct ieee80211_hdr *frame;
	const u8 *bssid;
	struct cfg80211_bss *bss;
	const u8 *ssidie;
	const u8 *dtimie;
	const struct ieee80211_tim_ie *tim = NULL;
	struct wsm_protected_mgmt_policy mgmt_policy;
	struct wsm_operational_mode mode = {
		.power_mode = wsm_power_mode_quiescent,
		.disableMoreFlagUsage = true,
	};
	//struct wsm_reset reset = {
	//	.reset_statistics = true,
	//};
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);


	BUG_ON(queueId >= 4);
	if (cw1200_queue_get_skb(queue,	hw_priv->pending_frame_id,
			&skb, &txpriv)) {
		wsm_unlock_tx(hw_priv);
		return;
	}
	wsm = (struct wsm_tx *)&skb->data[0];
	frame = (struct ieee80211_hdr *)&skb->data[txpriv->offset];
	bssid = &frame->addr1[0]; /* AP SSID in a 802.11 frame */

	BUG_ON(!wsm);
	BUG_ON(!hw_priv->channel);

	if (unlikely(priv->join_status)) {
		sta_printk(XRADIO_DBG_WARN, "%s, pre join_status=%d.\n",
		          __func__, priv->join_status);
		wsm_lock_tx(hw_priv);
		cw1200_unjoin_work(&priv->unjoin_work);
	}

	cancel_delayed_work_sync(&priv->join_timeout);

	bss = cfg80211_get_bss(hw_priv->hw->wiphy, hw_priv->channel,
			bssid, NULL, 0, 0, 0);
	if (!bss) {
#ifdef CONFIG_XRADIO_TESTMODE
		cw1200_queue_remove(hw_priv, queue, hw_priv->pending_frame_id);
#else
		cw1200_queue_remove(queue, hw_priv->pending_frame_id);
#endif /*CONFIG_XRADIO_TESTMODE*/
		wsm_unlock_tx(hw_priv);
		return;
	}
	ssidie = cfg80211_find_ie(WLAN_EID_SSID,
		bss->information_elements,
		bss->len_information_elements);
	dtimie = cfg80211_find_ie(WLAN_EID_TIM,
		bss->information_elements,
		bss->len_information_elements);
	if (dtimie)
		tim = (struct ieee80211_tim_ie *)&dtimie[2];

	mutex_lock(&hw_priv->conf_mutex);
	{
		struct wsm_join join = {
			.mode = (bss->capability & WLAN_CAPABILITY_IBSS) ?
				WSM_JOIN_MODE_IBSS : WSM_JOIN_MODE_BSS,
			/* default changed to LONG, by HuangLu, fix 2/5.5/11m tx fail*/
			.preambleType = WSM_JOIN_PREAMBLE_LONG,
			.probeForJoin = 1,
			/* dtimPeriod will be updated after association */
			.dtimPeriod = 1,
			.beaconInterval = bss->beacon_interval,
		};

		if (priv->if_id)
			join.flags |= WSM_FLAG_MAC_INSTANCE_1;
		else
			join.flags &= ~WSM_FLAG_MAC_INSTANCE_1;

		/* BT Coex related changes */
		if (hw_priv->is_BT_Present) {
			if (((hw_priv->conf_listen_interval * 100) %
					bss->beacon_interval) == 0)
				priv->listen_interval =
					((hw_priv->conf_listen_interval * 100) /
					bss->beacon_interval);
			else
				priv->listen_interval =
					((hw_priv->conf_listen_interval * 100) /
					bss->beacon_interval + 1);
		}

		if (tim && tim->dtim_period > 1) {
			join.dtimPeriod = tim->dtim_period;
			priv->join_dtim_period = tim->dtim_period;
		}
		priv->beacon_int = bss->beacon_interval;
		sta_printk(XRADIO_DBG_NIY, "Join DTIM: %d, interval: %d\n",
				join.dtimPeriod, priv->beacon_int);

		hw_priv->is_go_thru_go_neg = false;
		join.channelNumber = hw_priv->channel->hw_value;

		/* basicRateSet will be updated after association.
		Currently these values are hardcoded */
		if (hw_priv->channel->band == IEEE80211_BAND_5GHZ) {
			join.band = WSM_PHY_BAND_5G;
			join.basicRateSet = 64; /*6 mbps*/
		}else{
			join.band = WSM_PHY_BAND_2_4G;
			join.basicRateSet = 7; /*1, 2, 5.5 mbps*/
		}
		memcpy(&join.bssid[0], bssid, sizeof(join.bssid));
		memcpy(&priv->join_bssid[0], bssid, sizeof(priv->join_bssid));

		if (ssidie) {
			join.ssidLength = ssidie[1];
			if (WARN_ON(join.ssidLength > sizeof(join.ssid)))
				join.ssidLength = sizeof(join.ssid);
			memcpy(&join.ssid[0], &ssidie[2], join.ssidLength);
			if(strstr(&join.ssid[0],"5.1.4"))
				msleep(200);
#ifdef ROAM_OFFLOAD
			if((priv->vif->type == NL80211_IFTYPE_STATION)) {
				priv->ssid_length = join.ssidLength;
				memcpy(priv->ssid, &join.ssid[0], priv->ssid_length);
			}
#endif /*ROAM_OFFLOAD*/
		}

		if (priv->vif->p2p) {
			join.flags |= WSM_JOIN_FLAGS_P2P_GO;
#ifdef P2P_MULTIVIF
			join.flags |= (1 << 6);
#endif
			join.basicRateSet =
				cw1200_rate_mask_to_wsm(hw_priv, 0xFF0);
		}

		wsm_flush_tx(hw_priv);

		/* Queue unjoin if not associated in 3 sec. */
		queue_delayed_work(hw_priv->workqueue,
			&priv->join_timeout, 3 * HZ);
		/*Stay Awake for Join Timeout*/
		cw1200_pm_stay_awake(&hw_priv->pm_state, 3 * HZ);

		cw1200_disable_listening(priv);

		//WARN_ON(wsm_reset(hw_priv, &reset, priv->if_id));
		WARN_ON(wsm_set_operational_mode(hw_priv, &mode, priv->if_id));
		WARN_ON(wsm_set_block_ack_policy(hw_priv,
			0, hw_priv->ba_tid_mask, priv->if_id));
		spin_lock_bh(&hw_priv->ba_lock);
		hw_priv->ba_ena = false;
		hw_priv->ba_cnt = 0;
		hw_priv->ba_acc = 0;
		hw_priv->ba_hist = 0;
		hw_priv->ba_cnt_rx = 0;
		hw_priv->ba_acc_rx = 0;
		spin_unlock_bh(&hw_priv->ba_lock);

		mgmt_policy.protectedMgmtEnable = 0;
		mgmt_policy.unprotectedMgmtFramesAllowed = 1;
		mgmt_policy.encryptionForAuthFrame = 1;
		wsm_set_protected_mgmt_policy(hw_priv, &mgmt_policy, priv->if_id);

		if (wsm_join(hw_priv, &join, priv->if_id)) {
			memset(&priv->join_bssid[0],
				0, sizeof(priv->join_bssid));
#ifdef CONFIG_XRADIO_TESTMODE
			cw1200_queue_remove(hw_priv, queue,
						hw_priv->pending_frame_id);
#else
			cw1200_queue_remove(queue, hw_priv->pending_frame_id);
#endif /*CONFIG_XRADIO_TESTMODE*/
			cancel_delayed_work_sync(&priv->join_timeout);
		} else {
			/* Upload keys */
#ifdef CONFIG_XRADIO_TESTMODE
			cw1200_queue_requeue(hw_priv, queue,
				hw_priv->pending_frame_id, true);
#else
			cw1200_queue_requeue(queue, hw_priv->pending_frame_id,
						true);
#endif
			priv->join_status = XRADIO_JOIN_STATUS_STA;

			/* Due to beacon filtering it is possible that the
			 * AP's beacon is not known for the mac80211 stack.
			 * Disable filtering temporary to make sure the stack
			 * receives at least one */
			priv->disable_beacon_filter = true;

		}
		cw1200_update_filtering(priv);
	}
	mutex_unlock(&hw_priv->conf_mutex);
	cfg80211_put_bss(bss);
	wsm_unlock_tx(hw_priv);
}

void cw1200_join_timeout(struct work_struct *work)
{
	struct cw1200_vif *priv =
		container_of(work, struct cw1200_vif, join_timeout.work);
	sta_printk(XRADIO_DBG_WARN, "[WSM] Issue unjoin command (TMO).\n");
	wsm_lock_tx(priv->hw_priv);
	cw1200_unjoin_work(&priv->unjoin_work);
}

void cw1200_unjoin_work(struct work_struct *work)
{
	struct cw1200_vif *priv =
		container_of(work, struct cw1200_vif, unjoin_work);
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	
	struct wsm_reset reset = {
		.reset_statistics = true,
	};
	bool is_htcapie = false;
	int i;
	struct cw1200_vif *tmp_priv;
	struct wsm_operational_mode mode = {
		.power_mode = wsm_power_mode_quiescent,
		.disableMoreFlagUsage = true,
	};
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	//add by yangfh.
	hw_priv->connet_time[priv->if_id] = 0;
#ifdef AP_HT_COMPAT_FIX
	priv->ht_compat_det &= ~1;
	priv->ht_compat_cnt = 0;
#endif

	del_timer_sync(&hw_priv->ba_timer);
	mutex_lock(&hw_priv->conf_mutex);
	if (unlikely(atomic_read(&hw_priv->scan.in_progress))) {
		if (atomic_xchg(&priv->delayed_unjoin, 1)) {
			sta_printk(XRADIO_DBG_NIY, 
				"%s: Delayed unjoin "
				"is already scheduled.\n",
				__func__);
			wsm_unlock_tx(hw_priv);
		}
		mutex_unlock(&hw_priv->conf_mutex);
		return;
	}

	if (priv->join_status &&
			priv->join_status > XRADIO_JOIN_STATUS_STA) {
		sta_printk(XRADIO_DBG_ERROR, 
				"%s: Unexpected: join status: %d\n",
				__func__, priv->join_status);
		BUG_ON(1);
	}
	if (priv->join_status) {
		cancel_work_sync(&priv->update_filtering_work);
		cancel_work_sync(&priv->set_beacon_wakeup_period_work);
		memset(&priv->join_bssid[0], 0, sizeof(priv->join_bssid));
		priv->join_status = XRADIO_JOIN_STATUS_PASSIVE;

		/* Unjoin is a reset. */
		wsm_flush_tx(hw_priv);
		WARN_ON(wsm_keep_alive_period(hw_priv, 0, priv->if_id));
		WARN_ON(wsm_reset(hw_priv, &reset, priv->if_id));
		WARN_ON(wsm_set_operational_mode(hw_priv, &mode, priv->if_id));
		WARN_ON(wsm_set_output_power(hw_priv,
			hw_priv->output_power * 10, priv->if_id));
		priv->join_dtim_period = 0;
		priv->cipherType = 0;
		WARN_ON(cw1200_setup_mac_pvif(priv));
		cw1200_free_event_queue(hw_priv);
		cancel_work_sync(&hw_priv->event_handler);
		cancel_delayed_work_sync(&priv->connection_loss_work);
		WARN_ON(wsm_set_block_ack_policy(hw_priv,
			0, hw_priv->ba_tid_mask, priv->if_id));
		priv->disable_beacon_filter = false;
		cw1200_update_filtering(priv);
		priv->setbssparams_done = false;
		memset(&priv->association_mode, 0,
			sizeof(priv->association_mode));
		memset(&priv->bss_params, 0, sizeof(priv->bss_params));
		memset(&priv->firmware_ps_mode, 0,
			sizeof(priv->firmware_ps_mode));
		priv->htcap = false;
		cw1200_for_each_vif(hw_priv, tmp_priv, i) {
#ifdef P2P_MULTIVIF
			if ((i == (XRWL_MAX_VIFS - 1)) || !tmp_priv)
#else
			if (!tmp_priv)
#endif
				continue;
			if ((tmp_priv->join_status == XRADIO_JOIN_STATUS_STA) && tmp_priv->htcap)
				is_htcapie = true;
		}

		if (is_htcapie) {
			hw_priv->vif0_throttle = XRWL_HOST_VIF0_11N_THROTTLE;
			hw_priv->vif1_throttle = XRWL_HOST_VIF1_11N_THROTTLE;
			sta_printk(XRADIO_DBG_NIY, "UNJOIN HTCAP 11N %d\n",hw_priv->vif0_throttle);
		} else {
			hw_priv->vif0_throttle = XRWL_HOST_VIF0_11BG_THROTTLE;
			hw_priv->vif1_throttle = XRWL_HOST_VIF1_11BG_THROTTLE;
			sta_printk(XRADIO_DBG_NIY, "UNJOIN 11BG %d\n",hw_priv->vif0_throttle);
		}
		sta_printk(XRADIO_DBG_NIY, "Unjoin.\n");
	}
	mutex_unlock(&hw_priv->conf_mutex);
	wsm_unlock_tx(hw_priv);
}

int cw1200_enable_listening(struct cw1200_vif *priv,
				struct ieee80211_channel *chan)
{
	/* TODO:COMBO: Channel is common to HW currently in mac80211.
	Change the code below once channel is made per VIF */
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	struct wsm_start start = {
#ifdef P2P_MULTIVIF
		.mode = WSM_START_MODE_P2P_DEV | (priv->if_id ? (1 << 4) : 0),
#else
		.mode = WSM_START_MODE_P2P_DEV | (priv->if_id << 4),
#endif
		.band = (chan->band == IEEE80211_BAND_5GHZ) ?
				WSM_PHY_BAND_5G : WSM_PHY_BAND_2_4G,
		.channelNumber = chan->hw_value,
		.beaconInterval = 100,
		.DTIMPeriod = 1,
		.probeDelay = 0,
		.basicRateSet = 0x0F,
	};
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	if(priv->if_id != 2) {
		WARN_ON(priv->join_status > XRADIO_JOIN_STATUS_MONITOR);
		return 0;
	}
	if (priv->join_status == XRADIO_JOIN_STATUS_MONITOR)
		return 0;
	if (priv->join_status == XRADIO_JOIN_STATUS_PASSIVE)
		priv->join_status = XRADIO_JOIN_STATUS_MONITOR;

	WARN_ON(priv->join_status > XRADIO_JOIN_STATUS_MONITOR);

	return wsm_start(hw_priv, &start, XRWL_GENERIC_IF_ID);
}

int cw1200_disable_listening(struct cw1200_vif *priv)
{
	int ret;
	struct wsm_reset reset = {
		.reset_statistics = true,
	};
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	if(priv->if_id != 2) {
		WARN_ON(priv->join_status > XRADIO_JOIN_STATUS_MONITOR);
        return 0;
	}
	priv->join_status = XRADIO_JOIN_STATUS_PASSIVE;

	WARN_ON(priv->join_status > XRADIO_JOIN_STATUS_MONITOR);

	if (priv->hw_priv->roc_if_id == -1)
		return 0;

	ret = wsm_reset(priv->hw_priv, &reset, XRWL_GENERIC_IF_ID);
	return ret;
}

/* TODO:COMBO:UAPSD will be supported only on one interface */
int cw1200_set_uapsd_param(struct cw1200_vif *priv,
				const struct wsm_edca_params *arg)
{
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	int ret;
	u16 uapsdFlags = 0;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	/* Here's the mapping AC [queue, bit]
	VO [0,3], VI [1, 2], BE [2, 1], BK [3, 0]*/

	if (arg->params[0].uapsdEnable)
		uapsdFlags |= 1 << 3;

	if (arg->params[1].uapsdEnable)
		uapsdFlags |= 1 << 2;

	if (arg->params[2].uapsdEnable)
		uapsdFlags |= 1 << 1;

	if (arg->params[3].uapsdEnable)
		uapsdFlags |= 1;

	/* Currently pseudo U-APSD operation is not supported, so setting
	* MinAutoTriggerInterval, MaxAutoTriggerInterval and
	* AutoTriggerStep to 0 */

	priv->uapsd_info.uapsdFlags = cpu_to_le16(uapsdFlags);
	priv->uapsd_info.minAutoTriggerInterval = 0;
	priv->uapsd_info.maxAutoTriggerInterval = 0;
	priv->uapsd_info.autoTriggerStep = 0;

	ret = wsm_set_uapsd_info(hw_priv, &priv->uapsd_info,
				 priv->if_id);
	return ret;
}

/* ******************************************************************** */
/* AP API */
int cw1200_sta_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		   struct ieee80211_sta *sta)
{
	struct cw1200_vif *priv = xrwl_get_vif_from_ieee80211(vif);
	struct cw1200_sta_priv *sta_priv =
			(struct cw1200_sta_priv *)&sta->drv_priv;
	struct cw1200_link_entry *entry;
	struct sk_buff *skb;
#ifdef AP_AGGREGATE_FW_FIX
	struct cw1200_common *hw_priv = hw->priv;
#endif

	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

#ifdef P2P_MULTIVIF
	WARN_ON(priv->if_id == XRWL_GENERIC_IF_ID);
#endif

	if (priv->mode != NL80211_IFTYPE_AP)
		return 0;

	sta_priv->priv = priv;
	sta_priv->link_id = cw1200_find_link_id(priv, sta->addr);
	if (WARN_ON(!sta_priv->link_id)) {
		/* Impossible error */
		ap_printk(XRADIO_DBG_ERROR,"No more link IDs available.\n");
		return -ENOENT;
	}

	entry = &priv->link_id_db[sta_priv->link_id - 1];
	spin_lock_bh(&priv->ps_state_lock);
	if ((sta->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK) ==
					IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK)
		priv->sta_asleep_mask |= BIT(sta_priv->link_id);
	entry->status = XRADIO_LINK_HARD;
	while ((skb = skb_dequeue(&entry->rx_queue)))
		ieee80211_rx_irqsafe(priv->hw, skb);
	spin_unlock_bh(&priv->ps_state_lock);

#ifdef AP_AGGREGATE_FW_FIX
	hw_priv->connected_sta_cnt++;
	if(hw_priv->connected_sta_cnt>1) {
			wsm_lock_tx(hw_priv);
			WARN_ON(wsm_set_block_ack_policy(hw_priv,
					XRADIO_TX_BLOCK_ACK_DISABLED_FOR_ALL_TID,
					XRADIO_RX_BLOCK_ACK_DISABLED_FOR_ALL_TID,
					priv->if_id));
			wsm_unlock_tx(hw_priv);
	}
#endif

	return 0;
}

int cw1200_sta_remove(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
		      struct ieee80211_sta *sta)
{
	struct cw1200_common *hw_priv = hw->priv;
	struct cw1200_sta_priv *sta_priv =
			(struct cw1200_sta_priv *)&sta->drv_priv;
	struct cw1200_vif *priv = xrwl_get_vif_from_ieee80211(vif);
	struct cw1200_link_entry *entry;

#ifdef P2P_MULTIVIF
	WARN_ON(priv->if_id == XRWL_GENERIC_IF_ID);
#endif

	if (priv->mode != NL80211_IFTYPE_AP || !sta_priv->link_id)
		return 0;

	entry = &priv->link_id_db[sta_priv->link_id - 1];
	spin_lock_bh(&priv->ps_state_lock);
	entry->status = XRADIO_LINK_RESERVE;
	entry->timestamp = jiffies;
	wsm_lock_tx_async(hw_priv);
	if (queue_work(hw_priv->workqueue, &priv->link_id_work) <= 0)
		wsm_unlock_tx(hw_priv);
	spin_unlock_bh(&priv->ps_state_lock);
	flush_workqueue(hw_priv->workqueue);

#ifdef AP_AGGREGATE_FW_FIX
	hw_priv->connected_sta_cnt--;
	if(hw_priv->connected_sta_cnt <= 1) {
		if ((priv->if_id != 1) ||
			((priv->if_id == 1) && hw_priv->is_go_thru_go_neg)) {
			wsm_lock_tx(hw_priv);
			WARN_ON(wsm_set_block_ack_policy(hw_priv,
						XRADIO_TX_BLOCK_ACK_ENABLED_FOR_ALL_TID,
						XRADIO_RX_BLOCK_ACK_ENABLED_FOR_ALL_TID,
						priv->if_id));
			wsm_unlock_tx(hw_priv);
		}
	}
#endif

	return 0;
}

static void __cw1200_sta_notify(struct cw1200_vif *priv,
				enum sta_notify_cmd notify_cmd,
				int link_id)
{
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	u32 bit, prev;

	/* Zero link id means "for all link IDs" */
	if (link_id)
		bit = BIT(link_id);
	else if (WARN_ON_ONCE(notify_cmd != STA_NOTIFY_AWAKE))
		bit = 0;
	else
		bit = priv->link_id_map;
	prev = priv->sta_asleep_mask & bit;

	switch (notify_cmd) {
	case STA_NOTIFY_SLEEP:
		if (!prev) {
			if (priv->buffered_multicasts &&
			    !priv->sta_asleep_mask)
				queue_work(hw_priv->workqueue,
					   &priv->multicast_start_work);
			priv->sta_asleep_mask |= bit;
		}
		break;
	case STA_NOTIFY_AWAKE:
		if (prev) {
			priv->sta_asleep_mask &= ~bit;
			priv->pspoll_mask &= ~bit;
			if (priv->tx_multicast && link_id &&
			    !priv->sta_asleep_mask)
				queue_work(hw_priv->workqueue,
					   &priv->multicast_stop_work);
			cw1200_bh_wakeup(hw_priv);
		}
		break;
	}
}

void cw1200_sta_notify(struct ieee80211_hw *dev,
		       struct ieee80211_vif *vif,
		       enum sta_notify_cmd notify_cmd,
		       struct ieee80211_sta *sta)
{
	struct cw1200_vif *priv = xrwl_get_vif_from_ieee80211(vif);
	struct cw1200_sta_priv *sta_priv =
		(struct cw1200_sta_priv *)&sta->drv_priv;

#ifdef P2P_MULTIVIF
	WARN_ON(priv->if_id == XRWL_GENERIC_IF_ID);
#endif
	spin_lock_bh(&priv->ps_state_lock);
	__cw1200_sta_notify(priv, notify_cmd, sta_priv->link_id);
	spin_unlock_bh(&priv->ps_state_lock);
}

static void cw1200_ps_notify(struct cw1200_vif *priv,
		      int link_id, bool ps)
{
	if (link_id > MAX_STA_IN_AP_MODE)
		return;

	pr_debug("%s for LinkId: %d. STAs asleep: %.8X\n",
		 ps ? "Stop" : "Start",
		 link_id, priv->sta_asleep_mask);

	/* TODO:COMBO: __cw1200_sta_notify changed. */
	__cw1200_sta_notify(priv,
			    ps ? STA_NOTIFY_SLEEP : STA_NOTIFY_AWAKE, link_id);
}

void cw1200_ba_work(struct work_struct *work)
{
	struct cw1200_common *hw_priv =
		container_of(work, struct cw1200_common, ba_work);
	u8 tx_ba_tid_mask;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	/* TODO:COMBO: reenable this part of code */
/*	if (priv->join_status != XRADIO_JOIN_STATUS_STA)
		return;
	if (!priv->setbssparams_done)
		return;*/

	sta_printk(XRADIO_DBG_WARN, "BA work****\n");
	spin_lock_bh(&hw_priv->ba_lock);
//	tx_ba_tid_mask = hw_priv->ba_ena ? hw_priv->ba_tid_mask : 0;
	tx_ba_tid_mask = hw_priv->ba_tid_mask;
	spin_unlock_bh(&hw_priv->ba_lock);

	wsm_lock_tx(hw_priv);

	WARN_ON(wsm_set_block_ack_policy(hw_priv,
		tx_ba_tid_mask, hw_priv->ba_tid_mask, -1)); /*TODO:COMBO*/

	wsm_unlock_tx(hw_priv);
}

static int cw1200_set_tim_impl(struct cw1200_vif *priv, bool aid0_bit_set)
{
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	struct sk_buff *skb;
	struct wsm_update_ie update_ie = {
		.what = WSM_UPDATE_IE_BEACON,
		.count = 1,
	};
	u16 tim_offset, tim_length;

	pr_debug("[AP] mcast: %s.\n", aid0_bit_set ? "ena" : "dis");

	skb = ieee80211_beacon_get_tim(priv->hw, priv->vif,
			&tim_offset, &tim_length);
	if (!skb) {
		__cw1200_flush(hw_priv, true, priv->if_id);
		return -ENOENT;
	}

	if (tim_offset && tim_length >= 6) {
		/* Ignore DTIM count from mac80211:
		 * firmware handles DTIM internally.
		 */
		skb->data[tim_offset + 2] = 0;

		/* Set/reset aid0 bit */
		if (aid0_bit_set)
			skb->data[tim_offset + 4] |= 1;
		else
			skb->data[tim_offset + 4] &= ~1;
	}

	update_ie.ies = &skb->data[tim_offset];
	update_ie.length = tim_length;
	// filter same tim info, yangfh
	if(memcmp(priv->last_tim, update_ie.ies, tim_length)) {
		WARN_ON(wsm_update_ie(hw_priv, &update_ie, priv->if_id));
		memcpy(priv->last_tim, update_ie.ies, tim_length);
		ap_printk(XRADIO_DBG_MSG,"%02x %02x %02x %02x %02x %02x\n", 
		          update_ie.ies[0], update_ie.ies[1], update_ie.ies[2], 
		          update_ie.ies[3], update_ie.ies[4], update_ie.ies[5]);
	}

	dev_kfree_skb(skb);

	return 0;
}

void cw1200_set_tim_work(struct work_struct *work)
{
	struct cw1200_vif *priv =
		container_of(work, struct cw1200_vif, set_tim_work);
	(void)cw1200_set_tim_impl(priv, priv->aid0_bit_set);
}

int cw1200_set_tim(struct ieee80211_hw *dev, struct ieee80211_sta *sta,
		   bool set)
{
	struct cw1200_sta_priv *sta_priv = (struct cw1200_sta_priv *)&sta->drv_priv;
	struct cw1200_vif *priv = sta_priv->priv;

#ifdef P2P_MULTIVIF
	WARN_ON(priv->if_id == XRWL_GENERIC_IF_ID);
#endif
	WARN_ON(priv->mode != NL80211_IFTYPE_AP);
	queue_work(priv->hw_priv->workqueue, &priv->set_tim_work);
	return 0;
}

void cw1200_set_cts_work(struct work_struct *work)
{
	struct cw1200_vif *priv =
		container_of(work, struct cw1200_vif, set_cts_work.work);
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	u8 erp_ie[3] = {WLAN_EID_ERP_INFO, 0x1, 0};
	struct wsm_update_ie update_ie = {
		.what = WSM_UPDATE_IE_BEACON,
		.count = 1,
		.ies = erp_ie,
		.length = 3,
	};
	u32 erp_info;
	__le32 use_cts_prot;
	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	mutex_lock(&hw_priv->conf_mutex);
	erp_info = priv->erp_info;
	mutex_unlock(&hw_priv->conf_mutex);
	use_cts_prot = (erp_info & WLAN_ERP_USE_PROTECTION)? __cpu_to_le32(1) : 0;

	erp_ie[ERP_INFO_BYTE_OFFSET] = erp_info;

	ap_printk(XRADIO_DBG_MSG, "ERP information 0x%x\n", erp_info);

	/* TODO:COMBO: If 2 interfaces are on the same channel they share
	the same ERP values */
	WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_NON_ERP_PROTECTION,
	                       &use_cts_prot, sizeof(use_cts_prot), priv->if_id));
	/* If STA Mode update_ie is not required */
	if (priv->mode != NL80211_IFTYPE_STATION) {
		WARN_ON(wsm_update_ie(hw_priv, &update_ie, priv->if_id));
	}

	return;
}

static int cw1200_set_btcoexinfo(struct cw1200_vif *priv)
{
	struct wsm_override_internal_txrate arg;
	int ret = 0;

	if (priv->mode == NL80211_IFTYPE_STATION) {
		/* Plumb PSPOLL and NULL template */
		WARN_ON(cw1200_upload_pspoll(priv));
		WARN_ON(cw1200_upload_null(priv));
	} else {
		return 0;
	}

	memset(&arg, 0, sizeof(struct wsm_override_internal_txrate));

	if (!priv->vif->p2p) {
		/* STATION mode */
		if (priv->bss_params.operationalRateSet & ~0xF) {
			pr_debug("[STA] STA has ERP rates\n");
			/* G or BG mode */
			arg.internalTxRate = (__ffs(
			priv->bss_params.operationalRateSet & ~0xF));
		} else {
			pr_debug("[STA] STA has non ERP rates\n");
			/* B only mode */
			arg.internalTxRate = (__ffs(
			priv->association_mode.basicRateSet));
		}
		arg.nonErpInternalTxRate = (__ffs(
			priv->association_mode.basicRateSet));
	} else {
		/* P2P mode */
		arg.internalTxRate = (__ffs(
			priv->bss_params.operationalRateSet & ~0xF));
		arg.nonErpInternalTxRate = (__ffs(
			priv->bss_params.operationalRateSet & ~0xF));
	}

	ap_printk(XRADIO_DBG_NIY, "BTCOEX_INFO" "MODE %d, internalTxRate : %x,"
	          "nonErpInternalTxRate: %x\n", priv->mode, arg.internalTxRate,
	          arg.nonErpInternalTxRate);

	ret = wsm_write_mib(xrwl_vifpriv_to_hwpriv(priv),
	               WSM_MIB_ID_OVERRIDE_INTERNAL_TX_RATE, 
	               &arg, sizeof(arg), priv->if_id);

	return ret;
}

void cw1200_bss_info_changed(struct ieee80211_hw *dev,
			     struct ieee80211_vif *vif,
			     struct ieee80211_bss_conf *info,
			     u32 changed)
{
	struct cw1200_common *hw_priv = dev->priv;
	struct cw1200_vif *priv = xrwl_get_vif_from_ieee80211(vif);

	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

#ifdef P2P_MULTIVIF
	if (priv->if_id == XRWL_GENERIC_IF_ID)
		return;
#endif
	mutex_lock(&hw_priv->conf_mutex);
	if (changed & BSS_CHANGED_BSSID) {
#ifdef CONFIG_XRADIO_TESTMODE
		spin_lock_bh(&hw_priv->tsm_lock);
		if (hw_priv->tsm_info.sta_associated) {
			unsigned now = jiffies;
			hw_priv->tsm_info.sta_roamed = 1;
			if ((now - hw_priv->tsm_info.txconf_timestamp_vo) >
			    (now - hw_priv->tsm_info.rx_timestamp_vo))
				hw_priv->tsm_info.use_rx_roaming = 1;
		} else {
			hw_priv->tsm_info.sta_associated = 1;
		}
		spin_unlock_bh(&hw_priv->tsm_lock);
#endif /*CONFIG_XRADIO_TESTMODE*/
		memcpy(priv->bssid, info->bssid, ETH_ALEN);
		cw1200_setup_mac_pvif(priv);
	}

	/* TODO: BSS_CHANGED_IBSS */
	if (changed & BSS_CHANGED_ARP_FILTER) {
		struct wsm_arp_ipv4_filter filter = {0};
		int i;
		ap_printk(XRADIO_DBG_MSG, "[STA] BSS_CHANGED_ARP_FILTER enabled: %d, cnt: %d\n",
		          info->arp_filter_enabled, info->arp_addr_cnt);

		if (info->arp_filter_enabled){
			if (vif->type == NL80211_IFTYPE_STATION)
				filter.enable = (u32)XRADIO_ENABLE_ARP_FILTER_OFFLOAD;
			else if (priv->join_status == XRADIO_JOIN_STATUS_AP)
				filter.enable = (u32)(1<<1);
			else
				filter.enable = 0;
		}

		/* Currently only one IP address is supported by firmware.
		 * In case of more IPs arp filtering will be disabled. */
		if (info->arp_addr_cnt > 0 &&
		    info->arp_addr_cnt <= WSM_MAX_ARP_IP_ADDRTABLE_ENTRIES) {
			for (i = 0; i < info->arp_addr_cnt; i++) {
				filter.ipv4Address[i] = info->arp_addr_list[i];
				ap_printk(XRADIO_DBG_NIY, "[STA]addr[%d]: 0x%X\n", i, filter.ipv4Address[i]);
			}
		} else
			filter.enable = 0;

		if (filter.enable)
			cw1200_set_arpreply(dev, vif);

		priv->filter4.enable = filter.enable;
		ap_printk(XRADIO_DBG_NIY, "[STA]arp ip filter enable: %d\n", __le32_to_cpu(filter.enable));

		if (wsm_set_arp_ipv4_filter(hw_priv, &filter, priv->if_id))
			WARN_ON(1);

		if (filter.enable &&
			(priv->join_status == XRADIO_JOIN_STATUS_STA)) {
			/* Firmware requires that value for this 1-byte field must
			 * be specified in units of 500us. Values above the 128ms
			 * threshold are not supported. */
			//if (info->dynamic_ps_timeout >= 0x80)
			//	priv->powersave_mode.fastPsmIdlePeriod = 0xFF;
			//else
			//	priv->powersave_mode.fastPsmIdlePeriod = info->dynamic_ps_timeout << 1;

			priv->powersave_mode.fastPsmIdlePeriod = 200;//when connected,the dev->conf.dynamic_ps_timeout value is 0
			priv->powersave_mode.apPsmChangePeriod = 200; //100ms, add by yangfh
			ap_printk(XRADIO_DBG_NIY, "[STA]fastPsmIdle=%d, apPsmChange=%d\n", 
			          priv->powersave_mode.fastPsmIdlePeriod, 
			          priv->powersave_mode.apPsmChangePeriod);

			if (priv->setbssparams_done) {
				int ret = 0;
				struct wsm_set_pm pm = priv->powersave_mode;
				if (priv->user_power_set_true)
					priv->powersave_mode.pmMode = priv->user_pm_mode;
				else if ((priv->power_set_true &&
				         ((priv->powersave_mode.pmMode == WSM_PSM_ACTIVE) ||
				         (priv->powersave_mode.pmMode == WSM_PSM_PS)))    ||
				         !priv->power_set_true)
					priv->powersave_mode.pmMode = WSM_PSM_FAST_PS;

				ret = cw1200_set_pm (priv, &priv->powersave_mode);
				if(ret)
					priv->powersave_mode = pm;
			} else {
				priv->powersave_mode.pmMode = WSM_PSM_FAST_PS;
			}
			priv->power_set_true = 0;
			priv->user_power_set_true = 0;
		}
	}

#ifdef IPV6_FILTERING
    /*in linux3.4 mac,the  enum ieee80211_bss_change variable doesn't have BSS_CHANGED_NDP_FILTER enum value*/
#if 0
	if (changed & BSS_CHANGED_NDP_FILTER) {
		int i;
		struct wsm_ndp_ipv6_filter filter = {0};
		u16 *ipv6addr = NULL;

		ap_printk(XRADIO_DBG_MSG, "[STA] BSS_CHANGED_NDP_FILTER enabled: %d, cnt: %d\n", 
		          info->ndp_filter_enabled, info->ndp_addr_cnt);

		if (info->ndp_filter_enabled) {
			if (vif->type == NL80211_IFTYPE_STATION)
				filter.enable = (u32)XRADIO_ENABLE_NDP_FILTER_OFFLOAD;
			else if ((vif->type == NL80211_IFTYPE_AP))
				filter.enable = (u32)(1<<1);
			else
				filter.enable = 0;
		}

		/* Currently only one IP address is supported by firmware.
		 * In case of more IPs ndp filtering will be disabled. */
		if (info->ndp_addr_cnt > 0 &&
		    info->ndp_addr_cnt <= WSM_MAX_NDP_IP_ADDRTABLE_ENTRIES) {
			for (i = 0; i < info->ndp_addr_cnt; i++) {
				priv->filter6.ipv6Address[i] = filter.ipv6Address[i] = info->ndp_addr_list[i];
				ipv6addr = (u16 *)(&filter.ipv6Address[i]);
				ap_printk(XRADIO_DBG_MSG, "[STA] ipv6 addr[%d]: %x:%x:%x:%x:%x:%x:%x:%x\n", \
				          i, cpu_to_be16(*(ipv6addr + 0)), cpu_to_be16(*(ipv6addr + 1)), \
				          cpu_to_be16(*(ipv6addr + 2)), cpu_to_be16(*(ipv6addr + 3)), \
				          cpu_to_be16(*(ipv6addr + 4)), cpu_to_be16(*(ipv6addr + 5)), \
				          cpu_to_be16(*(ipv6addr + 6)), cpu_to_be16(*(ipv6addr + 7)));
			}
		} else {
			filter.enable = 0;
			for (i = 0; i < info->ndp_addr_cnt; i++) {
				ipv6addr = (u16 *)(&info->ndp_addr_list[i]);
				ap_printk(XRADIO_DBG_MSG, "[STA] ipv6 addr[%d]: %x:%x:%x:%x:%x:%x:%x:%x\n", \
				          i, cpu_to_be16(*(ipv6addr + 0)), cpu_to_be16(*(ipv6addr + 1)), \
				          cpu_to_be16(*(ipv6addr + 2)), cpu_to_be16(*(ipv6addr + 3)), \
				          cpu_to_be16(*(ipv6addr + 4)), cpu_to_be16(*(ipv6addr + 5)), \
									cpu_to_be16(*(ipv6addr + 6)), cpu_to_be16(*(ipv6addr + 7)));
			}
		}

		ap_printk(XRADIO_DBG_NIY, "[STA] ndp ip filter enable: %d\n",
		           __le32_to_cpu(filter.enable));

		if (filter.enable)
			cw1200_set_na(dev, vif);

		priv->filter6.enable = filter.enable;

		if (wsm_set_ndp_ipv6_filter(hw_priv, &filter, priv->if_id))
			WARN_ON(1);
#if 0 /*Commented out to disable Power Save in IPv6*/
		if (filter.enable && (priv->join_status == XRADIO_JOIN_STATUS_STA) && 
			  (priv->vif->p2p) && !(priv->firmware_ps_mode.pmMode & WSM_PSM_FAST_PS)) {
			if(priv->setbssparams_done) {
				int ret = 0;
				struct wsm_set_pm pm = priv->powersave_mode;

				priv->powersave_mode.pmMode = WSM_PSM_FAST_PS;
				ret = cw1200_set_pm(priv, &priv->powersave_mode);
				if(ret) {
					priv->powersave_mode = pm;
				}
			} else {
				priv->powersave_mode.pmMode = WSM_PSM_FAST_PS;
			}
		}
#endif
	}
#endif
#endif /*IPV6_FILTERING*/

	if (changed & BSS_CHANGED_BEACON) {
		ap_printk(XRADIO_DBG_NIY, "BSS_CHANGED_BEACON\n");
#ifdef HIDDEN_SSID
		if(priv->join_status != XRADIO_JOIN_STATUS_AP) {
			priv->hidden_ssid = info->hidden_ssid;
			priv->ssid_length = info->ssid_len;
			memcpy(priv->ssid, info->ssid, info->ssid_len);
		} else
			ap_printk(XRADIO_DBG_NIY, "priv->join_status=%d\n", priv->join_status);
#endif
		WARN_ON(cw1200_upload_beacon(priv));
		WARN_ON(cw1200_update_beaconing(priv));
	}

	if (changed & BSS_CHANGED_BEACON_ENABLED) {
		ap_printk(XRADIO_DBG_NIY, "BSS_CHANGED_BEACON_ENABLED dummy\n");
		priv->enable_beacon = info->enable_beacon;
	}

	if (changed & BSS_CHANGED_BEACON_INT) {
		pr_debug("CHANGED_BEACON_INT\n");
		/* Restart AP only when connected */
		if (priv->join_status == XRADIO_JOIN_STATUS_AP)
			WARN_ON(cw1200_update_beaconing(priv));
	}


	if (changed & BSS_CHANGED_ASSOC) {
		wsm_lock_tx(hw_priv);
		priv->wep_default_key_id = -1;
		wsm_unlock_tx(hw_priv);

		if (!info->assoc /* && !info->ibss_joined */) {
			priv->cqm_link_loss_count = XRADIO_LINK_LOSS_THOLD_DEF;
			priv->cqm_beacon_loss_count = XRADIO_BSS_LOSS_THOLD_DEF;
			priv->cqm_tx_failure_thold = 0;
		}
		priv->cqm_tx_failure_count = 0;
	}

	if (changed & 
	    (BSS_CHANGED_ASSOC        |
	     BSS_CHANGED_BASIC_RATES  |
	     BSS_CHANGED_ERP_PREAMBLE |
	     BSS_CHANGED_HT           |
	     BSS_CHANGED_ERP_SLOT)) {
		int is_combo = 0;
		int i;
		struct cw1200_vif *tmp_priv;
		ap_printk(XRADIO_DBG_NIY, "BSS_CHANGED_ASSOC.\n");
		if (info->assoc) { /* TODO: ibss_joined */
			struct ieee80211_sta *sta = NULL;
			if (info->dtim_period)
				priv->join_dtim_period = info->dtim_period;
			priv->beacon_int = info->beacon_int;

			/* Associated: kill join timeout */
			cancel_delayed_work_sync(&priv->join_timeout);

			rcu_read_lock();
			if (info->bssid)
				sta = ieee80211_find_sta(vif, info->bssid);
			if (sta) {
				/* TODO:COMBO:Change this once
				* mac80211 changes are available */
				BUG_ON(!hw_priv->channel);
				hw_priv->ht_info.ht_cap = sta->ht_cap;
				priv->bss_params.operationalRateSet =__cpu_to_le32(
				  cw1200_rate_mask_to_wsm(hw_priv, sta->supp_rates[hw_priv->channel->band]));
				hw_priv->ht_info.channel_type   = info->channel_type;
				hw_priv->ht_info.operation_mode = info->ht_operation_mode;
			} else {
				memset(&hw_priv->ht_info, 0, sizeof(hw_priv->ht_info));
				priv->bss_params.operationalRateSet = -1;
			}
			rcu_read_unlock();
			priv->htcap = (sta && cw1200_is_ht(&hw_priv->ht_info));
			cw1200_for_each_vif(hw_priv, tmp_priv, i) {
#ifdef P2P_MULTIVIF
				if ((i == (XRWL_MAX_VIFS - 1)) || !tmp_priv)
#else
				if (!tmp_priv)
#endif
					continue;
				if (tmp_priv->join_status >= XRADIO_JOIN_STATUS_STA)
					is_combo++;
			}

			if (is_combo > 1) {
				hw_priv->vif0_throttle = XRWL_HOST_VIF0_11BG_THROTTLE;
				hw_priv->vif1_throttle = XRWL_HOST_VIF1_11BG_THROTTLE;
				ap_printk(XRADIO_DBG_WARN, "%sASSOC is_combo %d\n", 
				         (priv->join_status == XRADIO_JOIN_STATUS_STA)?"[STA] ":"",
				          hw_priv->vif0_throttle);
			} else if ((priv->join_status == XRADIO_JOIN_STATUS_STA) && priv->htcap) {
				hw_priv->vif0_throttle = XRWL_HOST_VIF0_11N_THROTTLE;
				hw_priv->vif1_throttle = XRWL_HOST_VIF1_11N_THROTTLE;
				ap_printk(XRADIO_DBG_WARN, "[STA] ASSOC HTCAP 11N %d\n",hw_priv->vif0_throttle);
			} else {
				hw_priv->vif0_throttle = XRWL_HOST_VIF0_11BG_THROTTLE;
				hw_priv->vif1_throttle = XRWL_HOST_VIF1_11BG_THROTTLE;
				ap_printk(XRADIO_DBG_WARN, "ASSOC not_combo 11BG %d\n",hw_priv->vif0_throttle);
			}

			if (sta) {
				__le32 val = 0;
				if (hw_priv->ht_info.operation_mode & IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT) {
					ap_printk(XRADIO_DBG_NIY,"[STA] Non-GF STA present\n");
					/* Non Green field capable STA */
					val = __cpu_to_le32(BIT(1));
				}
				WARN_ON(wsm_write_mib(hw_priv, WSM_MID_ID_SET_HT_PROTECTION,
				                       &val, sizeof(val), priv->if_id));
			}

			priv->association_mode.greenfieldMode = cw1200_ht_greenfield(&hw_priv->ht_info);
			priv->association_mode.flags =
			  WSM_ASSOCIATION_MODE_SNOOP_ASSOC_FRAMES |
			  WSM_ASSOCIATION_MODE_USE_PREAMBLE_TYPE  |
			  WSM_ASSOCIATION_MODE_USE_HT_MODE        |
			  WSM_ASSOCIATION_MODE_USE_BASIC_RATE_SET |
			  WSM_ASSOCIATION_MODE_USE_MPDU_START_SPACING;

			priv->association_mode.preambleType =
			  (info->use_short_preamble ? WSM_JOIN_PREAMBLE_SHORT : WSM_JOIN_PREAMBLE_LONG);
			priv->association_mode.basicRateSet = __cpu_to_le32(
			  cw1200_rate_mask_to_wsm(hw_priv,info->basic_rates));
			priv->association_mode.mpduStartSpacing =
			  cw1200_ht_ampdu_density(&hw_priv->ht_info);

			//priv->cqm_beacon_loss_count = info->cqm_beacon_miss_thold;
			//priv->cqm_tx_failure_thold  = info->cqm_tx_fail_thold;
			//priv->cqm_tx_failure_count  = 0;
			cancel_delayed_work_sync(&priv->bss_loss_work);
			cancel_delayed_work_sync(&priv->connection_loss_work);

			priv->bss_params.beaconLostCount = (priv->cqm_beacon_loss_count ?
			  priv->cqm_beacon_loss_count : priv->cqm_link_loss_count);

			priv->bss_params.aid = info->aid;

			if (priv->join_dtim_period < 1)
				priv->join_dtim_period = 1;

			ap_printk(XRADIO_DBG_MSG, "[STA] DTIM %d, interval: %d\n",
			          priv->join_dtim_period, priv->beacon_int);
			ap_printk(XRADIO_DBG_MSG, "[STA] Preamble: %d, " \
			          "Greenfield: %d, Aid: %d, Rates: 0x%.8X, Basic: 0x%.8X\n",
			          priv->association_mode.preambleType,
			          priv->association_mode.greenfieldMode,
			          priv->bss_params.aid,
			          priv->bss_params.operationalRateSet,
			          priv->association_mode.basicRateSet);
			WARN_ON(wsm_set_association_mode(hw_priv, &priv->association_mode, priv->if_id));
			WARN_ON(wsm_keep_alive_period(hw_priv, XRADIO_KEEP_ALIVE_PERIOD /* sec */,
			                               priv->if_id));
			WARN_ON(wsm_set_bss_params(hw_priv, &priv->bss_params, priv->if_id));
			priv->setbssparams_done = true;
#ifdef XRADIO_USE_LONG_DTIM_PERIOD
{
			int join_dtim_period_extend;
			if (priv->join_dtim_period <= 3) {
				join_dtim_period_extend = priv->join_dtim_period * 3;
			} else if (priv->join_dtim_period <= 5) {
				join_dtim_period_extend = priv->join_dtim_period * 2;
			} else {
				join_dtim_period_extend = priv->join_dtim_period;
			}
			WARN_ON(wsm_set_beacon_wakeup_period(hw_priv,
				((priv->beacon_int * join_dtim_period_extend) > MAX_BEACON_SKIP_TIME_MS 
				? 1 : join_dtim_period_extend) , 0, priv->if_id));
}
#else
			WARN_ON(wsm_set_beacon_wakeup_period(hw_priv,
				((priv->beacon_int * priv->join_dtim_period) > MAX_BEACON_SKIP_TIME_MS 
				? 1 : priv->join_dtim_period) , 0, priv->if_id));
#endif
			if (priv->htcap) {
				wsm_lock_tx(hw_priv);
				/* Statically enabling block ack for TX/RX */
				WARN_ON(wsm_set_block_ack_policy(hw_priv, hw_priv->ba_tid_mask, 
				                                  hw_priv->ba_tid_mask, priv->if_id));
				wsm_unlock_tx(hw_priv);
			}
			/*set ps active,avoid that when connecting process,the device sleeps,then can't receive pkts.*/
			if (changed & BSS_CHANGED_ASSOC) 
				priv->powersave_mode.pmMode = WSM_PSM_ACTIVE;
			cw1200_set_pm(priv, &priv->powersave_mode);
			if (priv->vif->p2p) {
				pr_debug("[STA] Setting p2p powersave configuration.\n");
				wsm_set_p2p_ps_modeinfo(hw_priv, &priv->p2p_ps_modeinfo, priv->if_id);
				//cw1200_notify_noa(priv, XRADIO_NOA_NOTIFICATION_DELAY);
			}

			if (priv->mode == NL80211_IFTYPE_STATION)
				WARN_ON(cw1200_upload_qosnull(priv));

			if (hw_priv->is_BT_Present)
				WARN_ON(cw1200_set_btcoexinfo(priv));
#if 0
			/* It's better to override internal TX rete; otherwise
			 * device sends RTS at too high rate. However device
			 * can't receive CTS at 1 and 2 Mbps. Well, 5.5 is a
			 * good choice for RTS/CTS, but that means PS poll
			 * will be sent at the same rate - impact on link
			 * budget. Not sure what is better.. */

			/* Update: internal rate selection algorythm is not
			 * bad: if device is not receiving CTS at high rate,
			 * it drops RTS rate.
			 * So, conclusion: if-0 the code. Keep code just for
			 * information:
			 * Do not touch WSM_MIB_ID_OVERRIDE_INTERNAL_TX_RATE! */

			/* ~3 is a bug in device: RTS/CTS is not working at
			 * low rates */
			__le32 internal_tx_rate = __cpu_to_le32(
			                          __ffs(priv->association_mode.basicRateSet & ~3));
			WARN_ON(wsm_write_mib(priv, WSM_MIB_ID_OVERRIDE_INTERNAL_TX_RATE,
			                       &internal_tx_rate,sizeof(internal_tx_rate)));
#endif
		} else {
			memset(&priv->association_mode, 0, sizeof(priv->association_mode));
			memset(&priv->bss_params, 0, sizeof(priv->bss_params));
		}
	}
	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_ERP_CTS_PROT)) {
		u32 prev_erp_info = priv->erp_info;
		if (priv->join_status == XRADIO_JOIN_STATUS_AP) {
			if (info->use_cts_prot)
				priv->erp_info |= WLAN_ERP_USE_PROTECTION;
			else if (!(prev_erp_info & WLAN_ERP_NON_ERP_PRESENT))
				priv->erp_info &= ~WLAN_ERP_USE_PROTECTION;

			if (prev_erp_info != priv->erp_info)
				queue_delayed_work(hw_priv->workqueue, &priv->set_cts_work, 0*HZ);
		}
	}

	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_ERP_SLOT)) {
		__le32 slot_time = info->use_short_slot ? __cpu_to_le32(9) : __cpu_to_le32(20);
		ap_printk(XRADIO_DBG_MSG, "[STA] Slot time :%d us.\n", __le32_to_cpu(slot_time));
		WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_DOT11_SLOT_TIME, &slot_time, 
		                       sizeof(slot_time), priv->if_id));
	}
	if (changed & (BSS_CHANGED_ASSOC | BSS_CHANGED_CQM)) {
		struct wsm_rcpi_rssi_threshold threshold = {
			.rollingAverageCount = 8,
		};

#if 0
		/* For verification purposes */
		info->cqm_rssi_thold = -50;
		info->cqm_rssi_hyst = 4;
#endif /* 0 */

		pr_debug("[CQM] RSSI threshold subscribe: %d +- %d\n",
			 info->cqm_rssi_thold, info->cqm_rssi_hyst);
		priv->cqm_rssi_thold = info->cqm_rssi_thold;
		priv->cqm_rssi_hyst = info->cqm_rssi_hyst;

		if (info->cqm_rssi_thold || info->cqm_rssi_hyst) {
			/* RSSI subscription enabled */
			/* TODO: It's not a correct way of setting threshold.
			 * Upper and lower must be set equal here and adjusted
			 * in callback. However current implementation is much
			 * more reliable and stable.
			 */
			if (priv->cqm_use_rssi) {
				threshold.upperThreshold = info->cqm_rssi_thold + info->cqm_rssi_hyst;
				threshold.lowerThreshold = info->cqm_rssi_thold;
			} else {
				/* convert RSSI to RCPI, RCPI = (RSSI + 110) * 2 */
				threshold.upperThreshold = (info->cqm_rssi_thold + info->cqm_rssi_hyst + 110)<<1;
				threshold.lowerThreshold = (info->cqm_rssi_thold + 110)<<1;
			}
			threshold.rssiRcpiMode |= WSM_RCPI_RSSI_THRESHOLD_ENABLE;
		} else {
			/* There is a bug in FW, see sta.c. We have to enable
			 * dummy subscription to get correct RSSI values. */
			threshold.rssiRcpiMode |= WSM_RCPI_RSSI_THRESHOLD_ENABLE |
			                          WSM_RCPI_RSSI_DONT_USE_UPPER   |
			                          WSM_RCPI_RSSI_DONT_USE_LOWER;
		}
		WARN_ON(wsm_set_rcpi_rssi_threshold(hw_priv, &threshold, priv->if_id));

		//priv->cqm_tx_failure_thold = info->cqm_tx_fail_thold;
		//priv->cqm_tx_failure_count = 0;

		//if (priv->cqm_beacon_loss_count != info->cqm_beacon_miss_thold) {
		//	priv->cqm_beacon_loss_count = info->cqm_beacon_miss_thold;
		//	priv->bss_params.beaconLostCount = (priv->cqm_beacon_loss_count?
		//	  priv->cqm_beacon_loss_count : priv->cqm_link_loss_count);
			/* Make sure we are associated before sending
			 * set_bss_params to firmware */
			if (priv->bss_params.aid) {
				WARN_ON(wsm_set_bss_params(hw_priv, &priv->bss_params, priv->if_id));
				priv->setbssparams_done = true;
			}
		//}
	}
	/*
	 * in linux3.4 mac,the  enum ieee80211_bss_change variable doesn't have
	 * BSS_CHANGED_PS and BSS_CHANGED_RETRY_LIMITS enum value.
	 */
#if 0
	if (changed & BSS_CHANGED_PS) {
		if (info->ps_enabled == false)
			priv->powersave_mode.pmMode = WSM_PSM_ACTIVE;
		else if (info->dynamic_ps_timeout <= 0)
			priv->powersave_mode.pmMode = WSM_PSM_PS;
		else
			priv->powersave_mode.pmMode = WSM_PSM_FAST_PS;

		ap_printk(XRADIO_DBG_MSG, "[STA] Aid: %d, Joined: %s, Powersave: %s\n",
		          priv->bss_params.aid,
		          priv->join_status == XRADIO_JOIN_STATUS_STA ? "yes" : "no",
		         (priv->powersave_mode.pmMode == WSM_PSM_ACTIVE ? "WSM_PSM_ACTIVE" :
		          priv->powersave_mode.pmMode == WSM_PSM_PS ? "WSM_PSM_PS" :
		          priv->powersave_mode.pmMode == WSM_PSM_FAST_PS ? "WSM_PSM_FAST_PS" :
		          "UNKNOWN"));

		/* Firmware requires that value for this 1-byte field must
		 * be specified in units of 500us. Values above the 128ms
		 * threshold are not supported. */
		if (info->dynamic_ps_timeout >= 0x80)
			priv->powersave_mode.fastPsmIdlePeriod = 0xFF;
		else
			priv->powersave_mode.fastPsmIdlePeriod = info->dynamic_ps_timeout << 1;
		ap_printk(XRADIO_DBG_NIY, "[STA]CHANGED_PS fastPsmIdle=%d, apPsmChange=%d\n", 
		          priv->powersave_mode.fastPsmIdlePeriod, 
		          priv->powersave_mode.apPsmChangePeriod);

		if (priv->join_status == XRADIO_JOIN_STATUS_STA && priv->bss_params.aid &&
			  priv->setbssparams_done && priv->filter4.enable)
			cw1200_set_pm(priv, &priv->powersave_mode);
		else
			priv->power_set_true = 1;
	}

	if (changed & BSS_CHANGED_RETRY_LIMITS) {
		ap_printk(XRADIO_DBG_NIY, "Retry limits: %d (long), %d (short).\n", 
		          info->retry_long, info->retry_short);
		spin_lock_bh(&hw_priv->tx_policy_cache.lock);
		/*TODO:COMBO: for now it's still handled per hw and kept
		 * in cw1200_common */
		hw_priv->long_frame_max_tx_count  = info->retry_long;
		hw_priv->short_frame_max_tx_count = 
		  (info->retry_short < 0x0F ? info->retry_short : 0x0F);
		hw_priv->hw->max_rate_tries = hw_priv->short_frame_max_tx_count;
		spin_unlock_bh(&hw_priv->tx_policy_cache.lock);
		/* TBD: I think we don't need tx_policy_force_upload().
		 * Outdated policies will leave cache in a normal way. */
		/* WARN_ON(tx_policy_force_upload(priv)); */
	}
#endif
	/*in linux3.4 mac,the  enum ieee80211_bss_change variable doesn't have BSS_CHANGED_P2P_PS enum value*/
#if 0
	if (changed & BSS_CHANGED_P2P_PS) {
		struct wsm_p2p_ps_modeinfo *modeinfo;
		modeinfo = &priv->p2p_ps_modeinfo;
		ap_printk(XRADIO_DBG_NIY, "[AP] BSS_CHANGED_P2P_PS\n");
		ap_printk(XRADIO_DBG_NIY, "[AP] Legacy PS: %d for AID %d in %d mode.\n",
		          info->p2p_ps.legacy_ps, priv->bss_params.aid, priv->join_status);

		if (info->p2p_ps.legacy_ps >= 0) {
			if (info->p2p_ps.legacy_ps > 0)
				priv->powersave_mode.pmMode = WSM_PSM_PS;
			else
				priv->powersave_mode.pmMode = WSM_PSM_ACTIVE;

			if(info->p2p_ps.ctwindow && info->p2p_ps.opp_ps)
				priv->powersave_mode.pmMode = WSM_PSM_PS;
			if (priv->join_status == XRADIO_JOIN_STATUS_STA)
				cw1200_set_pm(priv, &priv->powersave_mode);
		}

		ap_printk(XRADIO_DBG_MSG, "[AP] CTWindow: %d\n", info->p2p_ps.ctwindow);
		if (info->p2p_ps.ctwindow >= 128)
			modeinfo->oppPsCTWindow = 127;
		else if (info->p2p_ps.ctwindow >= 0)
			modeinfo->oppPsCTWindow = info->p2p_ps.ctwindow;

		ap_printk(XRADIO_DBG_MSG, "[AP] Opportunistic: %d\n", info->p2p_ps.opp_ps);
		switch (info->p2p_ps.opp_ps) {
		case 0:
			modeinfo->oppPsCTWindow &= ~(BIT(7));
			break;
		case 1:
			modeinfo->oppPsCTWindow |= BIT(7);
			break;
		default:
			break;
		}

		ap_printk(XRADIO_DBG_MSG, "[AP] NOA: %d, %d, %d, %d\n",
		          info->p2p_ps.count, info->p2p_ps.start,
		          info->p2p_ps.duration, info->p2p_ps.interval);
		/* Notice of Absence */
		modeinfo->count = info->p2p_ps.count;

		if (info->p2p_ps.count) {
			/* In case P2P_GO we need some extra time to be sure
			 * we will update beacon/probe_resp IEs correctly */
#define NOA_DELAY_START_MS	300
			if (priv->join_status == XRADIO_JOIN_STATUS_AP)
				modeinfo->startTime = __cpu_to_le32(info->p2p_ps.start + NOA_DELAY_START_MS);
			else
				modeinfo->startTime = __cpu_to_le32(info->p2p_ps.start);
			modeinfo->duration    = __cpu_to_le32(info->p2p_ps.duration);
			modeinfo->interval    = __cpu_to_le32(info->p2p_ps.interval);
			modeinfo->dtimCount   = 1;
			modeinfo->reserved    = 0;
		} else {
			modeinfo->dtimCount = 0;
			modeinfo->startTime = 0;
			modeinfo->reserved  = 0;
			modeinfo->duration  = 0;
			modeinfo->interval  = 0;
		}

#if defined(CONFIG_XRADIO_DEBUG)
		print_hex_dump_bytes("p2p_set_ps_modeinfo: ", DUMP_PREFIX_NONE,
		                     (u8 *)modeinfo, sizeof(*modeinfo));
#endif /* CONFIG_XRADIO_DEBUG */

		if (priv->join_status == XRADIO_JOIN_STATUS_STA ||
		    priv->join_status == XRADIO_JOIN_STATUS_AP) {
			WARN_ON(wsm_set_p2p_ps_modeinfo(hw_priv, modeinfo, priv->if_id));
		}
		/* Temporary solution while firmware don't support NOA change
		 * notification yet */
		cw1200_notify_noa(priv, 10);
	}
#endif
	mutex_unlock(&hw_priv->conf_mutex);
}

void cw1200_ba_timer(unsigned long arg)
{
	bool ba_ena;
	struct cw1200_common *hw_priv = (struct cw1200_common *)arg;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	spin_lock_bh(&hw_priv->ba_lock);
	cw1200_debug_ba(hw_priv, hw_priv->ba_cnt, hw_priv->ba_acc,
			hw_priv->ba_cnt_rx, hw_priv->ba_acc_rx);

	if (atomic_read(&hw_priv->scan.in_progress)) {
		hw_priv->ba_cnt = 0;
		hw_priv->ba_acc = 0;
		hw_priv->ba_cnt_rx = 0;
		hw_priv->ba_acc_rx = 0;
		goto skip_statistic_update;
	}

	if (hw_priv->ba_cnt >= XRADIO_BLOCK_ACK_CNT &&
		(hw_priv->ba_acc / hw_priv->ba_cnt >= XRADIO_BLOCK_ACK_THLD ||
		(hw_priv->ba_cnt_rx >= XRADIO_BLOCK_ACK_CNT &&
		hw_priv->ba_acc_rx / hw_priv->ba_cnt_rx >=
			XRADIO_BLOCK_ACK_THLD)))
		ba_ena = true;
	else
		ba_ena = false;

	hw_priv->ba_cnt = 0;
	hw_priv->ba_acc = 0;
	hw_priv->ba_cnt_rx = 0;
	hw_priv->ba_acc_rx = 0;

	if (ba_ena != hw_priv->ba_ena) {
		if (ba_ena || ++hw_priv->ba_hist >= XRADIO_BLOCK_ACK_HIST) {
			hw_priv->ba_ena = ba_ena;
			hw_priv->ba_hist = 0;
#if 0
			sta_printk(XRADIO_DBG_NIY, "%s block ACK:\n",
				ba_ena ? "enable" : "disable");
			queue_work(hw_priv->workqueue, &hw_priv->ba_work);
#endif
		}
	} else if (hw_priv->ba_hist)
		--hw_priv->ba_hist;

skip_statistic_update:
	spin_unlock_bh(&hw_priv->ba_lock);
}

void cw1200_multicast_start_work(struct work_struct *work)
{
	struct cw1200_vif *priv =
	       container_of(work, struct cw1200_vif, multicast_start_work);
	long tmo = priv->join_dtim_period * (priv->beacon_int + 20) * HZ / 1024;

	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	cancel_work_sync(&priv->multicast_stop_work);
	if (!priv->aid0_bit_set) {
		wsm_lock_tx(priv->hw_priv);
		cw1200_set_tim_impl(priv, true);
		priv->aid0_bit_set = true;
		mod_timer(&priv->mcast_timeout, jiffies + tmo);
		wsm_unlock_tx(priv->hw_priv);
	}
}

void cw1200_multicast_stop_work(struct work_struct *work)
{
	struct cw1200_vif *priv =
		container_of(work, struct cw1200_vif, multicast_stop_work);

	if (priv->aid0_bit_set) {
		del_timer_sync(&priv->mcast_timeout);
		wsm_lock_tx(priv->hw_priv);
		priv->aid0_bit_set = false;
		cw1200_set_tim_impl(priv, false);
		wsm_unlock_tx(priv->hw_priv);
	}
}

void cw1200_mcast_timeout(unsigned long arg)
{
	struct cw1200_vif *priv = (struct cw1200_vif *)arg;
	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	ap_printk(XRADIO_DBG_WARN, "Multicast delivery timeout.\n");
	spin_lock_bh(&priv->ps_state_lock);
	priv->tx_multicast = priv->aid0_bit_set && priv->buffered_multicasts;
	if (priv->tx_multicast)
		cw1200_bh_wakeup(xrwl_vifpriv_to_hwpriv(priv));
	spin_unlock_bh(&priv->ps_state_lock);
}

int cw1200_ampdu_action(struct ieee80211_hw *hw,
			struct ieee80211_vif *vif,
                        enum ieee80211_ampdu_mlme_action action,
                        struct ieee80211_sta *sta, 
                        u16 tid, u16 *ssn, u8 buf_size)
{
	/* Aggregation is implemented fully in firmware,
	 * including block ack negotiation.
	 * In case of AMPDU aggregation in RX direction
	 * re-ordering of packets takes place on host. mac80211
	 * needs the ADDBA Request to setup reodering.mac80211 also
	 * sends ADDBA Response which is discarded in the driver as
	 * FW generates the ADDBA Response on its own.*/
	int ret;
	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	switch (action) {
	case IEEE80211_AMPDU_RX_START:
	case IEEE80211_AMPDU_RX_STOP:
		/* Just return OK to mac80211 */
		ret = 0;
		break;
	default:
		ret = -ENOTSUPP;
	}
	return ret;
}

/* ******************************************************************** */
/* WSM callback								*/
void cw1200_suspend_resume(struct cw1200_vif *priv, struct wsm_suspend_resume *arg)
{
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

#if 0
	ap_printk(XRADIO_DBG_MSG, "[AP] %s: %s\n", 
	          arg->stop ? "stop" : "start",
	          arg->multicast ? "broadcast" : "unicast");
#endif
	if (arg->multicast) {
		bool cancel_tmo = false;
		spin_lock_bh(&priv->ps_state_lock);
		if (arg->stop) {
			priv->tx_multicast = false;
		} else {
			/* Firmware sends this indication every DTIM if there
			 * is a STA in powersave connected. There is no reason
			 * to suspend, following wakeup will consume much more
			 * power than it could be saved. */
			cw1200_pm_stay_awake(&hw_priv->pm_state, (priv->join_dtim_period *
			                     (priv->beacon_int + 20) * HZ / 1024));
			priv->tx_multicast = priv->aid0_bit_set && priv->buffered_multicasts;
			if (priv->tx_multicast) {
				cancel_tmo = true;
				cw1200_bh_wakeup(hw_priv);
			}
		}
		spin_unlock_bh(&priv->ps_state_lock);
		if (cancel_tmo)
			del_timer_sync(&priv->mcast_timeout);
	} else {
		spin_lock_bh(&priv->ps_state_lock);
		cw1200_ps_notify(priv, arg->link_id, arg->stop);
		spin_unlock_bh(&priv->ps_state_lock);
		if (!arg->stop)
			cw1200_bh_wakeup(hw_priv);
	}
	return;
}

/* ******************************************************************** */
/* AP privates								*/

static int cw1200_upload_beacon(struct cw1200_vif *priv)
{
	int ret = 0;
	struct ieee80211_mgmt *mgmt;
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_BEACON,
	};
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	u8 *erp_inf, *ies, *ht_info;
	u32 ies_len;

	if (priv->vif->p2p || hw_priv->channel->band == IEEE80211_BAND_5GHZ)
		frame.rate = WSM_TRANSMIT_RATE_6;

	frame.skb = ieee80211_beacon_get(priv->hw, priv->vif);
	if (WARN_ON(!frame.skb))
		return -ENOMEM;

	mgmt = (void *)frame.skb->data;
	ies  = mgmt->u.beacon.variable;
	ies_len = frame.skb->len - (u32)(ies - (u8 *)mgmt);

	ht_info = (u8 *)cfg80211_find_ie( WLAN_EID_HT_INFORMATION, ies, ies_len);
	if (ht_info) {
		/* Enable RIFS*/
		ht_info[3] |= 8;
	}

	erp_inf = (u8 *)cfg80211_find_ie(WLAN_EID_ERP_INFO, ies, ies_len);
	if (erp_inf) {
		if (erp_inf[ERP_INFO_BYTE_OFFSET]
				& WLAN_ERP_BARKER_PREAMBLE)
			priv->erp_info |= WLAN_ERP_BARKER_PREAMBLE;
		else
			priv->erp_info &= ~WLAN_ERP_BARKER_PREAMBLE;

		if (erp_inf[ERP_INFO_BYTE_OFFSET]
				& WLAN_ERP_NON_ERP_PRESENT) {
			priv->erp_info |= WLAN_ERP_USE_PROTECTION;
			priv->erp_info |= WLAN_ERP_NON_ERP_PRESENT;
		} else {
			priv->erp_info &= ~WLAN_ERP_USE_PROTECTION;
			priv->erp_info &= ~WLAN_ERP_NON_ERP_PRESENT;
		}
	}

#ifdef HIDDEN_SSID
	if (priv->hidden_ssid) {
		u8 *ssid_ie;
		u8 ssid_len;

		ap_printk(XRADIO_DBG_NIY, "%s: hidden_ssid set\n", __func__);
		ssid_ie = (u8 *)cfg80211_find_ie(WLAN_EID_SSID, ies, ies_len);
		WARN_ON(!ssid_ie);
		ssid_len = ssid_ie[1];
		if (ssid_len) {
			ap_printk(XRADIO_DBG_MSG, "hidden_ssid with zero content ssid\n");
			ssid_ie[1] = 0;
			memmove(ssid_ie + 2, ssid_ie + 2 + ssid_len,
					(ies + ies_len -
					 (ssid_ie + 2 + ssid_len)));
			frame.skb->len -= ssid_len;
		} else {
			ap_printk(XRADIO_DBG_WARN, "hidden ssid with ssid len 0 not supported");
			dev_kfree_skb(frame.skb);
			return -1;
		}
	}
#endif

	ret = wsm_set_template_frame(hw_priv, &frame, priv->if_id);
	if (!ret) {
#ifdef PROBE_RESP_EXTRA_IE
		ret = cw1200_upload_proberesp(priv);
#else
		/* TODO: Distille probe resp; remove TIM
		 * and other beacon-specific IEs */
		*(__le16 *)frame.skb->data = __cpu_to_le16(
		                             IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_RESP);
		frame.frame_type = WSM_FRAME_TYPE_PROBE_RESPONSE;
		/* TODO: Ideally probe response template should separately
		   configured by supplicant through openmac. This is a
		   temporary work-around known to fail p2p group info
		   attribute related tests
		   */
		if (0 /* priv->vif->p2p */)
			ret = wsm_set_probe_responder(priv, true);
		else {
			ret = wsm_set_template_frame(hw_priv, &frame, priv->if_id);
			WARN_ON(wsm_set_probe_responder(priv, false));
		}
#endif
	}
	dev_kfree_skb(frame.skb);

	return ret;
}

#ifdef PROBE_RESP_EXTRA_IE
static int cw1200_upload_proberesp(struct cw1200_vif *priv)
{
	int ret = 0;
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_PROBE_RESPONSE,
	};
#ifdef HIDDEN_SSID
	u8 *ssid_ie;
#endif
	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	if (priv->vif->p2p || hw_priv->channel->band == IEEE80211_BAND_5GHZ)
		frame.rate = WSM_TRANSMIT_RATE_6;

	frame.skb = ieee80211_proberesp_get(priv->hw, priv->vif);
	if (WARN_ON(!frame.skb))
		return -ENOMEM;

#ifdef HIDDEN_SSID
	if (priv->hidden_ssid) {
		int offset;
		u8 ssid_len;
		/* we are assuming beacon from upper layer will always contain
		   zero filled ssid for hidden ap. The beacon shall never have
		   ssid len = 0.
		  */

		offset  = offsetof(struct ieee80211_mgmt, u.probe_resp.variable);
		ssid_ie = (u8 *)cfg80211_find_ie(WLAN_EID_SSID, frame.skb->data + offset,
		                           frame.skb->len - offset);
		ssid_len = ssid_ie[1];
		if (ssid_len && (ssid_len == priv->ssid_length)) {
			memcpy(ssid_ie + 2, priv->ssid, ssid_len);
		} else {
			ap_printk(XRADIO_DBG_ERROR, "%s: hidden ssid with mismatched ssid_len %d\n",
			         __func__, ssid_len);
			dev_kfree_skb(frame.skb);
			return -1;
		}
	}
#endif
	ret = wsm_set_template_frame(hw_priv, &frame,  priv->if_id);
	WARN_ON(wsm_set_probe_responder(priv, false));

	dev_kfree_skb(frame.skb);

	return ret;
}
#endif

static int cw1200_upload_pspoll(struct cw1200_vif *priv)
{
	int ret = 0;
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_PS_POLL,
		.rate = 0xFF,
	};
	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	frame.skb = ieee80211_pspoll_get(priv->hw, priv->vif);
	if (WARN_ON(!frame.skb))
		return -ENOMEM;
	ret = wsm_set_template_frame(xrwl_vifpriv_to_hwpriv(priv), &frame, priv->if_id);
	dev_kfree_skb(frame.skb);
	return ret;
}

static int cw1200_upload_null(struct cw1200_vif *priv)
{
	int ret = 0;
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_NULL,
		.rate = 0xFF,
	};
	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	frame.skb = ieee80211_nullfunc_get(priv->hw, priv->vif);
	if (WARN_ON(!frame.skb))
		return -ENOMEM;

	ret = wsm_set_template_frame(xrwl_vifpriv_to_hwpriv(priv), &frame, priv->if_id);
	dev_kfree_skb(frame.skb);
	return ret;
}

static int cw1200_upload_qosnull(struct cw1200_vif *priv)
{
	struct ieee80211_qos_hdr* qos_null_template;
	struct sk_buff* skb;
	int ret = 0;
	struct cw1200_common *hw_priv =xrwl_vifpriv_to_hwpriv(priv);
	struct wsm_template_frame frame = {
		.frame_type = WSM_FRAME_TYPE_QOS_NULL,
		.rate = 0xFF,
	};
	if (!hw_priv) 
		ap_printk(XRADIO_DBG_ERROR,"%s: Cannot find cw1200_common pointer!\n",__FUNCTION__);
	/*set qos template*/
	skb = dev_alloc_skb(hw_priv->hw->extra_tx_headroom + sizeof(struct ieee80211_qos_hdr));
	if (!skb) {
		ap_printk(XRADIO_DBG_ERROR,"%s: failed to allocate buffer for qos  nullfunc template!\n",__FUNCTION__);
		return -1;
	}
	skb_reserve(skb, hw_priv->hw->extra_tx_headroom);
	qos_null_template = (struct ieee80211_qos_hdr *)skb_put(skb,sizeof(struct ieee80211_qos_hdr));
	memset(qos_null_template, 0, sizeof(struct ieee80211_qos_hdr));
	memcpy(qos_null_template->addr1, priv->vif->bss_conf.bssid, ETH_ALEN);
	memcpy(qos_null_template->addr2, priv->vif->addr, ETH_ALEN);
	memcpy(qos_null_template->addr3, priv->vif->bss_conf.bssid, ETH_ALEN);
	qos_null_template->frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA |
					     IEEE80211_STYPE_QOS_NULLFUNC |
					     IEEE80211_FCTL_TODS);
	frame.skb = skb;
	ret = wsm_set_template_frame(hw_priv, &frame, priv->if_id);
	dev_kfree_skb(frame.skb);
	return ret;
}

/* This API is nolonegr present in WSC */
#if 0
static int cw1200_enable_beaconing(struct cw1200_vif *priv,
				   bool enable)
{
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	struct wsm_beacon_transmit transmit = {
		.enableBeaconing = enable,
	};

	return wsm_beacon_transmit(hw_priv, &transmit, priv->if_id);
}
#endif

static int cw1200_start_ap(struct cw1200_vif *priv)
{
	int ret;
#ifndef HIDDEN_SSID
	const u8 *ssidie;
	struct sk_buff *skb;
	int offset;
#endif
	struct ieee80211_bss_conf *conf = &priv->vif->bss_conf;
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	struct wsm_start start = {
		.mode = priv->vif->p2p ? WSM_START_MODE_P2P_GO : WSM_START_MODE_AP,
		/* TODO:COMBO:Change once mac80211 support is available */
		.band = (hw_priv->channel->band == IEEE80211_BAND_5GHZ) ?
				     WSM_PHY_BAND_5G : WSM_PHY_BAND_2_4G,
		.channelNumber = hw_priv->channel->hw_value,
		.beaconInterval = conf->beacon_int,
		.DTIMPeriod = conf->dtim_period,
		.preambleType = conf->use_short_preamble ?
		                WSM_JOIN_PREAMBLE_SHORT :WSM_JOIN_PREAMBLE_LONG,
		.probeDelay = 100,
		.basicRateSet = cw1200_rate_mask_to_wsm(hw_priv, conf->basic_rates),
#ifdef P2P_MULTIVIF
		.CTWindow = priv->vif->p2p ? 0xFFFFFFFF : 0,
#endif
	};
	struct wsm_operational_mode mode = {
		.power_mode = wsm_power_mode_quiescent,
		.disableMoreFlagUsage = true,
	};

#ifdef TES_P2P_000B_EXTEND_INACTIVITY_CNT
	///w, TES_P2P_000B WorkAround:
	///w, when inactivity count of a peer device is zero,
	///w, which will reset while receiving a peer device frame,
	///w, firmware will disconnect with it.
	///w, due to some reason, such as scan/phy error, we miss these frame.
	///w, then we can't keep connection with peer device.
	///w, we set the min_inactivity value to large as WorkAround.
	//min_inactivity be modified to 20, yangfh.
	struct wsm_inactivity inactivity = {
		.min_inactivity = 20,
		.max_inactivity = 10,
	};
#else
	struct wsm_inactivity inactivity = {
		.min_inactivity = 9,
		.max_inactivity = 1,
	};
#endif

	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	if (priv->if_id)
		start.mode |= WSM_FLAG_MAC_INSTANCE_1;
	else
		start.mode &= ~WSM_FLAG_MAC_INSTANCE_1;

	hw_priv->connected_sta_cnt = 0;

#ifndef HIDDEN_SSID
	/* Get SSID */
	skb = ieee80211_beacon_get(priv->hw, priv->vif);
	if (WARN_ON(!skb)) {
		ap_printk(XRADIO_DBG_ERROR,"%s, ieee80211_beacon_get failed\n", __func__);
		return -ENOMEM;
	}

	offset = offsetof(struct ieee80211_mgmt, u.beacon.variable);
	ssidie = cfg80211_find_ie(WLAN_EID_SSID, skb->data + offset, skb->len - offset);

	memset(priv->ssid, 0, sizeof(priv->ssid));
	if (ssidie) {
		priv->ssid_length = ssidie[1];
		if (WARN_ON(priv->ssid_length > sizeof(priv->ssid)))
			priv->ssid_length = sizeof(priv->ssid);
		memcpy(priv->ssid, &ssidie[2], priv->ssid_length);
	} else {
		priv->ssid_length = 0;
	}
	dev_kfree_skb(skb);
#endif

	priv->beacon_int = conf->beacon_int;
	priv->join_dtim_period = conf->dtim_period;
	memset(&priv->last_tim[0], 0, sizeof(priv->last_tim)); //yangfh

	start.ssidLength = priv->ssid_length;
	memcpy(&start.ssid[0], priv->ssid, start.ssidLength);

	memset(&priv->link_id_db, 0, sizeof(priv->link_id_db));

	ap_printk(XRADIO_DBG_NIY, "[AP] ch: %d(%d), bcn: %d(%d),"
	          "bss_rate: 0x%.8X, ssid: %.*s.\n",
	          start.channelNumber,  start.band,
	          start.beaconInterval, start.DTIMPeriod, 
	          start.basicRateSet, start.ssidLength, start.ssid);
	ret = WARN_ON(wsm_start(hw_priv, &start, priv->if_id));

	if (!ret && priv->vif->p2p) {
		pr_debug("[AP] Setting p2p powersave configuration.\n");
		wsm_set_p2p_ps_modeinfo(hw_priv, &priv->p2p_ps_modeinfo, priv->if_id));
		//cw1200_notify_noa(priv, XRADIO_NOA_NOTIFICATION_DELAY);
	}

	/*Set Inactivity time*/
	if(!(strstr(&start.ssid[0], "6.1.12"))) {
		wsm_set_inactivity(hw_priv, &inactivity, priv->if_id);
	}
	if (!ret) {
#ifndef AP_AGGREGATE_FW_FIX
		WARN_ON(wsm_set_block_ack_policy(hw_priv,
		         XRADIO_TX_BLOCK_ACK_DISABLED_FOR_ALL_TID,
		         XRADIO_RX_BLOCK_ACK_DISABLED_FOR_ALL_TID, priv->if_id));
#else
		if ((priv->if_id ==1) && !hw_priv->is_go_thru_go_neg)
			WARN_ON(wsm_set_block_ack_policy(hw_priv,
			         XRADIO_TX_BLOCK_ACK_ENABLED_FOR_ALL_TID, //modified for WFD by yangfh
			         XRADIO_RX_BLOCK_ACK_ENABLED_FOR_ALL_TID, priv->if_id));
		else
			WARN_ON(wsm_set_block_ack_policy(hw_priv,
			         XRADIO_TX_BLOCK_ACK_ENABLED_FOR_ALL_TID,
			         XRADIO_RX_BLOCK_ACK_ENABLED_FOR_ALL_TID, priv->if_id));
#endif
		priv->join_status = XRADIO_JOIN_STATUS_AP;
		/* cw1200_update_filtering(priv); */
	}
	WARN_ON(wsm_set_operational_mode(hw_priv, &mode, priv->if_id));
	hw_priv->vif0_throttle = XRWL_HOST_VIF0_11BG_THROTTLE;
	hw_priv->vif1_throttle = XRWL_HOST_VIF1_11BG_THROTTLE;
	ap_printk(XRADIO_DBG_WARN, "vif%d, AP/GO mode THROTTLE=%d\n", priv->if_id,
	          priv->if_id==0?hw_priv->vif0_throttle:hw_priv->vif1_throttle);
	return ret;
}

static int cw1200_update_beaconing(struct cw1200_vif *priv)
{
	struct ieee80211_bss_conf *conf = &priv->vif->bss_conf;
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	struct wsm_reset reset = {
		.link_id = 0,
		.reset_statistics = true,
	};
	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	if (priv->mode == NL80211_IFTYPE_AP) {
		/* TODO: check if changed channel, band */
		if (priv->join_status != XRADIO_JOIN_STATUS_AP ||
		    priv->beacon_int  != conf->beacon_int) {
			ap_printk(XRADIO_DBG_WARN, "ap restarting!\n");
			wsm_lock_tx(hw_priv);
			if (priv->join_status != XRADIO_JOIN_STATUS_PASSIVE)
				WARN_ON(wsm_reset(hw_priv, &reset, priv->if_id));
			priv->join_status = XRADIO_JOIN_STATUS_PASSIVE;
			WARN_ON(cw1200_start_ap(priv));
			wsm_unlock_tx(hw_priv);
		} else
			ap_printk(XRADIO_DBG_NIY, "ap started join_status: %d\n", priv->join_status);
	}
	return 0;
}

#if 0
void cw1200_notify_noa(struct cw1200_vif *priv, int delay)
{
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	struct cfg80211_p2p_ps p2p_ps = {0};
	struct wsm_p2p_ps_modeinfo *modeinfo;
	modeinfo = &priv->p2p_ps_modeinfo;

	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	if (priv->join_status != XRADIO_JOIN_STATUS_AP)
		return;

	if (delay)
		msleep(delay);

	if (!WARN_ON(wsm_get_p2p_ps_modeinfo(hw_priv, modeinfo))) {
#if defined(CONFIG_XRADIO_DEBUG)
		print_hex_dump_bytes("[AP] p2p_get_ps_modeinfo: ", DUMP_PREFIX_NONE,
		                    (u8 *)modeinfo, sizeof(*modeinfo));
#endif /* CONFIG_XRADIO_DEBUG */
		p2p_ps.opp_ps = !!(modeinfo->oppPsCTWindow & BIT(7));
		p2p_ps.ctwindow = modeinfo->oppPsCTWindow & (~BIT(7));
		p2p_ps.count = modeinfo->count;
		p2p_ps.start = __le32_to_cpu(modeinfo->startTime);
		p2p_ps.duration = __le32_to_cpu(modeinfo->duration);
		p2p_ps.interval = __le32_to_cpu(modeinfo->interval);
		p2p_ps.index = modeinfo->reserved;

		ieee80211_p2p_noa_notify(priv->vif, &p2p_ps, GFP_KERNEL);
	}
}
#endif
int xrwl_unmap_link(struct cw1200_vif *priv, int link_id)
{
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	int ret = 0;
	struct wsm_operational_mode mode = {
		.power_mode = wsm_power_mode_quiescent,
		.disableMoreFlagUsage = true,
	};
	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	if (is_hardware_cw1200(hw_priv)) {
		struct wsm_map_link maplink = {
			.link_id = link_id,
			.unmap = true,
		};
		if (link_id)
			memcpy(&maplink.mac_addr[0], priv->link_id_db[link_id - 1].mac, ETH_ALEN);
		return wsm_map_link(hw_priv, &maplink, priv->if_id);
	} else {
		struct wsm_reset reset = {
			.link_id = link_id,
			.reset_statistics = true,
		};
		ret = wsm_reset(hw_priv, &reset, priv->if_id);
		WARN_ON(wsm_set_operational_mode(hw_priv, &mode, priv->if_id));
		return ret;
	}
}
#ifdef AP_HT_CAP_UPDATE
void cw1200_ht_info_update_work(struct work_struct *work)
{
	struct sk_buff *skb;
	struct ieee80211_mgmt *mgmt;
	u8 *ht_info, *ies;
	u32 ies_len;
	struct cw1200_vif *priv =
	        container_of(work, struct cw1200_vif, ht_info_update_work);
	struct cw1200_common *hw_priv = xrwl_vifpriv_to_hwpriv(priv);
	struct wsm_update_ie update_ie = {
		.what = WSM_UPDATE_IE_BEACON,
		.count = 1,
	};
	ap_printk(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	skb = ieee80211_beacon_get(priv->hw, priv->vif);
	if (WARN_ON(!skb))
		return;

	mgmt = (void *)skb->data;
	ies = mgmt->u.beacon.variable;
	ies_len = skb->len - (u32)(ies - (u8 *)mgmt);
	ht_info= (u8 *)cfg80211_find_ie( WLAN_EID_HT_INFORMATION, ies, ies_len);
	if(ht_info && priv->ht_info == HT_INFO_MASK) {
		ht_info[HT_INFO_OFFSET] |= 0x11;
		update_ie.ies = ht_info;
		update_ie.length = HT_INFO_IE_LEN;
		WARN_ON(wsm_update_ie(hw_priv, &update_ie, priv->if_id));
	}
	dev_kfree_skb(skb);
}
#endif

int cw1200_vif_setup(struct cw1200_vif *priv)
{
	struct cw1200_common *hw_priv = priv->hw_priv;
	int ret = 0;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	//reset channel change flag, yangfh 2015-5-15 17:12:14
	hw_priv->channel_changed  = 0;
	/* Setup per vif workitems and locks */
	spin_lock_init(&priv->vif_lock);
	INIT_WORK(&priv->join_work, cw1200_join_work);
	INIT_DELAYED_WORK(&priv->join_timeout, cw1200_join_timeout);
	INIT_WORK(&priv->unjoin_work, cw1200_unjoin_work);
	INIT_WORK(&priv->wep_key_work, cw1200_wep_key_work);
	INIT_WORK(&priv->offchannel_work, cw1200_offchannel_work);
	INIT_DELAYED_WORK(&priv->bss_loss_work, cw1200_bss_loss_work);
	INIT_DELAYED_WORK(&priv->connection_loss_work, cw1200_connection_loss_work);
	priv->bss_loss_status = XRADIO_BSS_LOSS_NONE;
	spin_lock_init(&priv->bss_loss_lock);
	INIT_WORK(&priv->tx_failure_work, cw1200_tx_failure_work);
	spin_lock_init(&priv->ps_state_lock);
	INIT_DELAYED_WORK(&priv->set_cts_work, cw1200_set_cts_work);
	INIT_WORK(&priv->set_tim_work, cw1200_set_tim_work);
	INIT_WORK(&priv->multicast_start_work, cw1200_multicast_start_work);
	INIT_WORK(&priv->multicast_stop_work, cw1200_multicast_stop_work);
	INIT_WORK(&priv->link_id_work, cw1200_link_id_work);
	INIT_DELAYED_WORK(&priv->link_id_gc_work, cw1200_link_id_gc_work);
	INIT_WORK(&priv->linkid_reset_work, cw1200_link_id_reset);
	INIT_WORK(&priv->update_filtering_work, cw1200_update_filtering_work);
	INIT_DELAYED_WORK(&priv->pending_offchanneltx_work,
			cw1200_pending_offchanneltx_work);
	INIT_WORK(&priv->set_beacon_wakeup_period_work,
		cw1200_set_beacon_wakeup_period_work);
#ifdef AP_HT_CAP_UPDATE
        INIT_WORK(&priv->ht_info_update_work, cw1200_ht_info_update_work);
#endif
	init_timer(&priv->mcast_timeout);
	priv->mcast_timeout.data = (unsigned long)priv;
	priv->mcast_timeout.function = cw1200_mcast_timeout;
	priv->setbssparams_done = false;
	priv->power_set_true = 0;
	priv->user_power_set_true = 0;
	priv->user_pm_mode = 0;
	WARN_ON(cw1200_debug_init_priv(hw_priv, priv));

	/* Initialising the broadcast filter */
	memset(priv->broadcast_filter.MacAddr, 0xFF, ETH_ALEN);
	priv->broadcast_filter.nummacaddr = 1;
	priv->broadcast_filter.address_mode = 1;
	priv->broadcast_filter.filter_mode = 1;
	priv->htcap = false;
#ifdef AP_HT_COMPAT_FIX
	priv->ht_compat_det = 0;
	priv->ht_compat_cnt = 0;
#endif

	sta_printk(XRADIO_DBG_ALWY, "!!!%s: id=%d, type=%d, p2p=%d\n",
			__func__, priv->if_id, priv->vif->type, priv->vif->p2p);

	atomic_set(&priv->enabled, 1);

#ifdef P2P_MULTIVIF
	if (priv->if_id < 2) {
#endif
		/* default EDCA */
		WSM_EDCA_SET(&priv->edca, 0, 0x0002, 0x0003, 0x0007,
				47, 0xc8, false);
		WSM_EDCA_SET(&priv->edca, 1, 0x0002, 0x0007, 0x000f,
				94, 0xc8, false);

//		if(priv->vif->p2p == true) {
			WSM_EDCA_SET(&priv->edca, 2, 0x0002, 0x0003, 0x0007,
				0, 0xc8, false);
			sta_printk(XRADIO_DBG_MSG, "EDCA params Best effort for sta/p2p is " \
				 "aifs=%u, cw_min=%u, cw_max=%u \n",
				priv->edca.params[2].aifns, priv->edca.params[2].cwMin,
				 priv->edca.params[2].cwMax);
#if 0					 
		}else {
			WSM_EDCA_SET(&priv->edca, 2, 0x0003, 0x000f, 0x03ff,
				0, 0xc8, false);
			sta_printk(XRADIO_DBG_MSG, "EDCA params Best effort for sta is " \
				 "aifs=%u, cw_min=%u, cw_max=%u \n",
				priv->edca.params[2].aifns, priv->edca.params[2].cwMin,
				 priv->edca.params[2].cwMax);
		}
#endif
		WSM_EDCA_SET(&priv->edca, 3, 0x0007, 0x000f, 0x03ff,
				0, 0xc8, false);

		ret = wsm_set_edca_params(hw_priv, &priv->edca, priv->if_id);
		if (WARN_ON(ret))
			goto out;

		ret = cw1200_set_uapsd_param(priv, &priv->edca);
		if (WARN_ON(ret))
			goto out;

		memset(priv->bssid, ~0, ETH_ALEN);
		priv->wep_default_key_id = -1;
		priv->cipherType = 0;
		priv->cqm_link_loss_count   = XRADIO_LINK_LOSS_THOLD_DEF;
		priv->cqm_beacon_loss_count = XRADIO_BSS_LOSS_THOLD_DEF;

		/* Temporary configuration - beacon filter table */
		__cw1200_bf_configure(priv);
#ifdef P2P_MULTIVIF
	}
#endif
out:
	return ret;
}

int cw1200_setup_mac_pvif(struct cw1200_vif *priv)
{
	int ret = 0;
	/* NOTE: There is a bug in FW: it reports signal
	* as RSSI if RSSI subscription is enabled.
	* It's not enough to set WSM_RCPI_RSSI_USE_RSSI. */
	/* NOTE2: RSSI based reports have been switched to RCPI, since
	* FW has a bug and RSSI reported values are not stable,
	* what can leads to signal level oscilations in user-end applications */
	struct wsm_rcpi_rssi_threshold threshold = {
		.rssiRcpiMode = WSM_RCPI_RSSI_THRESHOLD_ENABLE |
		WSM_RCPI_RSSI_DONT_USE_UPPER |
		WSM_RCPI_RSSI_DONT_USE_LOWER,
		.rollingAverageCount = 16,
	};
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	/* Remember the decission here to make sure, we will handle
	 * the RCPI/RSSI value correctly on WSM_EVENT_RCPI_RSS */
	if (threshold.rssiRcpiMode & WSM_RCPI_RSSI_USE_RSSI)
		priv->cqm_use_rssi = true;


	/* Configure RSSI/SCPI reporting as RSSI. */
#ifdef P2P_MULTIVIF
	ret = wsm_set_rcpi_rssi_threshold(priv->hw_priv, &threshold, priv->if_id ? 1 : 0);
#else
	ret = wsm_set_rcpi_rssi_threshold(priv->hw_priv, &threshold, priv->if_id);
#endif
	return ret;
}

void cw1200_rem_chan_timeout(struct work_struct *work)
{
	struct cw1200_common *hw_priv =
		container_of(work, struct cw1200_common, rem_chan_timeout.work);
	int ret, if_id;
	struct cw1200_vif *priv;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

#ifdef TES_P2P_0002_ROC_RESTART
	if(TES_P2P_0002_state == TES_P2P_0002_STATE_GET_PKTID) {
		sta_printk(XRADIO_DBG_WARN, "[Restart rem_chan_timeout:Timeout]\n");
		return;
	}
#endif

	if (atomic_read(&hw_priv->remain_on_channel) == 0) {
		return;
	}
	ieee80211_remain_on_channel_expired(hw_priv->hw);

	mutex_lock(&hw_priv->conf_mutex);
	if_id = hw_priv->roc_if_id;
#ifdef ROC_DEBUG
	sta_printk(XRADIO_DBG_ERROR, "ROC TO IN %d\n", if_id);
#endif
	priv = __xrwl_hwpriv_to_vifpriv(hw_priv, if_id);
	ret = WARN_ON(__cw1200_flush(hw_priv, false, if_id));
	if (!ret) {
		cw1200_disable_listening(priv);
	}
	atomic_set(&hw_priv->remain_on_channel, 0);
	hw_priv->roc_if_id = -1;

#ifdef ROC_DEBUG
	sta_printk(XRADIO_DBG_ERROR, "ROC TO OUT %d\n", if_id);
#endif

	mutex_unlock(&hw_priv->conf_mutex);
	up(&hw_priv->scan.lock);
}
const u8 *cw1200_get_ie(u8 *start, size_t len, u8 ie)
{
	u8 *end, *pos;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	pos = start;
	if (pos == NULL)
		return NULL;
	end = pos + len;

	while (pos + 1 < end) {
		if (pos + 2 + pos[1] > end)
			break;
		if (pos[0] == ie)
			return pos;
		pos += 2 + pos[1];
	}

	return NULL;
}

/**
 * cw1200_set_macaddrfilter -called when tesmode command
 * is for setting mac address filter
 *
 * @hw: the hardware
 * @data: incoming data
 *
 * Returns: 0 on success or non zero value on failure
 */
int cw1200_set_macaddrfilter(struct cw1200_common *hw_priv, struct cw1200_vif *priv, u8 *data)
{
	struct wsm_mac_addr_filter *mac_addr_filter =  NULL;
	struct wsm_mac_addr_info *addr_info = NULL;
	u8 action_mode = 0, no_of_mac_addr = 0, i = 0;
	int ret = 0;
	u16 macaddrfiltersize = 0;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	/* Retrieving Action Mode */
	action_mode = data[0];
	/* Retrieving number of address entries */
	no_of_mac_addr = data[1];

	addr_info = (struct wsm_mac_addr_info *)&data[2];

	/* Computing sizeof Mac addr filter */
	macaddrfiltersize =  sizeof(*mac_addr_filter) + \
			(no_of_mac_addr * sizeof(struct wsm_mac_addr_info));

	mac_addr_filter = xr_kzalloc(macaddrfiltersize, false);
	if (!mac_addr_filter) {
		ret = -ENOMEM;
		goto exit_p;
	}
	mac_addr_filter->action_mode = action_mode;
	mac_addr_filter->numfilter = no_of_mac_addr;

	for (i = 0; i < no_of_mac_addr; i++) {
		mac_addr_filter->macaddrfilter[i].address_mode = \
						addr_info[i].address_mode;
		memcpy(mac_addr_filter->macaddrfilter[i].MacAddr, \
				addr_info[i].MacAddr , ETH_ALEN);
		mac_addr_filter->macaddrfilter[i].filter_mode = \
						addr_info[i].filter_mode;
	}
	ret = WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_MAC_ADDR_FILTER, \
					 mac_addr_filter, macaddrfiltersize, priv->if_id));

	kfree(mac_addr_filter);
exit_p:
	return ret;
}

#if 0
/**
 * cw1200_set_multicastaddrfilter -called when tesmode command
 * is for setting the ipv4 address filter
 *
 * @hw: the hardware
 * @data: incoming data
 *
 * Returns: 0 on success or non zero value on failure
 */
static int cw1200_set_multicastfilter(struct cw1200_common *hw_priv, struct cw1200_vif *priv, u8 *data)
{
	u8 i = 0;
	int ret = 0;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	memset(&priv->multicast_filter, 0, sizeof(priv->multicast_filter));
	priv->multicast_filter.enable = (u32)data[0];
	priv->multicast_filter.numOfAddresses = (u32)data[1];

	for (i = 0; i < priv->multicast_filter.numOfAddresses; i++) {
		memcpy(&priv->multicast_filter.macAddress[i], \
			   &data[2+(i*ETH_ALEN)], ETH_ALEN);
	}
	/* Configure the multicast mib in case of drop all multicast */
	if (priv->multicast_filter.enable != 2)
		return ret;

	ret = wsm_write_mib(hw_priv, WSM_MIB_ID_DOT11_GROUP_ADDRESSES_TABLE, \
		&priv->multicast_filter, sizeof(priv->multicast_filter), priv->if_id);

	return ret;
}
#endif

#ifdef IPV6_FILTERING
/**
 * cw1200_set_ipv6addrfilter -called when tesmode command
 * is for setting the ipv6 address filter
 *
 * @hw: the hardware
 * @data: incoming data
 * @if_id: interface id
 *
 * Returns: 0 on success or non zero value on failure
 */
static int cw1200_set_ipv6addrfilter(struct ieee80211_hw *hw,
				     u8 *data, int if_id)
{
	struct cw1200_common *hw_priv = (struct cw1200_common *) hw->priv;
	struct wsm_ipv6_filter  *ipv6_filter =  NULL;
	struct ipv6_addr_info *ipv6_info = NULL;
	u8 action_mode = 0, no_of_ip_addr = 0, i = 0, ret = 0;
	u16 ipaddrfiltersize = 0;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	/* Retrieving Action Mode */
	action_mode = data[0];
	/* Retrieving number of ipv4 address entries */
	no_of_ip_addr = data[1];

	ipv6_info = (struct ipv6_addr_info *)&data[2];

	/* Computing sizeof Mac addr filter */
	ipaddrfiltersize =  sizeof(*ipv6_filter) + \
			(no_of_ip_addr * sizeof(struct wsm_ip6_addr_info));


	ipv6_filter = xr_kzalloc(ipaddrfiltersize, false);
	if (!ipv6_filter) {
		ret = -ENOMEM;
		goto exit_p;
	}
	ipv6_filter->action_mode = action_mode;
	ipv6_filter->numfilter = no_of_ip_addr;

	for (i = 0; i < no_of_ip_addr; i++) {
		ipv6_filter->ipv6filter[i].address_mode = \
					ipv6_info[i].address_mode;
		ipv6_filter->ipv6filter[i].filter_mode = \
					ipv6_info[i].filter_mode;
		memcpy(ipv6_filter->ipv6filter[i].ipv6, \
					(u8 *)(ipv6_info[i].ipv6), 16);
	}

	ret = WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_IP_IPV6_ADDR_FILTER, \
					 ipv6_filter, ipaddrfiltersize, \
					 if_id));

	kfree(ipv6_filter);
exit_p:
	return ret;
}
#endif /*IPV6_FILTERING*/

/**
 * cw1200_set_data_filter -configure data filter in device
*
 * @hw: the hardware
 * @vif: vif
 * @data: incoming data
 * @len: incoming data length
 *
 */
void cw1200_set_data_filter(struct ieee80211_hw *hw,
			   struct ieee80211_vif *vif,
			   void *data, int len)
{
	int ret = 0;
	struct cw1200_vif *priv = xrwl_get_vif_from_ieee80211(vif);
	int filter_id;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	if (!data) {
		ret = -EINVAL;
		goto exit_p;
	}
	filter_id=*((enum cw1200_data_filterid*)data);

	switch (filter_id) {
#ifdef IPV6_FILTERING
	case IPV6ADDR_FILTER_ID:
		ret = cw1200_set_ipv6addrfilter(hw, \
			&((u8 *)data)[4], priv->if_id);
		break;
#endif /*IPV6_FILTERING*/
	default:
		ret = -EINVAL;
		break;
	}
exit_p:

	 return ;
}

/**
 * cw1200_set_arpreply -called for creating and
 * configuring arp response template frame
 *
 * @hw: the hardware
 *
 * Returns: 0 on success or non zero value on failure
 */
int cw1200_set_arpreply(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct cw1200_vif *priv = xrwl_get_vif_from_ieee80211(vif);
	struct cw1200_common *hw_priv = (struct cw1200_common *)hw->priv;
	u32 framehdrlen, encrypthdr, encrypttailsize, framebdylen = 0;
	bool encrypt = false;
	int ret = 0;
	u8 *template_frame = NULL;
	struct ieee80211_hdr_3addr *dot11hdr = NULL;
	struct ieee80211_snap_hdr *snaphdr = NULL;
	struct arphdr *arp_hdr = NULL;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	template_frame = xr_kzalloc(MAX_ARP_REPLY_TEMPLATE_SIZE, false);
	if (!template_frame) {
		sta_printk(XRADIO_DBG_ERROR, "Template frame memory failed\n");
		ret = -ENOMEM;
		goto exit_p;
	}
	dot11hdr = (struct ieee80211_hdr_3addr *)&template_frame[4];
	
	framehdrlen = sizeof(*dot11hdr);
	if ((priv->vif->type == NL80211_IFTYPE_AP) && priv->vif->p2p)
	        priv->cipherType = WLAN_CIPHER_SUITE_CCMP;
	switch (priv->cipherType) {
	
	case WLAN_CIPHER_SUITE_WEP40:
	case WLAN_CIPHER_SUITE_WEP104:
		sta_printk(XRADIO_DBG_NIY, "WEP\n");
		encrypthdr = WEP_ENCRYPT_HDR_SIZE;
		encrypttailsize = WEP_ENCRYPT_TAIL_SIZE;
		encrypt = 1;
		break;
	
	
	case WLAN_CIPHER_SUITE_TKIP:
		sta_printk(XRADIO_DBG_NIY, "WPA\n");
		encrypthdr = WPA_ENCRYPT_HDR_SIZE;
		encrypttailsize = WPA_ENCRYPT_TAIL_SIZE;
		encrypt = 1;
		break;
	
	case WLAN_CIPHER_SUITE_CCMP:
		sta_printk(XRADIO_DBG_NIY, "WPA2\n");
		encrypthdr = WPA2_ENCRYPT_HDR_SIZE;
		encrypttailsize = WPA2_ENCRYPT_TAIL_SIZE;
		encrypt = 1;
		break;
	
	case WLAN_CIPHER_SUITE_SMS4:
		sta_printk(XRADIO_DBG_NIY, "WAPI\n");
		encrypthdr = WAPI_ENCRYPT_HDR_SIZE;
		encrypttailsize = WAPI_ENCRYPT_TAIL_SIZE;
		encrypt = 1;
		break;
	
	default:
		encrypthdr = 0;
		encrypttailsize = 0;
		encrypt = 0;
		break;
	}

	framehdrlen += encrypthdr;
	/* Filling the 802.11 Hdr */
	dot11hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA);
	if (priv->vif->type == NL80211_IFTYPE_STATION)
		dot11hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_TODS);
	else
		dot11hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_FROMDS);
	
	if (encrypt)
		dot11hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_WEP);
	
	if (priv->vif->bss_conf.qos) {
		sta_printk(XRADIO_DBG_NIY, "QOS Enabled\n");
		dot11hdr->frame_control |= cpu_to_le16(IEEE80211_QOS_DATAGRP);
		*(u16 *)(dot11hdr + 1) = 0x0;
		framehdrlen += 2;
	} else {
		dot11hdr->frame_control |= cpu_to_le16(IEEE80211_STYPE_DATA);
	}
	
	memcpy(dot11hdr->addr1, priv->vif->bss_conf.bssid, ETH_ALEN);
	memcpy(dot11hdr->addr2, priv->vif->addr, ETH_ALEN);
	memcpy(dot11hdr->addr3, priv->vif->bss_conf.bssid, ETH_ALEN);
	
	/* Filling the LLC/SNAP Hdr */
	snaphdr = (struct ieee80211_snap_hdr *)((u8 *)dot11hdr + framehdrlen);
	memcpy(snaphdr, (struct ieee80211_snap_hdr *)rfc1042_header, \
	        sizeof(*snaphdr));
	*(u16 *)(++snaphdr) = cpu_to_be16(ETH_P_ARP);
	/* Updating the framebdylen with snaphdr and LLC hdr size */
	framebdylen = sizeof(*snaphdr) + 2;
	
	/* Filling the ARP Reply Payload */
	arp_hdr = (struct arphdr *)((u8 *)dot11hdr + framehdrlen + framebdylen);
	arp_hdr->ar_hrd = cpu_to_be16(ARPHRD_ETHER);
	arp_hdr->ar_pro = cpu_to_be16(ETH_P_IP);
	arp_hdr->ar_hln = ETH_ALEN;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = cpu_to_be16(ARPOP_REPLY);
	
	/* Updating the frmbdylen with Arp Reply Hdr and Arp payload size(20) */
	framebdylen += sizeof(*arp_hdr) + 20;
	
	/* Updating the framebdylen with Encryption Tail Size */
	framebdylen += encrypttailsize;
	
	/* Filling the Template Frame Hdr */
	template_frame[0] = WSM_FRAME_TYPE_ARP_REPLY; /* Template frame type */
	template_frame[1] = 0xFF; /* Rate to be fixed */
	((u16 *)&template_frame[2])[0] = framehdrlen + framebdylen;
	
	ret = WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_TEMPLATE_FRAME, \
	                              template_frame, (framehdrlen+framebdylen+4), 
	                              priv->if_id));
	kfree(template_frame);
exit_p:
	return ret;
}

#ifdef ROAM_OFFLOAD
/**
 * cw1200_testmode_event -send asynchronous event
 * to userspace
 *
 * @wiphy: the wiphy
 * @msg_id: XR msg ID
 * @data: data to be sent
 * @len: data length
 * @gfp: allocation flag
 *
 * Returns: 0 on success or non zero value on failure
 */
int cw1200_testmode_event(struct wiphy *wiphy, const u32 msg_id,
                          const void *data, int len, gfp_t gfp)
{
	struct sk_buff *skb = NULL;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	skb = cfg80211_testmode_alloc_event_skb(wiphy, 
	      nla_total_size(len+sizeof(msg_id)), gfp);

	if (!skb)
		return -ENOMEM;

	cfg80211_testmode_event(skb, gfp);
	return 0;
}
#endif /*ROAM_OFFLOAD*/

#ifdef IPV6_FILTERING
/**
 * cw1200_set_na -called for creating and
 * configuring NDP Neighbor Advertisement (NA) template frame
 *
 * @hw: the hardware
 * @vif: vif
 *
 * Returns: 0 on success or non zero value on failure
 */
int cw1200_set_na(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct cw1200_vif *priv = xrwl_get_vif_from_ieee80211(vif);
	struct cw1200_common *hw_priv = (struct cw1200_common *)hw->priv;
	u32 framehdrlen, encrypthdr, encrypttailsize, framebdylen = 0;
	bool encrypt = false;
	int ret = 0;
	u8 *template_frame = NULL;
	struct ieee80211_hdr_3addr *dot11hdr = NULL;
	struct ieee80211_snap_hdr *snaphdr = NULL;
	struct ipv6hdr *ipv6_hdr = NULL;
	struct icmp6hdr *icmp6_hdr = NULL;
	struct nd_msg *na = NULL;
	struct nd_opt_hdr *opt_hdr = NULL;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	template_frame = xr_kzalloc(MAX_NEIGHBOR_ADVERTISEMENT_TEMPLATE_SIZE, false);
	if (!template_frame) {
		sta_printk(XRADIO_DBG_ERROR, "Template frame memory failed\n");
		ret = -ENOMEM;
		goto exit_p;
	}
	dot11hdr = (struct ieee80211_hdr_3addr *)&template_frame[4];

	framehdrlen = sizeof(*dot11hdr);
        if ((priv->vif->type == NL80211_IFTYPE_AP) && priv->vif->p2p)
		priv->cipherType = WLAN_CIPHER_SUITE_CCMP;
	switch (priv->cipherType) {

	case WLAN_CIPHER_SUITE_WEP40:
	case WLAN_CIPHER_SUITE_WEP104:
		sta_printk(XRADIO_DBG_NIY, "WEP\n");
		encrypthdr = WEP_ENCRYPT_HDR_SIZE;
		encrypttailsize = WEP_ENCRYPT_TAIL_SIZE;
		encrypt = 1;
		break;


	case WLAN_CIPHER_SUITE_TKIP:
		sta_printk(XRADIO_DBG_NIY, "WPA\n");
		encrypthdr = WPA_ENCRYPT_HDR_SIZE;
		encrypttailsize = WPA_ENCRYPT_TAIL_SIZE;
		encrypt = 1;
		break;

	case WLAN_CIPHER_SUITE_CCMP:
		sta_printk(XRADIO_DBG_NIY, "WPA2\n");
		encrypthdr = WPA2_ENCRYPT_HDR_SIZE;
		encrypttailsize = WPA2_ENCRYPT_TAIL_SIZE;
		encrypt = 1;
		break;

	case WLAN_CIPHER_SUITE_SMS4:
		sta_printk(XRADIO_DBG_NIY, "WAPI\n");
		encrypthdr = WAPI_ENCRYPT_HDR_SIZE;
		encrypttailsize = WAPI_ENCRYPT_TAIL_SIZE;
		encrypt = 1;
		break;

	default:
		encrypthdr = 0;
		encrypttailsize = 0;
		encrypt = 0;
		break;
	}

	framehdrlen += encrypthdr;

	/* Filling the 802.11 Hdr */
	dot11hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA);
	if (priv->vif->type == NL80211_IFTYPE_STATION)
		dot11hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_TODS);
	else
		dot11hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_FROMDS);

	if (encrypt)
		dot11hdr->frame_control |= cpu_to_le16(IEEE80211_FCTL_WEP);

	if (priv->vif->bss_conf.qos) {
		sta_printk(XRADIO_DBG_MSG, "QOS Enabled\n");
		dot11hdr->frame_control |= cpu_to_le16(IEEE80211_QOS_DATAGRP);
		/* Filling QOS Control Field */
		 *(u16 *)(dot11hdr + 1) = 0x0;
		 framehdrlen += 2;
	} else {
		dot11hdr->frame_control |= cpu_to_le16(IEEE80211_STYPE_DATA);
	}

	memcpy(dot11hdr->addr1, priv->vif->bss_conf.bssid, ETH_ALEN);
	memcpy(dot11hdr->addr2, priv->vif->addr, ETH_ALEN);
	memcpy(dot11hdr->addr3, priv->vif->bss_conf.bssid, ETH_ALEN);

	/* Filling the LLC/SNAP Hdr */
	snaphdr = (struct ieee80211_snap_hdr *)((u8 *)dot11hdr + framehdrlen);
	memcpy(snaphdr, (struct ieee80211_snap_hdr *)rfc1042_header, \
		sizeof(*snaphdr));
	*(u16 *)(++snaphdr) = cpu_to_be16(ETH_P_IPV6);
	/* Updating the framebdylen with snaphdr and LLC hdr size */
	framebdylen = sizeof(*snaphdr) + 2;

	/* Filling the ipv6 header */
	ipv6_hdr = (struct ipv6hdr *)((u8 *)dot11hdr + framehdrlen + framebdylen);
	ipv6_hdr->version = 6;
	ipv6_hdr->priority = 0;
	ipv6_hdr->payload_len = cpu_to_be16(32); /* ??? check the be or le ??? whether to use cpu_to_be16(32)*/
	ipv6_hdr->nexthdr = 58;
	ipv6_hdr->hop_limit = 255;

	/* Updating the framebdylen with ipv6 Hdr */
	framebdylen += sizeof(*ipv6_hdr);

	/* Filling the Neighbor Advertisement */
	na = (struct nd_msg *)((u8 *)dot11hdr + framehdrlen + framebdylen);
	icmp6_hdr = (struct icmp6hdr *)(&na->icmph);
	icmp6_hdr->icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT;
	icmp6_hdr->icmp6_code = 0;
	/* checksum (2 bytes), RSO fields (4 bytes) and target IP address (16 bytes) shall be filled by firmware */

	/* Filling the target link layer address in the optional field */
	opt_hdr = (struct nd_opt_hdr *)(&na->opt[0]);
	opt_hdr->nd_opt_type = 2;
	opt_hdr->nd_opt_len = 1;
	/* optional target link layer address (6 bytes) shall be filled by firmware */

	/* Updating the framebdylen with the ipv6 payload length */
	framebdylen += 32;

	/* Updating the framebdylen with Encryption Tail Size */
	framebdylen += encrypttailsize;

	/* Filling the Template Frame Hdr */
	template_frame[0] = WSM_FRAME_TYPE_NA; /* Template frame type */
	template_frame[1] = 0xFF; /* Rate to be fixed */
	((u16 *)&template_frame[2])[0] = framehdrlen + framebdylen;

	ret = WARN_ON(wsm_write_mib(hw_priv, WSM_MIB_ID_TEMPLATE_FRAME, \
				template_frame, (framehdrlen+framebdylen+4), \
				priv->if_id));

	kfree(template_frame);

exit_p:
	return ret;
}
#endif /*IPV6_FILTERING*/

#ifdef CONFIG_XRADIO_TESTMODE
/**
 * cw1200_set_snap_frame -Set SNAP frame format
 *
 * @hw: the hardware
 * @data: data frame
 * @len: data length
 *
 * Returns: 0 on success or non zero value on failure
 */
static int cw1200_set_snap_frame(struct ieee80211_hw *hw,
				 u8 *data, int len)
{
	struct xr_msg_set_snap_frame *snap_frame =
		(struct xr_msg_set_snap_frame *) data;
	struct cw1200_common *priv = (struct cw1200_common *) hw->priv;
	u8 frame_len = snap_frame->len;
	u8 *frame = &snap_frame->frame[0];
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	/*
	 * Check length of incoming frame format:
	 * SNAP + SNAP_LEN (u8)
	 */
	if (frame_len + sizeof(snap_frame->len) != len)
		return -EINVAL;

	if (frame_len > 0) {
		priv->test_frame.data = (u8 *) xr_krealloc(priv->test_frame.data,
						sizeof(u8) * frame_len, false);
		if (priv->test_frame.data == NULL) {
			sta_printk(XRADIO_DBG_ERROR, "cw1200_set_snap_frame memory" \
					 "allocation failed");
			priv->test_frame.len = 0;
			return -EINVAL;
		}
		memcpy(priv->test_frame.data, frame, frame_len);
	} else {
		kfree(priv->test_frame.data);
		priv->test_frame.data = NULL;
	}
	priv->test_frame.len = frame_len;
	return 0;
}

#ifdef CONFIG_XRADIO_TESTMODE
/**
 * cw1200_set_txqueue_params -Set txqueue params after successful TSPEC negotiation
 *
 * @hw: the hardware
 * @data: data frame
 * @len: data length
 *
 * Returns: 0 on success or non zero value on failure
 */
static int cw1200_set_txqueue_params(struct ieee80211_hw *hw,
				     u8 *data, int len)
{
	struct xr_msg_set_txqueue_params *txqueue_params =
		(struct xr_msg_set_txqueue_params *) data;
	struct cw1200_common *hw_priv = (struct cw1200_common *) hw->priv;
	struct cw1200_vif *priv;
	/* Interface ID is hard coded here, as interface is not
         * passed in testmode command.
         * Also it is assumed here that STA will be on interface
         * 0 always.
         */

	int if_id = 0;
	u16 queueId = cw1200_priority_to_queueId[txqueue_params->user_priority];
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	priv = xrwl_hwpriv_to_vifpriv(hw_priv, if_id);

	if (unlikely(!priv)) {
		sta_printk(XRADIO_DBG_ERROR, "%s: Warning Priv is Null\n",
			   __func__);
		return 0;
	}
	spin_unlock(&priv->vif_lock);

	/* Default Ack policy is WSM_ACK_POLICY_NORMAL */
	WSM_TX_QUEUE_SET(&priv->tx_queue_params,
			queueId,
			WSM_ACK_POLICY_NORMAL,
			txqueue_params->medium_time,
			txqueue_params->expiry_time);
	return WARN_ON(wsm_set_tx_queue_params(hw_priv,
			&priv->tx_queue_params.params[queueId], queueId,
			priv->if_id));
}
#endif /*CONFIG_XRADIO_TESTMODE*/

/**
 * cw1200_tesmode_reply -called inside a testmode command
 * handler to send a response to user space
 *
 * @wiphy: the wiphy
 * @data: data to be send to user space
 * @len: data length
 *
 * Returns: 0 on success or non zero value on failure
 */
static int cw1200_tesmode_reply(struct wiphy *wiphy,
				const void *data, int len)
{
	int ret = 0;
	struct sk_buff *skb = NULL;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	skb = cfg80211_testmode_alloc_reply_skb(wiphy, nla_total_size(len));

	if (!skb)
		return -ENOMEM;

	ret = nla_put(skb, XR_TM_MSG_DATA, len, data);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}

	return cfg80211_testmode_reply(skb);
}

/**
 * cw1200_tesmode_event -send asynchronous event
 * to userspace
 *
 * @wiphy: the wiphy
 * @msg_id: XR msg ID
 * @data: data to be sent
 * @len: data length
 * @gfp: allocation flag
 *
 * Returns: 0 on success or non zero value on failure
 */
int cw1200_tesmode_event(struct wiphy *wiphy, const u32 msg_id,
			 const void *data, int len, gfp_t gfp)
{
	struct sk_buff *skb = NULL;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	skb = cfg80211_testmode_alloc_event_skb(wiphy,
	      nla_total_size(len+sizeof(msg_id)), gfp);
	if (!skb)
		return -ENOMEM;

	NLA_PUT_U32(skb, XR_TM_MSG_ID, msg_id);
	if (data)
		NLA_PUT(skb, XR_TM_MSG_DATA, len, data);

	cfg80211_testmode_event(skb, gfp);
	return 0;
nla_put_failure:
	kfree_skb(skb);
	return -ENOBUFS;
}

/**
 * example function for test purposes
 * sends both: synchronous reply and asynchronous event
 */
static int cw1200_test(struct ieee80211_hw *hw,
		       void *data, int len)
{
	struct xr_msg_test_t *test_p;
	struct xr_reply_test_t reply;
	struct xr_event_test_t event;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	if (sizeof(struct xr_msg_test_t)  != len)
		return -EINVAL;

	test_p = (struct xr_msg_test_t *) data;

	reply.dummy = test_p->dummy + 10;

	event.dummy = test_p->dummy + 20;

	if (cw1200_tesmode_event(hw->wiphy, XR_MSG_EVENT_TEST,
		&event, sizeof(event), GFP_KERNEL))
		return -1;

	return cw1200_tesmode_reply(hw->wiphy, &reply, sizeof(reply));
}

/**
 * cw1200_get_tx_power_level - send tx power level
 * to userspace
 *
 * @hw: the hardware
 *
 * Returns: 0 on success or non zero value on failure
 */
int cw1200_get_tx_power_level(struct ieee80211_hw *hw)
{
	struct cw1200_common *hw_priv = hw->priv;
	int get_power = 0;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	get_power = hw_priv->output_power;
	sta_printk(XRADIO_DBG_MSG, "%s: Power set on Device : %d",
		__func__, get_power);
	return cw1200_tesmode_reply(hw->wiphy, &get_power, sizeof(get_power));
}

/**
 * cw1200_get_tx_power_range- send tx power range
 * to userspace for each band
 *
 * @hw: the hardware
 *
 * Returns: 0 on success or non zero value on failure
 */
int cw1200_get_tx_power_range(struct ieee80211_hw *hw)
{
	struct cw1200_common *hw_priv = hw->priv;
	struct wsm_tx_power_range txPowerRange[2];
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	size_t len = sizeof(txPowerRange);
	memcpy(txPowerRange, hw_priv->txPowerRange, len);
	return cw1200_tesmode_reply(hw->wiphy, txPowerRange, len);
}

/**
 * cw1200_set_advance_scan_elems -Set Advcance Scan
 * elements
 * @hw: the hardware
 * @data: data frame
 * @len: data length
 *
 * Returns: 0 on success or non zero value on failure
 */
static int cw1200_set_advance_scan_elems(struct ieee80211_hw *hw,
				 u8 *data, int len)
{
	struct advance_scan_elems *scan_elems =
		(struct advance_scan_elems *) data;
	struct cw1200_common *hw_priv = (struct cw1200_common *) hw->priv;
	size_t elems_len = sizeof(struct advance_scan_elems);
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	if (elems_len != len)
		return -EINVAL;

	scan_elems = (struct advance_scan_elems *) data;

	/* Locks required to prevent simultaneous scan */
	down(&hw_priv->scan.lock);
	mutex_lock(&hw_priv->conf_mutex);

	hw_priv->advanceScanElems.scanMode = scan_elems->scanMode;
	hw_priv->advanceScanElems.duration = scan_elems->duration;
	hw_priv->enable_advance_scan = true;

	mutex_unlock(&hw_priv->conf_mutex);
	up(&hw_priv->scan.lock);

	return 0;
}

/**
 * cw1200_set_power_save -Set Power Save
 * elements
 * @hw: the hardware
 * @data: data frame
 * @len: data length
 *
 * Returns: 0 on success or non zero value on failure
 */
static int cw1200_set_power_save(struct ieee80211_hw *hw,
				 u8 *data, int len)
{
	struct power_save_elems *ps_elems =
		(struct power_save_elems *) data;
	struct cw1200_common *hw_priv = (struct cw1200_common *) hw->priv;
	size_t elems_len = sizeof(struct power_save_elems);
	struct cw1200_vif *priv;
	int if_id = 0;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	/* Interface ID is hard coded here, as interface is not
	* passed in testmode command.
	* Also it is assumed here that STA will be on interface
	* 0 always. */

	if (elems_len != len)
		return -EINVAL;

	priv = xrwl_hwpriv_to_vifpriv(hw_priv, if_id);

	if (unlikely(!priv)) {
		sta_printk(XRADIO_DBG_ERROR, "%s: Warning Priv is Null\n",
			   __func__);
		return 0;
	}

	spin_unlock(&priv->vif_lock);
	mutex_lock(&hw_priv->conf_mutex);

	ps_elems = (struct power_save_elems *) data;

	if (ps_elems->powerSave == 1)
		priv->user_pm_mode = WSM_PSM_PS;
	else
		priv->user_pm_mode = WSM_PSM_FAST_PS;

	sta_printk(XRADIO_DBG_MSG, "Aid: %d, Joined: %s, Powersave: %s\n",
		priv->bss_params.aid,
		priv->join_status == XRADIO_JOIN_STATUS_STA ? "yes" : "no",
		priv->user_pm_mode == WSM_PSM_ACTIVE ? "WSM_PSM_ACTIVE" :
		priv->user_pm_mode == WSM_PSM_PS ? "WSM_PSM_PS" :
		priv->user_pm_mode == WSM_PSM_FAST_PS ? "WSM_PSM_FAST_PS" : "UNKNOWN");
	if (priv->join_status == XRADIO_JOIN_STATUS_STA &&
			priv->bss_params.aid &&
			priv->setbssparams_done &&
			priv->filter4.enable) {
		priv->powersave_mode.pmMode = priv->user_pm_mode;
		cw1200_set_pm(priv, &priv->powersave_mode);
	}
	else
		priv->user_power_set_true = ps_elems->powerSave;
	mutex_unlock(&hw_priv->conf_mutex);
	return 0;
}
/**
 * cw1200_start_stop_tsm - starts/stops collecting TSM
 *
 * @hw: the hardware
 * @data: data frame
 *
 * Returns: 0 on success or non zero value on failure
 */
int cw1200_start_stop_tsm(struct ieee80211_hw *hw, void *data)
{
	struct xr_msg_start_stop_tsm *start_stop_tsm =
		(struct xr_msg_start_stop_tsm *) data;
	struct cw1200_common *hw_priv = hw->priv;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	hw_priv->start_stop_tsm.start = start_stop_tsm->start;
	hw_priv->start_stop_tsm.up = start_stop_tsm->up;
	hw_priv->start_stop_tsm.packetization_delay =
		start_stop_tsm->packetization_delay;
	sta_printk(XRADIO_DBG_MSG, "%s: start : %u: up : %u",
		__func__, hw_priv->start_stop_tsm.start,
		hw_priv->start_stop_tsm.up);
	hw_priv->tsm_info.ac = cw1200_1d_to_ac[start_stop_tsm->up];

	if (!hw_priv->start_stop_tsm.start) {
		spin_lock_bh(&hw_priv->tsm_lock);
		memset(&hw_priv->tsm_stats, 0, sizeof(hw_priv->tsm_stats));
		memset(&hw_priv->tsm_info, 0, sizeof(hw_priv->tsm_info));
		spin_unlock_bh(&hw_priv->tsm_lock);
	}
	return 0;
}

/**
 * cw1200_get_tsm_params - Retrieves TSM parameters
 *
 * @hw: the hardware
 *
 * Returns: TSM parameters collected
 */
int cw1200_get_tsm_params(struct ieee80211_hw *hw)
{
	struct cw1200_common *hw_priv = hw->priv;
	struct xr_tsm_stats tsm_stats;
	u32 pkt_count;
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	spin_lock_bh(&hw_priv->tsm_lock);
	pkt_count = hw_priv->tsm_stats.txed_msdu_count -
			 hw_priv->tsm_stats.msdu_discarded_count;
	if (pkt_count) {
		hw_priv->tsm_stats.avg_q_delay =
			hw_priv->tsm_info.sum_pkt_q_delay/(pkt_count * 1000);
		hw_priv->tsm_stats.avg_transmit_delay =
			hw_priv->tsm_info.sum_media_delay/pkt_count;
	} else {
		hw_priv->tsm_stats.avg_q_delay = 0;
		hw_priv->tsm_stats.avg_transmit_delay = 0;
	}
	sta_printk(XRADIO_DBG_MSG, "%s: Txed MSDU count : %u",
		__func__, hw_priv->tsm_stats.txed_msdu_count);
	sta_printk(XRADIO_DBG_MSG, "%s: Average queue delay : %u",
			__func__, hw_priv->tsm_stats.avg_q_delay);
	sta_printk(XRADIO_DBG_MSG, "%s: Average transmit delay : %u",
			__func__, hw_priv->tsm_stats.avg_transmit_delay);
	memcpy(&tsm_stats, &hw_priv->tsm_stats, sizeof(hw_priv->tsm_stats));
	/* Reset the TSM statistics */
	memset(&hw_priv->tsm_stats, 0, sizeof(hw_priv->tsm_stats));
	hw_priv->tsm_info.sum_pkt_q_delay = 0;
	hw_priv->tsm_info.sum_media_delay = 0;
	spin_unlock_bh(&hw_priv->tsm_lock);
	return cw1200_tesmode_reply(hw->wiphy, &tsm_stats,
				     sizeof(hw_priv->tsm_stats));
}

/**
 * cw1200_get_roam_delay - Retrieves roam delay
 *
 * @hw: the hardware
 *
 * Returns: Returns the last measured roam delay
 */
int cw1200_get_roam_delay(struct ieee80211_hw *hw)
{
	struct cw1200_common *hw_priv = hw->priv;
	u16 roam_delay = hw_priv->tsm_info.roam_delay / 1000;
	sta_printk(XRADIO_DBG_MSG, "%s: Roam delay : %u",
		__func__, roam_delay);

	spin_lock_bh(&hw_priv->tsm_lock);
	hw_priv->tsm_info.roam_delay = 0;
	hw_priv->tsm_info.use_rx_roaming = 0;
	spin_unlock_bh(&hw_priv->tsm_lock);
	return cw1200_tesmode_reply(hw->wiphy, &roam_delay, sizeof(u16));
}

/**
 * cw1200_testmode_cmd -called when tesmode command
 * reaches cw1200
 *
 * @hw: the hardware
 * @data: incoming data
 * @len: incoming data length
 *
 * Returns: 0 on success or non zero value on failure
 */
int cw1200_testmode_cmd(struct ieee80211_hw *hw, void *data, int len)
{
	int ret = 0;
	struct nlattr *type_p = nla_find(data, len, XR_TM_MSG_ID);
	struct nlattr *data_p = nla_find(data, len, XR_TM_MSG_DATA);
	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);

	if (!type_p || !data_p)
		return -EINVAL;

	sta_printk(XRADIO_DBG_MSG,  "%s: type: %i",
	           __func__, nla_get_u32(type_p));

	switch (nla_get_u32(type_p)) {
	case XR_MSG_TEST:
		ret = cw1200_test(hw,
			nla_data(data_p), nla_len(data_p));
		break;
	case XR_MSG_SET_SNAP_FRAME:
		ret = cw1200_set_snap_frame(hw, (u8 *) nla_data(data_p),
			nla_len(data_p));
		break;
	case XR_MSG_GET_TX_POWER_LEVEL:
		ret = cw1200_get_tx_power_level(hw);
		break;
	case XR_MSG_GET_TX_POWER_RANGE:
		ret = cw1200_get_tx_power_range(hw);
		break;
	case XR_MSG_SET_ADVANCE_SCAN_ELEMS:
		ret = cw1200_set_advance_scan_elems(hw, (u8 *) nla_data(data_p),
			nla_len(data_p));
		break;
	case XR_MSG_SET_TX_QUEUE_PARAMS:
		ret = cw1200_set_txqueue_params(hw, (u8 *) nla_data(data_p),
			nla_len(data_p));
		break;
	case XR_MSG_GET_TSM_PARAMS:
		ret = cw1200_get_tsm_params(hw);
		break;
	case XR_MSG_START_STOP_TSM:
		ret = cw1200_start_stop_tsm(hw, (u8 *) nla_data(data_p));
		break;
	case XR_MSG_GET_ROAM_DELAY:
		ret = cw1200_get_roam_delay(hw);
		break;
	case XR_MSG_SET_POWER_SAVE:
		ret = cw1200_set_power_save(hw, (u8 *) nla_data(data_p),
			nla_len(data_p));
		break;
	default:
		break;
	}
	return ret;
}
#endif /* CONFIG_XRADIO_TESTMODE */

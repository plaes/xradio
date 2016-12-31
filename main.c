/*
 * Main code of XRadio drivers
 *
 * Copyright (c) 2013, XRadio
 * Author: XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/*Linux version 3.4.0 compilation*/
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/firmware.h>
#include <linux/etherdevice.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <net/mac80211.h>

#include "platform.h"
#include "cw1200.h"
#include "txrx.h"
#include "hwbus.h"
#include "fwio.h"
#include "hwio.h"
#include "bh.h"
#include "sta.h"
#include "ap.h"
#include "scan.h"
#include "pm.h"
#include "xr_version.h"

MODULE_AUTHOR("XRadioTech");
MODULE_DESCRIPTION("XRadioTech WLAN driver core");
MODULE_LICENSE("GPL");
MODULE_ALIAS("cw1200_core");

char *drv_version   = XRADIO_VERSION;
char *drv_buildtime = __DATE__" "__TIME__;

#define XRADIO_MAC_CHARLEN 18
#ifdef XRADIO_MACPARAM_HEX
/* insmod cw1200_wlan.ko macaddr=0xDC,0x44,0x6D,0x00,0x00,0x00 */
static u8 cw1200_macaddr_param[ETH_ALEN] = { 0x0 };
module_param_array_named(macaddr, cw1200_macaddr_param, byte, NULL, S_IRUGO);
#else
/* insmod cw1200_wlan.ko macaddr=xx:xx:xx:xx:xx:xx */
static char *cw1200_macaddr_param = NULL;
module_param_named(macaddr, cw1200_macaddr_param, charp, S_IRUGO);
#endif

MODULE_PARM_DESC(macaddr, "First MAC address");

#ifdef HW_RESTART
void cw1200_restart_work(struct work_struct *work);
#endif

/* TODO: use rates and channels from the device */
#define RATETAB_ENT(_rate, _rateid, _flags)		\
	{						\
		.bitrate  = (_rate),    \
		.hw_value = (_rateid),  \
		.flags    = (_flags),   \
	}

static struct ieee80211_rate cw1200_rates[] = {
	RATETAB_ENT(10,  0,   0),
	RATETAB_ENT(20,  1,   0),
	RATETAB_ENT(55,  2,   0),
	RATETAB_ENT(110, 3,   0),
	RATETAB_ENT(60,  6,  0),
	RATETAB_ENT(90,  7,  0),
	RATETAB_ENT(120, 8,  0),
	RATETAB_ENT(180, 9,  0),
	RATETAB_ENT(240, 10, 0),
	RATETAB_ENT(360, 11, 0),
	RATETAB_ENT(480, 12, 0),
	RATETAB_ENT(540, 13, 0),
};

static struct ieee80211_rate cw1200_mcs_rates[] = {
	RATETAB_ENT(65,  14, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(130, 15, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(195, 16, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(260, 17, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(390, 18, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(520, 19, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(585, 20, IEEE80211_TX_RC_MCS),
	RATETAB_ENT(650, 21, IEEE80211_TX_RC_MCS),
};

#define cw1200_g_rates      (cw1200_rates + 0)
#define cw1200_a_rates      (cw1200_rates + 4)
#define cw1200_n_rates      (cw1200_mcs_rates)

#define cw1200_g_rates_size (ARRAY_SIZE(cw1200_rates))
#define cw1200_a_rates_size (ARRAY_SIZE(cw1200_rates) - 4)
#define cw1200_n_rates_size (ARRAY_SIZE(cw1200_mcs_rates))

#define CHAN2G(_channel, _freq, _flags) {   \
	.band             = IEEE80211_BAND_2GHZ,  \
	.center_freq      = (_freq),              \
	.hw_value         = (_channel),           \
	.flags            = (_flags),             \
	.max_antenna_gain = 0,                    \
	.max_power        = 30,                   \
}

#define CHAN5G(_channel, _flags) {   \
	.band             = IEEE80211_BAND_5GHZ,     \
	.center_freq      = 5000 + (5 * (_channel)), \
	.hw_value         = (_channel),              \
	.flags            = (_flags),                \
	.max_antenna_gain = 0,                       \
	.max_power        = 30,                      \
}

static struct ieee80211_channel cw1200_2ghz_chantable[] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0),
};

#ifdef CONFIG_XRADIO_5GHZ_SUPPORT
static struct ieee80211_channel cw1200_5ghz_chantable[] = {
	CHAN5G(34, 0),		CHAN5G(36, 0),
	CHAN5G(38, 0),		CHAN5G(40, 0),
	CHAN5G(42, 0),		CHAN5G(44, 0),
	CHAN5G(46, 0),		CHAN5G(48, 0),
	CHAN5G(52, 0),		CHAN5G(56, 0),
	CHAN5G(60, 0),		CHAN5G(64, 0),
	CHAN5G(100, 0),		CHAN5G(104, 0),
	CHAN5G(108, 0),		CHAN5G(112, 0),
	CHAN5G(116, 0),		CHAN5G(120, 0),
	CHAN5G(124, 0),		CHAN5G(128, 0),
	CHAN5G(132, 0),		CHAN5G(136, 0),
	CHAN5G(140, 0),		CHAN5G(149, 0),
	CHAN5G(153, 0),		CHAN5G(157, 0),
	CHAN5G(161, 0),		CHAN5G(165, 0),
	CHAN5G(184, 0),		CHAN5G(188, 0),
	CHAN5G(192, 0),		CHAN5G(196, 0),
	CHAN5G(200, 0),		CHAN5G(204, 0),
	CHAN5G(208, 0),		CHAN5G(212, 0),
	CHAN5G(216, 0),
};
#endif /* CONFIG_XRADIO_5GHZ_SUPPORT */

static struct ieee80211_supported_band cw1200_band_2ghz = {
	.channels = cw1200_2ghz_chantable,
	.n_channels = ARRAY_SIZE(cw1200_2ghz_chantable),
	.bitrates = cw1200_g_rates,
	.n_bitrates = cw1200_g_rates_size,
	.ht_cap = {
		.cap = IEEE80211_HT_CAP_GRN_FLD |
		       (1 << IEEE80211_HT_CAP_RX_STBC_SHIFT),
		.ht_supported  = 1,
		.ampdu_factor  = IEEE80211_HT_MAX_AMPDU_32K,
		.ampdu_density = IEEE80211_HT_MPDU_DENSITY_NONE,
		.mcs = {
			.rx_mask[0] = 0xFF,
			.rx_highest = __cpu_to_le16(0x41),
			.tx_params  = IEEE80211_HT_MCS_TX_DEFINED,
		},
	},
};

#ifdef CONFIG_XRADIO_5GHZ_SUPPORT
static struct ieee80211_supported_band cw1200_band_5ghz = {
	.channels   = cw1200_5ghz_chantable,
	.n_channels = ARRAY_SIZE(cw1200_5ghz_chantable),
	.bitrates   = cw1200_a_rates,
	.n_bitrates = cw1200_a_rates_size,
	.ht_cap = {
		.cap = IEEE80211_HT_CAP_GRN_FLD |
		       (1 << IEEE80211_HT_CAP_RX_STBC_SHIFT),
		.ht_supported  = 1,
		.ampdu_factor  = IEEE80211_HT_MAX_AMPDU_8K,
		.ampdu_density = IEEE80211_HT_MPDU_DENSITY_NONE,
		.mcs = {
			.rx_mask[0] = 0xFF,
			.rx_highest = __cpu_to_le16(0x41),
			.tx_params  = IEEE80211_HT_MCS_TX_DEFINED,
		},
	},
};
#endif /* CONFIG_XRADIO_5GHZ_SUPPORT */

static const unsigned long cw1200_ttl[] = {
	1 * HZ,	/* VO */
	2 * HZ,	/* VI */
	5 * HZ, /* BE */
	10 * HZ	/* BK */
};

static const struct ieee80211_ops cw1200_ops = {
	.start             = cw1200_start,
	.stop              = cw1200_stop,
	.add_interface     = cw1200_add_interface,
	.remove_interface  = cw1200_remove_interface,
	.change_interface  = cw1200_change_interface,
	.tx                = cw1200_tx,
	.hw_scan           = cw1200_hw_scan,
#ifdef ROAM_OFFLOAD
	.sched_scan_start  = cw1200_hw_sched_scan_start,
	.sched_scan_stop   = cw1200_hw_sched_scan_stop,
#endif /*ROAM_OFFLOAD*/
	.set_tim           = cw1200_set_tim,
	.sta_notify        = cw1200_sta_notify,
	.sta_add           = cw1200_sta_add,
	.sta_remove        = cw1200_sta_remove,
	.set_key           = cw1200_set_key,
	.set_rts_threshold = cw1200_set_rts_threshold,
	.config            = cw1200_config,
	.bss_info_changed  = cw1200_bss_info_changed,
	.prepare_multicast = cw1200_prepare_multicast,
	.configure_filter  = cw1200_configure_filter,
	.conf_tx           = cw1200_conf_tx,
	.get_stats         = cw1200_get_stats,
	.ampdu_action      = cw1200_ampdu_action,
	.flush             = cw1200_flush,
#ifdef CONFIG_PM
	.suspend           = cw1200_wow_suspend,
	.resume            = cw1200_wow_resume,
#endif /* CONFIG_PM */
	/* Intentionally not offloaded:					*/
	/*.channel_switch	 = cw1200_channel_switch,		*/
	.remain_on_channel = cw1200_remain_on_channel,
	.cancel_remain_on_channel = cw1200_cancel_remain_on_channel,
#ifdef IPV6_FILTERING
	/*in linux3.4 mac,it does't have the api*/
	//.set_data_filter   = cw1200_set_data_filter,
#endif /*IPV6_FILTERING*/
#ifdef CONFIG_XRADIO_TESTMODE
	.testmode_cmd      = cw1200_testmode_cmd,
#endif /* CONFIG_XRADIO_TESTMODE */
};

struct cw1200_common *g_hw_priv;

/*************************************** functions ***************************************/
void cw1200_version_show(void)
{
/* Show XRADIO version and compile time */
	cw1200_dbg(XRADIO_DBG_ALWY, "Driver Label:%s  %s\n", 
	           DRV_VERSION, DRV_BUILDTIME);

/************* Linux Kernel config *************/
#ifdef CONFIG_XRADIO_NON_POWER_OF_TWO_BLOCKSIZES
	cw1200_dbg(XRADIO_DBG_NIY, "[CONFIG_XRADIO_NON_POWER_OF_TWO_BLOCKSIZES]\n");
#endif

#ifdef CONFIG_XRADIO_USE_GPIO_IRQ
	cw1200_dbg(XRADIO_DBG_NIY, "[CONFIG_XRADIO_USE_GPIO_IRQ]\n");
#endif

#ifdef CONFIG_XRADIO_5GHZ_SUPPORT
	cw1200_dbg(XRADIO_DBG_NIY, "[CONFIG_XRADIO_5GHZ_SUPPORT]\n");
#endif
#ifdef CONFIG_PM
	cw1200_dbg(XRADIO_DBG_NIY, "[CONFIG_PM]\n");
#endif

#ifdef CONFIG_XRADIO_SDIO
	cw1200_dbg(XRADIO_DBG_NIY, "[CONFIG_XRADIO_SDIO]\n");
#endif

#ifdef CONFIG_XRADIO_DUMP_ON_ERROR
	cw1200_dbg(XRADIO_DBG_NIY, "[CONFIG_XRADIO_DUMP_ON_ERROR]\n");
#endif

#ifdef CONFIG_XRADIO_DEBUGFS
	cw1200_dbg(XRADIO_DBG_NIY, "[CONFIG_XRADIO_DEBUGFS]\n");
#endif

#ifdef CONFIG_XRADIO_ITP
	cw1200_dbg(XRADIO_DBG_NIY, "[CONFIG_XRADIO_ITP]\n");
#endif

#ifdef CONFIG_XRADIO_TESTMODE
	cw1200_dbg(XRADIO_DBG_NIY, "[CONFIG_XRADIO_TESTMODE]\n");
#endif

/************ XRADIO Make File config ************/
#ifdef P2P_MULTIVIF
	cw1200_dbg(XRADIO_DBG_NIY, "[P2P_MULTIVIF]\n");
#endif

#ifdef MCAST_FWDING
	cw1200_dbg(XRADIO_DBG_NIY, "[MCAST_FWDING]\n");
#endif

#ifdef XRADIO_SUSPEND_RESUME_FILTER_ENABLE
	cw1200_dbg(XRADIO_DBG_NIY, "[XRADIO_SUSPEND_RESUME_FILTER_ENABLE]\n");
#endif

#ifdef AP_AGGREGATE_FW_FIX
	cw1200_dbg(XRADIO_DBG_NIY, "[AP_AGGREGATE_FW_FIX]\n");
#endif

#ifdef AP_HT_CAP_UPDATE
	cw1200_dbg(XRADIO_DBG_NIY, "[AP_HT_CAP_UPDATE]\n");
#endif

#ifdef PROBE_RESP_EXTRA_IE
	cw1200_dbg(XRADIO_DBG_NIY, "[PROBE_RESP_EXTRA_IE]\n");
#endif

#ifdef IPV6_FILTERING
	cw1200_dbg(XRADIO_DBG_NIY, "[IPV6_FILTERING]\n");
#endif

#ifdef ROAM_OFFLOAD
	cw1200_dbg(XRADIO_DBG_NIY, "[ROAM_OFFLOAD]\n");
#endif

#ifdef TES_P2P_0002_ROC_RESTART
	cw1200_dbg(XRADIO_DBG_NIY, "[TES_P2P_0002_ROC_RESTART]\n");
#endif

#ifdef TES_P2P_000B_EXTEND_INACTIVITY_CNT
	cw1200_dbg(XRADIO_DBG_NIY, "[TES_P2P_000B_EXTEND_INACTIVITY_CNT]\n");
#endif

#ifdef TES_P2P_000B_DISABLE_EAPOL_FILTER
	cw1200_dbg(XRADIO_DBG_NIY, "[TES_P2P_000B_DISABLE_EAPOL_FILTER]\n");
#endif

#ifdef HAS_PUT_TASK_STRUCT
	cw1200_dbg(XRADIO_DBG_NIY, "[HAS_PUT_TASK_STRUCT]\n");
#endif

/************* XRADIO.h config *************/
#ifdef HIDDEN_SSID
	cw1200_dbg(XRADIO_DBG_NIY, "[HIDDEN_SSID]\n");
#endif

#ifdef ROC_DEBUG
	cw1200_dbg(XRADIO_DBG_NIY, "[ROC_DEBUG]\n");
#endif

#ifdef XRADIO_RRM
	cw1200_dbg(XRADIO_DBG_NIY, "[XRADIO_RRM]\n");
#endif
}

/* return 0: failed*/
static inline int cw1200_macaddr_val2char(char *c_mac, const u8* v_mac)
{
	SYS_BUG(!v_mac || !c_mac);
	return sprintf(c_mac, "%02x:%02x:%02x:%02x:%02x:%02x\n",
	               v_mac[0], v_mac[1], v_mac[2], 
	               v_mac[3], v_mac[4], v_mac[5]);
}

#ifndef XRADIO_MACPARAM_HEX
static int cw1200_macaddr_char2val(u8* v_mac, const char *c_mac)
{
	int i = 0;
	const char *tmp_char = c_mac;
	SYS_BUG(!v_mac || !c_mac);

	for (i = 0; i < ETH_ALEN; i++) {
		if (*tmp_char != 0) {
			v_mac[i] = simple_strtoul(tmp_char, (char **)&tmp_char, 16);
		} else {
			cw1200_dbg(XRADIO_DBG_ERROR, "%s, Len Error\n", __func__);
			return -1;
		}
		if (i < ETH_ALEN -1 && *tmp_char != ':') {
			cw1200_dbg(XRADIO_DBG_ERROR, "%s, Format or Len Error\n", __func__);
			return -1;
		}
		tmp_char++;
	}
	return 0;
}
#endif

#ifdef XRADIO_MACADDR_FROM_CHIPID
extern void wifi_hwaddr_from_chipid(u8 *addr);
#endif

#define MACADDR_VAILID(a) ( \
(a[0] != 0 || a[1] != 0 ||  \
 a[2] != 0 || a[3] != 0 ||  \
 a[4] != 0 || a[5] != 0) && \
 !(a[0] & 0x3))

static void cw1200_get_mac_addrs(u8 *macaddr)
{
	int ret = 0;
	SYS_BUG(!macaddr);
	/* Check mac addrs param, if exsist, use it first.*/
#ifdef XRADIO_MACPARAM_HEX
	memcpy(macaddr, cw1200_macaddr_param, ETH_ALEN);
#else
	if (cw1200_macaddr_param) {
		ret = cw1200_macaddr_char2val(macaddr, cw1200_macaddr_param);
	}
#endif

#ifdef XRADIO_MACADDR_FROM_CHIPID
	if (ret < 0 || !MACADDR_VAILID(macaddr)) {
		wifi_hwaddr_from_chipid(macaddr);
	}
#endif
	/* Use random value to set mac addr for the first time, 
	 * and save it in  wifi config file. TODO: read from product ID*/
	if (ret < 0 || !MACADDR_VAILID(macaddr)) {
#ifdef XRADIO_MACPARAM_HEX
		ret = access_file(WIFI_CONF_PATH, macaddr, ETH_ALEN, 1);
#else
		char  c_mac[XRADIO_MAC_CHARLEN+2] = {0};
		ret = access_file(WIFI_CONF_PATH, c_mac, XRADIO_MAC_CHARLEN, 1);
		if (ret >= 0) {
			ret = cw1200_macaddr_char2val(macaddr, c_mac);
		}
#endif
		if(ret<0 || !MACADDR_VAILID(macaddr)) {
			get_random_bytes(macaddr, 6);
			macaddr[0] &= 0xFC; 
#ifdef XRADIO_MACPARAM_HEX
			ret = access_file(WIFI_CONF_PATH, macaddr, ETH_ALEN, 0);
#else
			ret = cw1200_macaddr_val2char(c_mac, macaddr);
			ret = access_file(WIFI_CONF_PATH, c_mac, ret, 0);
#endif
			if(ret<0)
				cw1200_dbg(XRADIO_DBG_ERROR, "Access_file failed, path:%s!\n", 
				           WIFI_CONF_PATH);
			if (!MACADDR_VAILID(macaddr)) {
				cw1200_dbg(XRADIO_DBG_WARN, "Use default Mac addr!\n");
				macaddr[0] = 0xDC;
				macaddr[1] = 0x44;
				macaddr[2] = 0x6D;
			} else {
				cw1200_dbg(XRADIO_DBG_NIY, "Use random Mac addr!\n");
			}
		} else {
			cw1200_dbg(XRADIO_DBG_NIY, "Use Mac addr in file!\n");
		}
	}
	cw1200_dbg(XRADIO_DBG_NIY, "MACADDR=%02x:%02x:%02x:%02x:%02x:%02x\n",
	           macaddr[0], macaddr[1], macaddr[2], 
	           macaddr[3], macaddr[4], macaddr[5]);
}

static void cw1200_set_ifce_comb(struct cw1200_common *hw_priv,
				 struct ieee80211_hw *hw)
{
	cw1200_dbg(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);
#ifdef P2P_MULTIVIF
	hw_priv->if_limits1[0].max = 2;
#else
	hw_priv->if_limits1[0].max = 1;
#endif

	hw_priv->if_limits1[0].types = BIT(NL80211_IFTYPE_STATION);
	hw_priv->if_limits1[1].max = 1;
	hw_priv->if_limits1[1].types = BIT(NL80211_IFTYPE_AP);

#ifdef P2P_MULTIVIF
	hw_priv->if_limits2[0].max = 3;
#else
	hw_priv->if_limits2[0].max = 2;
#endif
	hw_priv->if_limits2[0].types = BIT(NL80211_IFTYPE_STATION);

#ifdef P2P_MULTIVIF
       hw_priv->if_limits3[0].max = 2;
#else
	hw_priv->if_limits3[0].max = 1;
#endif

	hw_priv->if_limits3[0].types = BIT(NL80211_IFTYPE_STATION);
	hw_priv->if_limits3[1].max = 1;
	hw_priv->if_limits3[1].types = BIT(NL80211_IFTYPE_P2P_CLIENT) |
				      BIT(NL80211_IFTYPE_P2P_GO);

	/* TODO:COMBO: mac80211 doesn't yet support more than 1
	 * different channel */
	hw_priv->if_combs[0].num_different_channels = 1;
#ifdef P2P_MULTIVIF
        hw_priv->if_combs[0].max_interfaces = 3;
#else
	hw_priv->if_combs[0].max_interfaces = 2;
#endif
	hw_priv->if_combs[0].limits = hw_priv->if_limits1;
	hw_priv->if_combs[0].n_limits = 2;

	hw_priv->if_combs[1].num_different_channels = 1;

#ifdef P2P_MULTIVIF
        hw_priv->if_combs[1].max_interfaces = 3;
#else
	hw_priv->if_combs[1].max_interfaces = 2;
#endif
	hw_priv->if_combs[1].limits = hw_priv->if_limits2;
	hw_priv->if_combs[1].n_limits = 1;

	hw_priv->if_combs[2].num_different_channels = 1;
#ifdef P2P_MULTIVIF
        hw_priv->if_combs[2].max_interfaces = 3;
#else
	hw_priv->if_combs[2].max_interfaces = 2;
#endif
	hw_priv->if_combs[2].limits = hw_priv->if_limits3;
	hw_priv->if_combs[2].n_limits = 2;

	hw->wiphy->iface_combinations = &hw_priv->if_combs[0];
	hw->wiphy->n_iface_combinations = 3;
}

struct ieee80211_hw *cw1200_init_common(size_t hw_priv_data_len)
{
	int i;
	struct ieee80211_hw *hw;
	struct cw1200_common *hw_priv;
	struct ieee80211_supported_band *sband;
	int band;

	cw1200_dbg(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	/* Alloc ieee_802.11 hw and cw1200_common struct. */
	hw = ieee80211_alloc_hw(hw_priv_data_len, &cw1200_ops);
	if (!hw)
		return NULL;
	hw_priv = hw->priv;
	cw1200_dbg(XRADIO_DBG_ALWY, "Allocated hw_priv @ %p\n", hw_priv);
	memset(hw_priv, 0, sizeof(*hw_priv));

	/* Get MAC address. */
	cw1200_get_mac_addrs((u8 *)&hw_priv->addresses[0]);
	memcpy(hw_priv->addresses[1].addr, hw_priv->addresses[0].addr, ETH_ALEN);
	hw_priv->addresses[1].addr[5] += 0x01;
#ifdef P2P_MULTIVIF
	memcpy(hw_priv->addresses[2].addr, hw_priv->addresses[1].addr, ETH_ALEN);
	hw_priv->addresses[2].addr[4] ^= 0x80;
#endif

	/* Initialize members of hw_priv. */
	hw_priv->hw = hw;
	hw_priv->if_id_slot = 0;
	hw_priv->roc_if_id = -1;
	atomic_set(&hw_priv->num_vifs, 0);
	/* initial rates and channels TODO: fetch from FW */
	hw_priv->rates = cw1200_rates;    
	hw_priv->mcs_rates = cw1200_n_rates;
#ifdef ROAM_OFFLOAD
	hw_priv->auto_scanning = 0;
	hw_priv->frame_rcvd = 0;
	hw_priv->num_scanchannels = 0;
	hw_priv->num_2g_channels = 0;
	hw_priv->num_5g_channels = 0;
#endif /*ROAM_OFFLOAD*/
#ifdef AP_AGGREGATE_FW_FIX
	/* Enable block ACK for 4 TID (BE,VI,VI,VO). */
	hw_priv->ba_tid_mask = 0xB1;  /*due to HW limitations*/
#else
	/* Enable block ACK for every TID but voice. */
	hw_priv->ba_tid_mask = 0x3F;
#endif
	hw_priv->noise = -94;
	/* hw_priv->beacon_req_id = cpu_to_le32(0); */

	/* Initialize members of ieee80211_hw, it works in UMAC. */
	hw->sta_data_size = sizeof(struct cw1200_sta_priv);
	hw->vif_data_size = sizeof(struct cw1200_vif);

	hw->flags = IEEE80211_HW_SIGNAL_DBM            |
	            IEEE80211_HW_SUPPORTS_PS           |
	            IEEE80211_HW_SUPPORTS_DYNAMIC_PS   |
	            IEEE80211_HW_REPORTS_TX_ACK_STATUS |
	            IEEE80211_HW_SUPPORTS_UAPSD        |
	            IEEE80211_HW_CONNECTION_MONITOR;
	            //IEEE80211_HW_SUPPORTS_CQM_RSSI     |
	            /* Aggregation is fully controlled by firmware.
	             * Do not need any support from the mac80211 stack */
	            /* IEEE80211_HW_AMPDU_AGGREGATION  | */
// XXX: Extensions
	            //IEEE80211_HW_SUPPORTS_P2P_PS          |
	            //IEEE80211_HW_SUPPORTS_CQM_BEACON_MISS |
	          //  IEEE80211_HW_SUPPORTS_CQM_TX_FAIL     |
// XXX: /Extensions
	            //IEEE80211_HW_BEACON_FILTER;

	hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION)    |
	                             BIT(NL80211_IFTYPE_ADHOC)      |
	                             BIT(NL80211_IFTYPE_AP)         |
	                             BIT(NL80211_IFTYPE_MESH_POINT) |
	                             BIT(NL80211_IFTYPE_P2P_CLIENT) |
	                             BIT(NL80211_IFTYPE_P2P_GO);

	/* Support only for limited wowlan functionalities */
	hw->wiphy->wowlan.flags = WIPHY_WOWLAN_ANY | WIPHY_WOWLAN_DISCONNECT;
	hw->wiphy->wowlan.n_patterns = 0;

	hw->wiphy->flags |= WIPHY_FLAG_AP_UAPSD;
	/* fix the problem that driver can not set pro-resp templet frame to fw */
	hw->wiphy->flags |= WIPHY_FLAG_AP_PROBE_RESP_OFFLOAD;

#if defined(CONFIG_XRADIO_DISABLE_BEACON_HINTS)
	hw->wiphy->flags |= WIPHY_FLAG_DISABLE_BEACON_HINTS;
#endif
	hw->wiphy->n_addresses = XRWL_MAX_VIFS;
	hw->wiphy->addresses   = hw_priv->addresses;
	hw->wiphy->max_remain_on_channel_duration = 500;
	hw->channel_change_time = 500;	/* TODO: find actual value */
	hw->extra_tx_headroom = WSM_TX_EXTRA_HEADROOM +
	                        8  /* TKIP IV */      +
	                        12 /* TKIP ICV and MIC */;
	hw->wiphy->bands[IEEE80211_BAND_2GHZ] = &cw1200_band_2ghz;
#ifdef CONFIG_XRADIO_5GHZ_SUPPORT
	hw->wiphy->bands[IEEE80211_BAND_5GHZ] = &cw1200_band_5ghz;
#endif /* CONFIG_XRADIO_5GHZ_SUPPORT */
	hw->queues         = AC_QUEUE_NUM;
	hw->max_rates      = MAX_RATES_STAGE;
	hw->max_rate_tries = MAX_RATES_RETRY;
	/* Channel params have to be cleared before registering wiphy again */
	for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
		sband = hw->wiphy->bands[band];
		if (!sband)
			continue;
		for (i = 0; i < sband->n_channels; i++) {
			sband->channels[i].flags = 0;
			sband->channels[i].max_antenna_gain = 0;
			sband->channels[i].max_power = 30;
		}
	}
	/* hw_priv->channel init value is the local->oper_channel init value;when transplanting,take care */
	for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
		sband = hw->wiphy->bands[band];
		if (!sband)
			continue;
		if(!hw_priv->channel){
			hw_priv->channel = &sband->channels[2];
		}	
	}
	hw->wiphy->max_scan_ssids = WSM_SCAN_MAX_NUM_OF_SSIDS;
	hw->wiphy->max_scan_ie_len = IEEE80211_MAX_DATA_LEN;
	SET_IEEE80211_PERM_ADDR(hw, hw_priv->addresses[0].addr);

	/* Initialize locks. */
	spin_lock_init(&hw_priv->vif_list_lock);
	mutex_init(&hw_priv->wsm_cmd_mux);
	mutex_init(&hw_priv->conf_mutex);
	mutex_init(&hw_priv->wsm_oper_lock);
	atomic_set(&hw_priv->tx_lock, 0);
	sema_init(&hw_priv->tx_lock_sem, 1);

	hw_priv->workqueue = create_singlethread_workqueue(XRADIO_WORKQUEUE);
	sema_init(&hw_priv->scan.lock, 1);
	sema_init(&hw_priv->scan.status_lock,1);
	INIT_WORK(&hw_priv->scan.work, cw1200_scan_work);
#ifdef ROAM_OFFLOAD
	INIT_WORK(&hw_priv->scan.swork, cw1200_sched_scan_work);
#endif /*ROAM_OFFLOAD*/
	INIT_DELAYED_WORK(&hw_priv->scan.probe_work, cw1200_probe_work);
	INIT_DELAYED_WORK(&hw_priv->scan.timeout, cw1200_scan_timeout);
	INIT_DELAYED_WORK(&hw_priv->rem_chan_timeout, cw1200_rem_chan_timeout);
	INIT_WORK(&hw_priv->tx_policy_upload_work, tx_policy_upload_work);
	atomic_set(&hw_priv->upload_count, 0);
	memset(&hw_priv->connet_time, 0, sizeof(hw_priv->connet_time));

	spin_lock_init(&hw_priv->event_queue_lock);
	INIT_LIST_HEAD(&hw_priv->event_queue);
	INIT_WORK(&hw_priv->event_handler, cw1200_event_handler);
	INIT_WORK(&hw_priv->ba_work, cw1200_ba_work);
	spin_lock_init(&hw_priv->ba_lock);
	init_timer(&hw_priv->ba_timer);
	hw_priv->ba_timer.data = (unsigned long)hw_priv;
	hw_priv->ba_timer.function = cw1200_ba_timer;

	if (unlikely(cw1200_queue_stats_init(&hw_priv->tx_queue_stats,
			WLAN_LINK_ID_MAX,cw1200_skb_dtor, hw_priv))) {
		ieee80211_free_hw(hw);
		return NULL;
	}
	for (i = 0; i < AC_QUEUE_NUM; ++i) {
		if (unlikely(cw1200_queue_init(&hw_priv->tx_queue[i],
				&hw_priv->tx_queue_stats, i, XRWL_MAX_QUEUE_SZ, cw1200_ttl[i]))) {
			for (; i > 0; i--)
				cw1200_queue_deinit(&hw_priv->tx_queue[i - 1]);
			cw1200_queue_stats_deinit(&hw_priv->tx_queue_stats);
			ieee80211_free_hw(hw);
			return NULL;
		}
	}

	init_waitqueue_head(&hw_priv->channel_switch_done);
	init_waitqueue_head(&hw_priv->wsm_cmd_wq);
	init_waitqueue_head(&hw_priv->wsm_startup_done);
	init_waitqueue_head(&hw_priv->offchannel_wq);
	hw_priv->wsm_caps.firmwareReady = 0;
	hw_priv->driver_ready = 0;
	hw_priv->offchannel_done = 0;
	wsm_buf_init(&hw_priv->wsm_cmd_buf);
	spin_lock_init(&hw_priv->wsm_cmd.lock);
	tx_policy_init(hw_priv);
	cw1200_init_resv_skb(hw_priv);
	/* add for setting short_frame_max_tx_count(mean wdev->retry_short) to drv,init the max_rate_tries */
	spin_lock_bh(&hw_priv->tx_policy_cache.lock);
	hw_priv->long_frame_max_tx_count = hw->conf.long_frame_max_tx_count;
	hw_priv->short_frame_max_tx_count =
			(hw->conf.short_frame_max_tx_count< 0x0F) ?
			hw->conf.short_frame_max_tx_count : 0x0F;
	hw_priv->hw->max_rate_tries = hw->conf.short_frame_max_tx_count;
	spin_unlock_bh(&hw_priv->tx_policy_cache.lock);

	for (i = 0; i < XRWL_MAX_VIFS; i++)
		hw_priv->hw_bufs_used_vif[i] = 0;

#ifdef MCAST_FWDING
	for (i = 0; i < WSM_MAX_BUF; i++)
		wsm_init_release_buffer_request(hw_priv, i);
	hw_priv->buf_released = 0;
#endif
	hw_priv->vif0_throttle = XRWL_HOST_VIF0_11BG_THROTTLE;
	hw_priv->vif1_throttle = XRWL_HOST_VIF1_11BG_THROTTLE;

#if defined(CONFIG_XRADIO_DEBUG)
	hw_priv->wsm_enable_wsm_dumps = 0;
	hw_priv->wsm_dump_max_size = WSM_DUMP_MAX_SIZE;
#endif /* CONFIG_XRADIO_DEBUG */
	hw_priv->query_packetID = 0;
	atomic_set(&hw_priv->query_cnt, 0);
	INIT_WORK(&hw_priv->query_work, wsm_query_work);

#ifdef CONFIG_XRADIO_SUSPEND_POWER_OFF
	atomic_set(&hw_priv->suspend_state, XRADIO_RESUME);
#endif
#ifdef HW_RESTART
	hw_priv->hw_restart = false;
	INIT_WORK(&hw_priv->hw_restart_work, cw1200_restart_work);
#endif
#ifdef CONFIG_XRADIO_TESTMODE
	hw_priv->test_frame.data = NULL;
	hw_priv->test_frame.len = 0;
	spin_lock_init(&hw_priv->tsm_lock);
	INIT_DELAYED_WORK(&hw_priv->advance_scan_timeout,
	                  cw1200_advance_scan_timeout);
#endif /*CONFIG_XRADIO_TESTMODE*/

	cw1200_set_ifce_comb(hw_priv, hw_priv->hw);

	if (!g_hw_priv) {
		g_hw_priv = hw_priv;
		return hw;
	} else { //error:didn't release hw_priv last time.
		ieee80211_free_hw(hw);
		cw1200_dbg(XRADIO_DBG_ERROR, "g_hw_priv is not NULL @ %p!\n", g_hw_priv);
		return NULL;
	}
}

void cw1200_free_common(struct ieee80211_hw *dev)
{
	int i;
	struct cw1200_common *hw_priv = dev->priv;
	cw1200_dbg(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

#ifdef CONFIG_XRADIO_TESTMODE
	kfree(hw_priv->test_frame.data);
#endif /* CONFIG_XRADIO_TESTMODE */

	cancel_work_sync(&hw_priv->query_work);
	del_timer_sync(&hw_priv->ba_timer);
	mutex_destroy(&hw_priv->wsm_oper_lock);
	mutex_destroy(&hw_priv->conf_mutex);
	mutex_destroy(&hw_priv->wsm_cmd_mux);
	wsm_buf_deinit(&hw_priv->wsm_cmd_buf);
	flush_workqueue(hw_priv->workqueue);
	destroy_workqueue(hw_priv->workqueue);
	hw_priv->workqueue = NULL;

	cw1200_deinit_resv_skb(hw_priv);
	if (hw_priv->skb_cache) {
		dev_kfree_skb(hw_priv->skb_cache);
		hw_priv->skb_cache = NULL;
	}

	for (i = 0; i < 4; ++i)
		cw1200_queue_deinit(&hw_priv->tx_queue[i]);
	cw1200_queue_stats_deinit(&hw_priv->tx_queue_stats);

	for (i = 0; i < XRWL_MAX_VIFS; i++) {
		kfree(hw_priv->vif_list[i]);
		hw_priv->vif_list[i] = NULL;
	}

//fixed memory leakage by yangfh
#ifdef MCAST_FWDING
	wsm_deinit_release_buffer(hw_priv);
#endif
	/* unsigned int i; */
	ieee80211_free_hw(dev);
	g_hw_priv = NULL;
}

int cw1200_register_common(struct ieee80211_hw *dev)
{
	int err = 0;
	struct cw1200_common *hw_priv = dev->priv;
	cw1200_dbg(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	SET_IEEE80211_DEV(dev, hw_priv->pdev);
	err = ieee80211_register_hw(dev);
	if (err) {
		cw1200_dbg(XRADIO_DBG_ERROR, "Cannot register device (%d).\n", err);
		return err;
	}
	cw1200_dbg(XRADIO_DBG_MSG, "is registered as '%s'\n", 
	           wiphy_name(dev->wiphy));

	cw1200_debug_init_common(hw_priv);
	hw_priv->driver_ready = 1;
	wake_up(&hw_priv->wsm_startup_done);
	return 0;
}

void cw1200_unregister_common(struct ieee80211_hw *dev)
{
	struct cw1200_common *hw_priv = dev->priv;
	cw1200_dbg(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	if (wiphy_dev(dev->wiphy)) {
	ieee80211_unregister_hw(dev);
		SET_IEEE80211_DEV(dev, NULL);
	cw1200_debug_release_common(hw_priv);
	}
	hw_priv->driver_ready = 0;
}

#ifdef HW_RESTART
int cw1200_core_reinit(struct cw1200_common *hw_priv)
{
	int ret = 0;
	u16 ctrl_reg;
	int i = 0;
	struct cw1200_vif *priv = NULL;
	struct wsm_operational_mode mode = {
		.power_mode = wsm_power_mode_quiescent,
		.disableMoreFlagUsage = true,
	};

	if (!hw_priv) {
		cw1200_dbg(XRADIO_DBG_ERROR, "%s hw_priv is NULL!\n", __func__);
		return -1;
	}

	/* Need some time for restart hardware, don't suspend again.*/
#ifdef CONFIG_PM
	cw1200_pm_lock_awake(&hw_priv->pm_state);
#endif

	cw1200_dbg(XRADIO_DBG_ALWY, "%s %d!\n", __func__, __LINE__);
	/* Disconnect with AP or STAs. */
	cw1200_for_each_vif(hw_priv, priv, i) {
#ifdef P2P_MULTIVIF
		if ((i == (XRWL_MAX_VIFS - 1)) || !priv)
#else
		if (!priv)
#endif
			continue;
		if (priv->join_status == XRADIO_JOIN_STATUS_STA) {
			ieee80211_connection_loss(priv->vif);
			msleep(200);
		} else if (priv->join_status == XRADIO_JOIN_STATUS_AP) {
			wms_send_disassoc_to_self(hw_priv, priv);
			msleep(200);
		}
	}
	cw1200_unregister_common(hw_priv->hw);
	
	/*deinit dev */
	cw1200_dev_deinit(hw_priv);

	/*reinit status refer to hif. */
	hw_priv->powersave_enabled = false;
	hw_priv->wsm_caps.firmwareReady = 0;
	atomic_set(&hw_priv->bh_rx, 0);
	atomic_set(&hw_priv->bh_tx, 0);
	atomic_set(&hw_priv->bh_term, 0);
	hw_priv->buf_id_tx = 0;
	hw_priv->buf_id_rx = 0;
	hw_priv->wsm_rx_seq   = 0;
	hw_priv->wsm_tx_seq   = 0;
	hw_priv->device_can_sleep = 0;
	hw_priv->hw_bufs_used = 0;
	memset(&hw_priv->hw_bufs_used_vif, 0, sizeof(hw_priv->hw_bufs_used_vif));
	memset(&hw_priv->connet_time, 0, sizeof(hw_priv->connet_time));
	atomic_set(&hw_priv->query_cnt, 0);
	hw_priv->query_packetID = 0;
	tx_policy_init(hw_priv);

	/*reinit sdio hwbus. */
	hwbus_sdio_deinit();
	msleep(100);
	hw_priv->pdev = hwbus_sdio_init((struct hwbus_ops **)&hw_priv->hwbus_ops,
	                               &hw_priv->hwbus_priv);
	if (!hw_priv->pdev) {
		cw1200_dbg(XRADIO_DBG_ERROR,"%s:hwbus_sdio_init failed\n", __func__);
		ret = -ETIMEDOUT;
		goto exit;
	}

	/*wake up bh thread. */
	if (hw_priv->bh_thread == NULL) {
		hw_priv->bh_error = 0;
		atomic_set(&hw_priv->tx_lock, 0);
		cw1200_register_bh(hw_priv);
	} else {
#ifdef CONFIG_XRADIO_SUSPEND_POWER_OFF
		WARN_ON(cw1200_bh_resume(hw_priv));
#endif
	}

	/* Load firmware and register Interrupt Handler */

	ret = cw1200_load_firmware(hw_priv);
	if (ret) {
		cw1200_dbg(XRADIO_DBG_ERROR, "%s:cw1200_load_firmware failed(%d).\n",
			   __func__, ret);
		goto exit;
	}

	/* Set sdio blocksize. */
	hw_priv->hwbus_ops->lock(hw_priv->hwbus_priv);
	SYS_WARN(hw_priv->hwbus_ops->set_block_size(hw_priv->hwbus_priv,
		 SDIO_BLOCK_SIZE));
	hw_priv->hwbus_ops->unlock(hw_priv->hwbus_priv);
	if (wait_event_interruptible_timeout(hw_priv->wsm_startup_done,
				hw_priv->wsm_caps.firmwareReady, 3*HZ) <= 0) {

		/* TODO: Needs to find how to reset device */
		/*       in QUEUE mode properly.           */
		cw1200_dbg(XRADIO_DBG_ERROR, "%s:Firmware Startup Timeout!\n",
			   __func__);
		ret = -ETIMEDOUT;
		goto exit;
	}
	cw1200_dbg(XRADIO_DBG_ALWY, "%s:Firmware Startup Done.\n", __func__);

	hw_priv->hw_restart = false;
#ifdef CONFIG_XRADIO_SUSPEND_POWER_OFF
	atomic_set(&hw_priv->suspend_state, XRADIO_RESUME);
#endif

	/* Keep device wake up. */
	ret = cw1200_reg_write_16(hw_priv, HIF_CONTROL_REG_ID, HIF_CTRL_WUP_BIT);
	if (cw1200_reg_read_16(hw_priv, HIF_CONTROL_REG_ID, &ctrl_reg))
		ret = cw1200_reg_read_16(hw_priv, HIF_CONTROL_REG_ID, &ctrl_reg);
	SYS_WARN(!(ctrl_reg & HIF_CTRL_RDY_BIT));

	/* Set device mode parameter. */
	for (i = 0; i < xrwl_get_nr_hw_ifaces(hw_priv); i++) {
		/* Set low-power mode. */
		ret = wsm_set_operational_mode(hw_priv, &mode, i);
		/* Enable multi-TX confirmation */
		ret = wsm_use_multi_tx_conf(hw_priv, true, i);
	}

	/* re-Register wireless net device. */
	if (!ret)
	ret = cw1200_register_common(hw_priv->hw);

	/* unlock queue if need. */
	for (i = 0; i < 4; ++i) {
		struct cw1200_queue *queue = &hw_priv->tx_queue[i];
		spin_lock_bh(&queue->lock);
		if (queue->tx_locked_cnt > 0) {
			queue->tx_locked_cnt = 0;
			ieee80211_wake_queue(hw_priv->hw, queue->queue_id);
			cw1200_dbg(XRADIO_DBG_WARN, "%s: unlock queue!\n", __func__);
		}
		spin_unlock_bh(&queue->lock);
	}
exit:
#ifdef CONFIG_PM
	cw1200_pm_unlock_awake(&hw_priv->pm_state);
#endif
	cw1200_dbg(XRADIO_DBG_ALWY, "%s end!\n", __func__);

	return ret;
}

void cw1200_restart_work(struct work_struct *work)
{
	struct cw1200_common *hw_priv =
		container_of(work, struct cw1200_common, hw_restart_work);
	cw1200_dbg(XRADIO_DBG_ALWY, "%s\n", __func__);

	if (hw_priv->bh_error) {
		cw1200_unregister_bh(hw_priv);
	}
	if (unlikely(cw1200_core_reinit(hw_priv))) {
		pm_printk(XRADIO_DBG_ALWY, "%s again!\n", __func__);
		mutex_lock(&hw_priv->wsm_cmd_mux);
		hw_priv->hw_restart = true;
		mutex_unlock(&hw_priv->wsm_cmd_mux);
		cw1200_unregister_bh(hw_priv);
		cw1200_core_reinit(hw_priv);
	}
}
#endif

int cw1200_core_init(void)
{
	int err = -ENOMEM;
	u16 ctrl_reg;
	int if_id;
	struct ieee80211_hw *dev;
	struct cw1200_common *hw_priv;
	struct wsm_operational_mode mode = {
		.power_mode = wsm_power_mode_quiescent,
		.disableMoreFlagUsage = true,
	};
	cw1200_version_show();

	//init cw1200_common
	dev = cw1200_init_common(sizeof(struct cw1200_common));
	if (!dev) {
		cw1200_dbg(XRADIO_DBG_ERROR,"cw1200_init_common failed\n");
		return err;
	}
	hw_priv = dev->priv;

	//init sdio hwbus
	hw_priv->pdev = hwbus_sdio_init((struct hwbus_ops **)&hw_priv->hwbus_ops, 
	                               &hw_priv->hwbus_priv);
	if (!hw_priv->pdev) {
		err = -ETIMEDOUT;
		cw1200_dbg(XRADIO_DBG_ERROR,"hwbus_sdio_init failed\n");
		goto err1;
	}

	/* WSM callbacks. */
	hw_priv->wsm_cbc.scan_complete = cw1200_scan_complete_cb;
	hw_priv->wsm_cbc.tx_confirm = cw1200_tx_confirm_cb;
	hw_priv->wsm_cbc.rx = cw1200_rx_cb;
	hw_priv->wsm_cbc.suspend_resume = cw1200_suspend_resume;
	/* hw_priv->wsm_cbc.set_pm_complete = cw1200_set_pm_complete_cb; */
	hw_priv->wsm_cbc.channel_switch = cw1200_channel_switch_cb;

	/*init pm and wakelock. */
#ifdef CONFIG_PM
	err = cw1200_pm_init(&hw_priv->pm_state, hw_priv);
	if (err) {
		cw1200_dbg(XRADIO_DBG_ERROR, "cw1200_pm_init failed(%d).\n", err);
		goto err2;
	}
#endif
	/* Register bh thread*/
	err = cw1200_register_bh(hw_priv);
	if (err) {
		cw1200_dbg(XRADIO_DBG_ERROR, "cw1200_register_bh failed(%d).\n",
			   err);
		goto err3;
	}

	/* Load firmware and register Interrupt Handler */
	err = cw1200_load_firmware(hw_priv);
	if (err) {
		cw1200_dbg(XRADIO_DBG_ERROR, "cw1200_load_firmware failed(%d).\n",
			   err);
		goto err4;
	}

	/* Set sdio blocksize. */
	hw_priv->hwbus_ops->lock(hw_priv->hwbus_priv);
	SYS_WARN(hw_priv->hwbus_ops->set_block_size(hw_priv->hwbus_priv,
			SDIO_BLOCK_SIZE));
	hw_priv->hwbus_ops->unlock(hw_priv->hwbus_priv);

	if (wait_event_interruptible_timeout(hw_priv->wsm_startup_done,
				hw_priv->wsm_caps.firmwareReady, 3*HZ) <= 0) {

		/* TODO: Needs to find how to reset device */
		/*       in QUEUE mode properly.           */
		cw1200_dbg(XRADIO_DBG_ERROR, "Firmware Startup Timeout!\n");
		err = -ETIMEDOUT;
		goto err5;
	}
	cw1200_dbg(XRADIO_DBG_ALWY,"Firmware Startup Done.\n");

	/* Keep device wake up. */
	SYS_WARN(cw1200_reg_write_16(hw_priv, HIF_CONTROL_REG_ID, HIF_CTRL_WUP_BIT));
	if (cw1200_reg_read_16(hw_priv,HIF_CONTROL_REG_ID, &ctrl_reg))
		SYS_WARN(cw1200_reg_read_16(hw_priv,HIF_CONTROL_REG_ID, &ctrl_reg));
	SYS_WARN(!(ctrl_reg & HIF_CTRL_RDY_BIT));

	/* Set device mode parameter. */
	for (if_id = 0; if_id < xrwl_get_nr_hw_ifaces(hw_priv); if_id++) {
		/* Set low-power mode. */
		SYS_WARN(wsm_set_operational_mode(hw_priv, &mode, if_id));
		/* Enable multi-TX confirmation */
		SYS_WARN(wsm_use_multi_tx_conf(hw_priv, true, if_id));
	}

	/* Register wireless net device. */
	err = cw1200_register_common(dev);
	if (err) {
		cw1200_dbg(XRADIO_DBG_ERROR,"cw1200_register_common failed(%d)!\n", err);
		goto err5;
	}

	return err;

err5:
	cw1200_dev_deinit(hw_priv);
err4:
	cw1200_unregister_bh(hw_priv);
err3:
	cw1200_pm_deinit(&hw_priv->pm_state);
err2:
	hwbus_sdio_deinit();
err1:
	cw1200_free_common(dev);
	return err;
}
EXPORT_SYMBOL_GPL(cw1200_core_init);

void cw1200_core_deinit(void)
{
	cw1200_dbg(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);
	if (g_hw_priv) {
#ifdef HW_RESTART
		cancel_work_sync(&g_hw_priv->hw_restart_work);
#endif
		cw1200_unregister_common(g_hw_priv->hw);
		cw1200_dev_deinit(g_hw_priv);
		cw1200_unregister_bh(g_hw_priv);
		cw1200_pm_deinit(&g_hw_priv->pm_state);
		cw1200_free_common(g_hw_priv->hw);
		hwbus_sdio_deinit();
	}
	return;
}
EXPORT_SYMBOL_GPL(cw1200_core_deinit);

/* Init Module function -> Called by insmod */
static int __init cw1200_core_entry(void)
{
	int ret = 0;
	cw1200_dbg(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);
	ret = cw1200_plat_init();
	if (ret) {
		cw1200_dbg(XRADIO_DBG_ERROR,"cw1200_plat_init failed(%d)!\n", ret);
	}
	ret = cw1200_host_dbg_init();
	ret = cw1200_core_init();
	return ret;
}

/* Called at Driver Unloading */
static void __exit cw1200_core_exit(void)
{
	cw1200_core_deinit();
	cw1200_host_dbg_deinit();
	cw1200_plat_deinit();
	cw1200_dbg(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);
}

module_init(cw1200_core_entry);
module_exit(cw1200_core_exit);


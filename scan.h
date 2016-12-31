/*
 * Scan interface for ST-Ericsson CW1200 mac80211 drivers
 *
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
 * Copyright (c) 2013, XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef SCAN_H_INCLUDED
#define SCAN_H_INCLUDED

#include <linux/semaphore.h>
#include "wsm.h"

/* external */ struct sk_buff;
/* external */ struct cfg80211_scan_request;
/* external */ struct ieee80211_channel;
/* external */ struct ieee80211_hw;
/* external */ struct work_struct;

struct cw1200_scan {
	struct semaphore lock;
	struct work_struct work;
#ifdef ROAM_OFFLOAD
	struct work_struct swork; /* scheduled scan work */
	struct cfg80211_sched_scan_request *sched_req;
#endif /*ROAM_OFFLOAD*/
	struct delayed_work timeout;
	struct cfg80211_scan_request *req;
	struct ieee80211_channel **begin;
	struct ieee80211_channel **curr;
	struct ieee80211_channel **end;
	struct wsm_ssid ssids[WSM_SCAN_MAX_NUM_OF_SSIDS];
	int output_power;
	int n_ssids;
	//add by liwei, for h64 ping WS550 BUG
	struct semaphore status_lock;
	int status;
	atomic_t in_progress;
	/* Direct probe requests workaround */
	struct delayed_work probe_work;
	int direct_probe;
	u8 if_id;
};

int cw1200_hw_scan(struct ieee80211_hw *hw,
		   struct ieee80211_vif *vif,
		   struct ieee80211_scan_request *hw_req);
#ifdef ROAM_OFFLOAD
int cw1200_hw_sched_scan_start(struct ieee80211_hw *hw,
                               struct ieee80211_vif *vif,
                               struct cfg80211_sched_scan_request *req,
                               struct ieee80211_sched_scan_ies *ies);
void cw1200_hw_sched_scan_stop(struct cw1200_common *priv);
void cw1200_sched_scan_work(struct work_struct *work);
#endif /*ROAM_OFFLOAD*/
void cw1200_scan_work(struct work_struct *work);
void cw1200_scan_timeout(struct work_struct *work);
/* TODO: cw1200_clear_recent_scan_work */
void cw1200_scan_complete_cb(struct cw1200_common *priv,
			     struct wsm_scan_complete *arg);
/* TODO: cw1200_scan_failed_cb */

/* ******************************************************************** */
/* Raw probe requests TX workaround					*/
void cw1200_probe_work(struct work_struct *work);
#ifdef CONFIG_XRADIO_TESTMODE
/* Advance Scan Timer							*/
void cw1200_advance_scan_timeout(struct work_struct *work);
#endif

#endif

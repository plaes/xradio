/*
 * queue operations for XRadio drivers
 *
 * Copyright (c) 2013, XRadio
 * Author: XRadio
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#ifndef XRADIO_QUEUE_H_INCLUDED
#define XRADIO_QUEUE_H_INCLUDED

/* private */ struct cw1200_queue_item;

/* extern */ struct sk_buff;
/* extern */ struct wsm_tx;
/* extern */ struct cw1200_common;
/* extern */ struct cw1200_vif;
/* extern */ struct ieee80211_tx_queue_stats;
/* extern */ struct cw1200_txpriv;

/* forward */ struct cw1200_queue_stats;

typedef void (*cw1200_queue_skb_dtor_t)(struct cw1200_common *priv,
                                        struct sk_buff *skb,
                                        const struct cw1200_txpriv *txpriv);

struct cw1200_queue {
	struct                    cw1200_queue_stats *stats;
	size_t                    capacity;
	size_t                    num_queued;
	size_t                    num_queued_vif[XRWL_MAX_VIFS];
	size_t                    num_pending;
	size_t                    num_pending_vif[XRWL_MAX_VIFS];
	size_t                    num_sent;
	struct cw1200_queue_item *pool;
	struct list_head          queue;
	struct list_head          free_pool;
	struct list_head          pending;
	int                       tx_locked_cnt;
	int                      *link_map_cache[XRWL_MAX_VIFS];
	bool                      overfull;
	spinlock_t                lock;
	u8                        queue_id;
	u8                        generation;
	struct timer_list	        gc;
	unsigned long             ttl;
};

struct cw1200_queue_stats {
	spinlock_t              lock;
	int                    *link_map_cache[XRWL_MAX_VIFS];
	int                     num_queued[XRWL_MAX_VIFS];
	size_t                  map_capacity;
	wait_queue_head_t       wait_link_id_empty;
	cw1200_queue_skb_dtor_t skb_dtor;
	struct cw1200_common   *hw_priv;
};

struct cw1200_txpriv {
	u8 link_id;
	u8 raw_link_id;
	u8 tid;
	u8 rate_id;
	u8 offset;
	u8 if_id;
#ifndef P2P_MULTIVIF
	u8 offchannel_if_id;
#else
	u8 raw_if_id;
#endif
	u8 use_bg_rate;
};

int cw1200_queue_stats_init(struct cw1200_queue_stats *stats,
                            size_t map_capacity,
                            cw1200_queue_skb_dtor_t skb_dtor,
                            struct cw1200_common *priv);
int cw1200_queue_init(struct cw1200_queue *queue,
                      struct cw1200_queue_stats *stats,
                      u8 queue_id,
                      size_t capacity,
                      unsigned long ttl);
int cw1200_queue_clear(struct cw1200_queue *queue, int if_id);
void cw1200_queue_stats_deinit(struct cw1200_queue_stats *stats);
void cw1200_queue_deinit(struct cw1200_queue *queue);

size_t cw1200_queue_get_num_queued(struct cw1200_vif *priv,
                                   struct cw1200_queue *queue,
                                   u32 link_id_map);
int cw1200_queue_put(struct cw1200_queue *queue,
                     struct sk_buff *skb, struct cw1200_txpriv *txpriv);
int cw1200_queue_get(struct cw1200_queue *queue,
                     int if_id, u32 link_id_map,
                     struct wsm_tx **tx,
                     struct ieee80211_tx_info **tx_info,
                     struct cw1200_txpriv **txpriv);

#ifdef CONFIG_XRADIO_TESTMODE
int cw1200_queue_requeue(struct cw1200_common *hw_priv,
                         struct cw1200_queue *queue,
                         u32 packetID, bool check);
#else
int cw1200_queue_requeue(struct cw1200_queue *queue, u32 packetID, bool check);
#endif
int cw1200_queue_requeue_all(struct cw1200_queue *queue);
#ifdef CONFIG_XRADIO_TESTMODE
int cw1200_queue_remove(struct cw1200_common *hw_priv,
                        struct cw1200_queue *queue,
                        u32 packetID);
#else
int cw1200_queue_remove(struct cw1200_queue *queue,
                        u32 packetID);
#endif /*CONFIG_XRADIO_TESTMODE*/
int cw1200_queue_get_skb(struct cw1200_queue *queue, u32 packetID,
                         struct sk_buff **skb,
                         const struct cw1200_txpriv **txpriv);
void cw1200_queue_lock(struct cw1200_queue *queue);
void cw1200_queue_unlock(struct cw1200_queue *queue);
bool cw1200_queue_get_xmit_timestamp(struct cw1200_queue *queue,
                                     unsigned long *timestamp, int if_id,
                                     u32 pending_frameID, u32 *Old_frame_ID);
bool cw1200_query_txpkt_timeout(struct cw1200_common *hw_priv, int if_id,
                                u32 pending_pkt_id, long *timeout);


bool cw1200_queue_stats_is_empty(struct cw1200_queue_stats *stats,
                                 u32 link_id_map, int if_id);

static inline u8 cw1200_queue_get_queue_id(u32 packetID)
{
	return (packetID >> 16) & 0xF;
}

static inline u8 cw1200_queue_get_if_id(u32 packetID)
{
	return (packetID >> 20) & 0xF;
}

static inline u8 cw1200_queue_get_link_id(u32 packetID)
{
	return (packetID >> 24) & 0xF;
}

static inline u8 cw1200_queue_get_generation(u32 packetID)
{
	return (packetID >>  8) & 0xFF;
}

#endif /* XRADIO_QUEUE_H_INCLUDED */

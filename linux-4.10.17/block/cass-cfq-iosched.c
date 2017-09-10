/*
 *  cass_cfq, or complete fairness queueing, disk scheduler.
 *
 *  Based on ideas from a previously unfinished io
 *  scheduler (round robin per-process disk scheduling) and Andrea Arcangeli.
 *
 *  Copyright (C) 2003 Jens Axboe <axboe@kernel.dk>
 */
#include <linux/cass_cfq_iosched.h>
#include "blk.h"
#include "blk-wbt.h"

static struct cass_cfq_rb_root *st_for(struct cass_cfq_group *cass_cfqg,
					    enum wl_class_t class,
					    enum wl_type_t type)
{
	if (!cass_cfqg)
		return NULL;

	if (class == IDLE_WORKLOAD)
		return &cass_cfqg->service_tree_idle;

	return &cass_cfqg->service_trees[class][type];
}

enum cass_cfqq_state_flags {
	CASS_CFQQ_FLAG_on_rr = 0,	/* on round-robin busy list */
	CASS_CFQQ_FLAG_wait_request,	/* waiting for a request */
	CASS_CFQQ_FLAG_must_dispatch,	/* must be allowed a dispatch */
	CASS_CFQQ_FLAG_must_alloc_slice,	/* per-slice must_alloc flag */
	CASS_CFQQ_FLAG_fifo_expire,	/* FIFO checked in this slice */
	CASS_CFQQ_FLAG_idle_window,	/* slice idling enabled */
	CASS_CFQQ_FLAG_prio_changed,	/* task priority has changed */
	CASS_CFQQ_FLAG_slice_new,	/* no requests dispatched in slice */
	CASS_CFQQ_FLAG_sync,		/* synchronous queue */
	CASS_CFQQ_FLAG_coop,		/* cass_cfqq is shared */
	CASS_CFQQ_FLAG_split_coop,	/* shared cass_cfqq will be splitted */
	CASS_CFQQ_FLAG_deep,		/* sync cass_cfqq experienced large depth */
	CASS_CFQQ_FLAG_wait_busy,	/* Waiting for next request */
};

#define CASS_CFQQ_FNS(name)						\
static inline void cass_cfq_mark_cass_cfqq_##name(struct cass_cfq_queue *cass_cfqq)		\
{									\
	(cass_cfqq)->flags |= (1 << CASS_CFQQ_FLAG_##name);			\
}									\
static inline void cass_cfq_clear_cass_cfqq_##name(struct cass_cfq_queue *cass_cfqq)	\
{									\
	(cass_cfqq)->flags &= ~(1 << CASS_CFQQ_FLAG_##name);			\
}									\
static inline int cass_cfqq_##name(const struct cass_cfq_queue *cass_cfqq)		\
{									\
	return ((cass_cfqq)->flags & (1 << CASS_CFQQ_FLAG_##name)) != 0;	\
}

CASS_CFQQ_FNS(on_rr);
CASS_CFQQ_FNS(wait_request);
CASS_CFQQ_FNS(must_dispatch);
CASS_CFQQ_FNS(must_alloc_slice);
CASS_CFQQ_FNS(fifo_expire);
CASS_CFQQ_FNS(idle_window);
CASS_CFQQ_FNS(prio_changed);
CASS_CFQQ_FNS(slice_new);
CASS_CFQQ_FNS(sync);
CASS_CFQQ_FNS(coop);
CASS_CFQQ_FNS(split_coop);
CASS_CFQQ_FNS(deep);
CASS_CFQQ_FNS(wait_busy);
#undef CASS_CFQQ_FNS

#if defined(CONFIG_CASS_CFQ_GROUP_IOSCHED) && defined(CONFIG_DEBUG_BLK_CGROUP)

/* cass_cfqg stats flags */
enum cass_cfqg_stats_flags {
	CASS_CFQG_stats_waiting = 0,
	CASS_CFQG_stats_idling,
	CASS_CFQG_stats_empty,
};

#define CASS_CFQG_FLAG_FNS(name)						\
static inline void cass_cfqg_stats_mark_##name(struct cass_cfqg_stats *stats)	\
{									\
	stats->flags |= (1 << CASS_CFQG_stats_##name);			\
}									\
static inline void cass_cfqg_stats_clear_##name(struct cass_cfqg_stats *stats)	\
{									\
	stats->flags &= ~(1 << CASS_CFQG_stats_##name);			\
}									\
static inline int cass_cfqg_stats_##name(struct cass_cfqg_stats *stats)		\
{									\
	return (stats->flags & (1 << CASS_CFQG_stats_##name)) != 0;		\
}									\

CASS_CFQG_FLAG_FNS(waiting)
CASS_CFQG_FLAG_FNS(idling)
CASS_CFQG_FLAG_FNS(empty)
#undef CASS_CFQG_FLAG_FNS

/* This should be called with the queue_lock held. */
static void cass_cfqg_stats_update_group_wait_time(struct cass_cfqg_stats *stats)
{
	unsigned long long now;

	if (!cass_cfqg_stats_waiting(stats))
		return;

	now = sched_clock();
	if (time_after64(now, stats->start_group_wait_time))
		blkg_stat_add(&stats->group_wait_time,
			      now - stats->start_group_wait_time);
	cass_cfqg_stats_clear_waiting(stats);
}

/* This should be called with the queue_lock held. */
static void cass_cfqg_stats_set_start_group_wait_time(struct cass_cfq_group *cass_cfqg,
						 struct cass_cfq_group *curr_cass_cfqg)
{
	struct cass_cfqg_stats *stats = &cass_cfqg->stats;

	if (cass_cfqg_stats_waiting(stats))
		return;
	if (cass_cfqg == curr_cass_cfqg)
		return;
	stats->start_group_wait_time = sched_clock();
	cass_cfqg_stats_mark_waiting(stats);
}

/* This should be called with the queue_lock held. */
static void cass_cfqg_stats_end_empty_time(struct cass_cfqg_stats *stats)
{
	unsigned long long now;

	if (!cass_cfqg_stats_empty(stats))
		return;

	now = sched_clock();
	if (time_after64(now, stats->start_empty_time))
		blkg_stat_add(&stats->empty_time,
			      now - stats->start_empty_time);
	cass_cfqg_stats_clear_empty(stats);
}

static void cass_cfqg_stats_update_dequeue(struct cass_cfq_group *cass_cfqg)
{
	blkg_stat_add(&cass_cfqg->stats.dequeue, 1);
}

static void cass_cfqg_stats_set_start_empty_time(struct cass_cfq_group *cass_cfqg)
{
	struct cass_cfqg_stats *stats = &cass_cfqg->stats;

	if (blkg_rwstat_total(&stats->queued))
		return;

	/*
	 * group is already marked empty. This can happen if cass_cfqq got new
	 * request in parent group and moved to this group while being added
	 * to service tree. Just ignore the event and move on.
	 */
	if (cass_cfqg_stats_empty(stats))
		return;

	stats->start_empty_time = sched_clock();
	cass_cfqg_stats_mark_empty(stats);
}

static void cass_cfqg_stats_update_idle_time(struct cass_cfq_group *cass_cfqg)
{
	struct cass_cfqg_stats *stats = &cass_cfqg->stats;

	if (cass_cfqg_stats_idling(stats)) {
		unsigned long long now = sched_clock();

		if (time_after64(now, stats->start_idle_time))
			blkg_stat_add(&stats->idle_time,
				      now - stats->start_idle_time);
		cass_cfqg_stats_clear_idling(stats);
	}
}

static void cass_cfqg_stats_set_start_idle_time(struct cass_cfq_group *cass_cfqg)
{
	struct cass_cfqg_stats *stats = &cass_cfqg->stats;

	BUG_ON(cass_cfqg_stats_idling(stats));

	stats->start_idle_time = sched_clock();
	cass_cfqg_stats_mark_idling(stats);
}

static void cass_cfqg_stats_update_avg_queue_size(struct cass_cfq_group *cass_cfqg)
{
	struct cass_cfqg_stats *stats = &cass_cfqg->stats;

	blkg_stat_add(&stats->avg_queue_size_sum,
		      blkg_rwstat_total(&stats->queued));
	blkg_stat_add(&stats->avg_queue_size_samples, 1);
	cass_cfqg_stats_update_group_wait_time(stats);
}

#else	/* CONFIG_CASS_CFQ_GROUP_IOSCHED && CONFIG_DEBUG_BLK_CGROUP */

static inline void cass_cfqg_stats_set_start_group_wait_time(struct cass_cfq_group *cass_cfqg, struct cass_cfq_group *curr_cass_cfqg) { }
static inline void cass_cfqg_stats_end_empty_time(struct cass_cfqg_stats *stats) { }
static inline void cass_cfqg_stats_update_dequeue(struct cass_cfq_group *cass_cfqg) { }
static inline void cass_cfqg_stats_set_start_empty_time(struct cass_cfq_group *cass_cfqg) { }
static inline void cass_cfqg_stats_update_idle_time(struct cass_cfq_group *cass_cfqg) { }
static inline void cass_cfqg_stats_set_start_idle_time(struct cass_cfq_group *cass_cfqg) { }
static inline void cass_cfqg_stats_update_avg_queue_size(struct cass_cfq_group *cass_cfqg) { }

#endif	/* CONFIG_CASS_CFQ_GROUP_IOSCHED && CONFIG_DEBUG_BLK_CGROUP */

#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED

static inline struct cass_cfq_group *pd_to_cass_cfqg(struct blkg_policy_data *pd)
{
	return pd ? container_of(pd, struct cass_cfq_group, pd) : NULL;
}

static struct cass_cfq_group_data
*cpd_to_cass_cfqgd(struct blkcg_policy_data *cpd)
{
	return cpd ? container_of(cpd, struct cass_cfq_group_data, cpd) : NULL;
}

static inline struct blkcg_gq *cass_cfqg_to_blkg(struct cass_cfq_group *cass_cfqg)
{
	return pd_to_blkg(&cass_cfqg->pd);
}

static struct blkcg_policy blkcg_policy_cass_cfq;

static inline struct cass_cfq_group *blkg_to_cass_cfqg(struct blkcg_gq *blkg)
{
	return pd_to_cass_cfqg(blkg_to_pd(blkg, &blkcg_policy_cass_cfq));
}

static struct cass_cfq_group_data *blkcg_to_cass_cfqgd(struct blkcg *blkcg)
{
	return cpd_to_cass_cfqgd(blkcg_to_cpd(blkcg, &blkcg_policy_cass_cfq));
}

static inline struct cass_cfq_group *cass_cfqg_parent(struct cass_cfq_group *cass_cfqg)
{
	struct blkcg_gq *pblkg = cass_cfqg_to_blkg(cass_cfqg)->parent;

	return pblkg ? blkg_to_cass_cfqg(pblkg) : NULL;
}

static inline bool cass_cfqg_is_descendant(struct cass_cfq_group *cass_cfqg,
				      struct cass_cfq_group *ancestor)
{
	return cgroup_is_descendant(cass_cfqg_to_blkg(cass_cfqg)->blkcg->css.cgroup,
				    cass_cfqg_to_blkg(ancestor)->blkcg->css.cgroup);
}

static inline void cass_cfqg_get(struct cass_cfq_group *cass_cfqg)
{
	return blkg_get(cass_cfqg_to_blkg(cass_cfqg));
}

static inline void cass_cfqg_put(struct cass_cfq_group *cass_cfqg)
{
	return blkg_put(cass_cfqg_to_blkg(cass_cfqg));
}

#define cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, fmt, args...)	do {			\
	char __pbuf[128];						\
									\
	blkg_path(cass_cfqg_to_blkg((cass_cfqq)->cass_cfqg), __pbuf, sizeof(__pbuf));	\
	blk_add_trace_msg((cass_cfqd)->queue, "cass_cfq%d%c%c %s " fmt, (cass_cfqq)->pid, \
			cass_cfqq_sync((cass_cfqq)) ? 'S' : 'A',		\
			cass_cfqq_type((cass_cfqq)) == SYNC_NOIDLE_WORKLOAD ? 'N' : ' ',\
			  __pbuf, ##args);				\
} while (0)

#define cass_cfq_log_cass_cfqg(cass_cfqd, cass_cfqg, fmt, args...)	do {			\
	char __pbuf[128];						\
									\
	blkg_path(cass_cfqg_to_blkg(cass_cfqg), __pbuf, sizeof(__pbuf));		\
	blk_add_trace_msg((cass_cfqd)->queue, "%s " fmt, __pbuf, ##args);	\
} while (0)

static inline void cass_cfqg_stats_update_io_add(struct cass_cfq_group *cass_cfqg,
					    struct cass_cfq_group *curr_cass_cfqg,
					    unsigned int op)
{
	blkg_rwstat_add(&cass_cfqg->stats.queued, op, 1);
	cass_cfqg_stats_end_empty_time(&cass_cfqg->stats);
	cass_cfqg_stats_set_start_group_wait_time(cass_cfqg, curr_cass_cfqg);
}

static inline void cass_cfqg_stats_update_timeslice_used(struct cass_cfq_group *cass_cfqg,
			uint64_t time, unsigned long unaccounted_time)
{
	blkg_stat_add(&cass_cfqg->stats.time, time);
#ifdef CONFIG_DEBUG_BLK_CGROUP
	blkg_stat_add(&cass_cfqg->stats.unaccounted_time, unaccounted_time);
#endif
}

static inline void cass_cfqg_stats_update_io_remove(struct cass_cfq_group *cass_cfqg,
					       unsigned int op)
{
	blkg_rwstat_add(&cass_cfqg->stats.queued, op, -1);
}

static inline void cass_cfqg_stats_update_io_merged(struct cass_cfq_group *cass_cfqg,
					       unsigned int op)
{
	blkg_rwstat_add(&cass_cfqg->stats.merged, op, 1);
}

static inline void cass_cfqg_stats_update_completion(struct cass_cfq_group *cass_cfqg,
			uint64_t start_time, uint64_t io_start_time,
			unsigned int op)
{
	struct cass_cfqg_stats *stats = &cass_cfqg->stats;
	unsigned long long now = sched_clock();

	if (time_after64(now, io_start_time))
		blkg_rwstat_add(&stats->service_time, op, now - io_start_time);
	if (time_after64(io_start_time, start_time))
		blkg_rwstat_add(&stats->wait_time, op,
				io_start_time - start_time);
}

/* @stats = 0 */
static void cass_cfqg_stats_reset(struct cass_cfqg_stats *stats)
{
	/* queued stats shouldn't be cleared */
	blkg_rwstat_reset(&stats->merged);
	blkg_rwstat_reset(&stats->service_time);
	blkg_rwstat_reset(&stats->wait_time);
	blkg_stat_reset(&stats->time);
#ifdef CONFIG_DEBUG_BLK_CGROUP
	blkg_stat_reset(&stats->unaccounted_time);
	blkg_stat_reset(&stats->avg_queue_size_sum);
	blkg_stat_reset(&stats->avg_queue_size_samples);
	blkg_stat_reset(&stats->dequeue);
	blkg_stat_reset(&stats->group_wait_time);
	blkg_stat_reset(&stats->idle_time);
	blkg_stat_reset(&stats->empty_time);
#endif
}

/* @to += @from */
static void cass_cfqg_stats_add_aux(struct cass_cfqg_stats *to, struct cass_cfqg_stats *from)
{
	/* queued stats shouldn't be cleared */
	blkg_rwstat_add_aux(&to->merged, &from->merged);
	blkg_rwstat_add_aux(&to->service_time, &from->service_time);
	blkg_rwstat_add_aux(&to->wait_time, &from->wait_time);
	blkg_stat_add_aux(&from->time, &from->time);
#ifdef CONFIG_DEBUG_BLK_CGROUP
	blkg_stat_add_aux(&to->unaccounted_time, &from->unaccounted_time);
	blkg_stat_add_aux(&to->avg_queue_size_sum, &from->avg_queue_size_sum);
	blkg_stat_add_aux(&to->avg_queue_size_samples, &from->avg_queue_size_samples);
	blkg_stat_add_aux(&to->dequeue, &from->dequeue);
	blkg_stat_add_aux(&to->group_wait_time, &from->group_wait_time);
	blkg_stat_add_aux(&to->idle_time, &from->idle_time);
	blkg_stat_add_aux(&to->empty_time, &from->empty_time);
#endif
}

/*
 * Transfer @cass_cfqg's stats to its parent's aux counts so that the ancestors'
 * recursive stats can still account for the amount used by this cass_cfqg after
 * it's gone.
 */
static void cass_cfqg_stats_xfer_dead(struct cass_cfq_group *cass_cfqg)
{
	struct cass_cfq_group *parent = cass_cfqg_parent(cass_cfqg);

	lockdep_assert_held(cass_cfqg_to_blkg(cass_cfqg)->q->queue_lock);

	if (unlikely(!parent))
		return;

	cass_cfqg_stats_add_aux(&parent->stats, &cass_cfqg->stats);
	cass_cfqg_stats_reset(&cass_cfqg->stats);
}

#else	/* CONFIG_CASS_CFQ_GROUP_IOSCHED */

static inline struct cass_cfq_group *cass_cfqg_parent(struct cass_cfq_group *cass_cfqg) { return NULL; }
static inline bool cass_cfqg_is_descendant(struct cass_cfq_group *cass_cfqg,
				      struct cass_cfq_group *ancestor)
{
	return true;
}
static inline void cass_cfqg_get(struct cass_cfq_group *cass_cfqg) { }
static inline void cass_cfqg_put(struct cass_cfq_group *cass_cfqg) { }

#define cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, fmt, args...)	\
	blk_add_trace_msg((cass_cfqd)->queue, "cass_cfq%d%c%c " fmt, (cass_cfqq)->pid,	\
			cass_cfqq_sync((cass_cfqq)) ? 'S' : 'A',		\
			cass_cfqq_type((cass_cfqq)) == SYNC_NOIDLE_WORKLOAD ? 'N' : ' ',\
				##args)
#define cass_cfq_log_cass_cfqg(cass_cfqd, cass_cfqg, fmt, args...)		do {} while (0)

static inline void cass_cfqg_stats_update_io_add(struct cass_cfq_group *cass_cfqg,
			struct cass_cfq_group *curr_cass_cfqg, unsigned int op) { }
static inline void cass_cfqg_stats_update_timeslice_used(struct cass_cfq_group *cass_cfqg,
			uint64_t time, unsigned long unaccounted_time) { }
static inline void cass_cfqg_stats_update_io_remove(struct cass_cfq_group *cass_cfqg,
			unsigned int op) { }
static inline void cass_cfqg_stats_update_io_merged(struct cass_cfq_group *cass_cfqg,
			unsigned int op) { }
static inline void cass_cfqg_stats_update_completion(struct cass_cfq_group *cass_cfqg,
			uint64_t start_time, uint64_t io_start_time,
			unsigned int op) { }

#endif	/* CONFIG_CASS_CFQ_GROUP_IOSCHED */

#define cass_cfq_log(cass_cfqd, fmt, args...)	\
	blk_add_trace_msg((cass_cfqd)->queue, "cass_cfq " fmt, ##args)

/* Traverses through cass_cfq group service trees */
#define for_each_cass_cfqg_st(cass_cfqg, i, j, st) \
	for (i = 0; i <= IDLE_WORKLOAD; i++) \
		for (j = 0, st = i < IDLE_WORKLOAD ? &cass_cfqg->service_trees[i][j]\
			: &cass_cfqg->service_tree_idle; \
			(i < IDLE_WORKLOAD && j <= SYNC_WORKLOAD) || \
			(i == IDLE_WORKLOAD && j == 0); \
			j++, st = i < IDLE_WORKLOAD ? \
			&cass_cfqg->service_trees[i][j]: NULL) \

static inline bool cass_cfq_io_thinktime_big(struct cass_cfq_data *cass_cfqd,
	struct cass_cfq_ttime *ttime, bool group_idle)
{
	u64 slice;
	if (!sample_valid(ttime->ttime_samples))
		return false;
	if (group_idle)
		slice = cass_cfqd->cass_cfq_group_idle;
	else
		slice = cass_cfqd->cass_cfq_slice_idle;
	return ttime->ttime_mean > slice;
}

static inline bool iops_mode(struct cass_cfq_data *cass_cfqd)
{
	/*
	 * If we are not idling on queues and it is a NCQ drive, parallel
	 * execution of requests is on and measuring time is not possible
	 * in most of the cases until and unless we drive shallower queue
	 * depths and that becomes a performance bottleneck. In such cases
	 * switch to start providing fairness in terms of number of IOs.
	 */
	if (!cass_cfqd->cass_cfq_slice_idle && cass_cfqd->hw_tag)
		return true;
	else
		return false;
}

static inline enum wl_class_t cass_cfqq_class(struct cass_cfq_queue *cass_cfqq)
{
	if (cass_cfq_class_idle(cass_cfqq))
		return IDLE_WORKLOAD;
	if (cass_cfq_class_rt(cass_cfqq))
		return RT_WORKLOAD;
	return BE_WORKLOAD;
}


static enum wl_type_t cass_cfqq_type(struct cass_cfq_queue *cass_cfqq)
{
	if (!cass_cfqq_sync(cass_cfqq))
		return ASYNC_WORKLOAD;
	if (!cass_cfqq_idle_window(cass_cfqq))
		return SYNC_NOIDLE_WORKLOAD;
	return SYNC_WORKLOAD;
}

static inline int cass_cfq_group_busy_queues_wl(enum wl_class_t wl_class,
					struct cass_cfq_data *cass_cfqd,
					struct cass_cfq_group *cass_cfqg)
{
	if (wl_class == IDLE_WORKLOAD)
		return cass_cfqg->service_tree_idle.count;

	return cass_cfqg->service_trees[wl_class][ASYNC_WORKLOAD].count +
		cass_cfqg->service_trees[wl_class][SYNC_NOIDLE_WORKLOAD].count +
		cass_cfqg->service_trees[wl_class][SYNC_WORKLOAD].count;
}

static inline int cass_cfqg_busy_async_queues(struct cass_cfq_data *cass_cfqd,
					struct cass_cfq_group *cass_cfqg)
{
	return cass_cfqg->service_trees[RT_WORKLOAD][ASYNC_WORKLOAD].count +
		cass_cfqg->service_trees[BE_WORKLOAD][ASYNC_WORKLOAD].count;
}

static void cass_cfq_dispatch_insert(struct request_queue *, struct request *);
static struct cass_cfq_queue *cass_cfq_get_queue(struct cass_cfq_data *cass_cfqd, bool is_sync,
				       struct cass_cfq_io_cq *cic, struct bio *bio);

static inline struct cass_cfq_io_cq *icq_to_cic(struct io_cq *icq)
{
	/* cic->icq is the first member, %NULL will convert to %NULL */
	return container_of(icq, struct cass_cfq_io_cq, icq);
}

static inline struct cass_cfq_io_cq *cass_cfq_cic_lookup(struct cass_cfq_data *cass_cfqd,
					       struct io_context *ioc)
{
	if (ioc)
		return icq_to_cic(ioc_lookup_icq(ioc, cass_cfqd->queue));
	return NULL;
}

static inline struct cass_cfq_queue *cic_to_cass_cfqq(struct cass_cfq_io_cq *cic, bool is_sync)
{
	return cic->cass_cfqq[is_sync];
}

static inline void cic_set_cass_cfqq(struct cass_cfq_io_cq *cic, struct cass_cfq_queue *cass_cfqq,
				bool is_sync)
{
	cic->cass_cfqq[is_sync] = cass_cfqq;
}

static inline struct cass_cfq_data *cic_to_cass_cfqd(struct cass_cfq_io_cq *cic)
{
	return cic->icq.q->elevator->elevator_data;
}

/*
 * scheduler run of queue, if there are requests pending and no one in the
 * driver that will restart queueing
 */
static inline void cass_cfq_schedule_dispatch(struct cass_cfq_data *cass_cfqd)
{
	if (cass_cfqd->busy_queues) {
		cass_cfq_log(cass_cfqd, "schedule dispatch");
		kblockd_schedule_work(&cass_cfqd->unplug_work);
	}
}

/*
 * Scale schedule slice based on io priority. Use the sync time slice only
 * if a queue is marked sync and has sync io queued. A sync queue with async
 * io only, should not get full sync slice length.
 */
static inline u64 cass_cfq_prio_slice(struct cass_cfq_data *cass_cfqd, bool sync,
				 unsigned short prio)
{
	u64 base_slice = cass_cfqd->cass_cfq_slice[sync];
	u64 slice = div_u64(base_slice, CASS_CFQ_SLICE_SCALE);

	WARN_ON(prio >= IOPRIO_BE_NR);

	return base_slice + (slice * (4 - prio));
}

static inline u64
cass_cfq_prio_to_slice(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	return cass_cfq_prio_slice(cass_cfqd, cass_cfqq_sync(cass_cfqq), cass_cfqq->ioprio);
}

/**
 * cass_cfqg_scale_charge - scale disk time charge according to cass_cfqg weight
 * @charge: disk time being charged
 * @vfraction: vfraction of the cass_cfqg, fixed point w/ CASS_CFQ_SERVICE_SHIFT
 *
 * Scale @charge according to @vfraction, which is in range (0, 1].  The
 * scaling is inversely proportional.
 *
 * scaled = charge / vfraction
 *
 * The result is also in fixed point w/ CASS_CFQ_SERVICE_SHIFT.
 */
static inline u64 cass_cfqg_scale_charge(u64 charge,
				    unsigned int vfraction)
{
	u64 c = charge << CASS_CFQ_SERVICE_SHIFT;	/* make it fixed point */

	/* charge / vfraction */
	c <<= CASS_CFQ_SERVICE_SHIFT;
	return div_u64(c, vfraction);
}

static inline u64 max_vdisktime(u64 min_vdisktime, u64 vdisktime)
{
	s64 delta = (s64)(vdisktime - min_vdisktime);
	if (delta > 0)
		min_vdisktime = vdisktime;

	return min_vdisktime;
}

static inline u64 min_vdisktime(u64 min_vdisktime, u64 vdisktime)
{
	s64 delta = (s64)(vdisktime - min_vdisktime);
	if (delta < 0)
		min_vdisktime = vdisktime;

	return min_vdisktime;
}

static void update_min_vdisktime(struct cass_cfq_rb_root *st)
{
	struct cass_cfq_group *cass_cfqg;

	if (st->left) {
		cass_cfqg = rb_entry_cass_cfqg(st->left);
		st->min_vdisktime = max_vdisktime(st->min_vdisktime,
						  cass_cfqg->vdisktime);
	}
}

/*
 * get averaged number of queues of RT/BE priority.
 * average is updated, with a formula that gives more weight to higher numbers,
 * to quickly follows sudden increases and decrease slowly
 */

static inline unsigned cass_cfq_group_get_avg_queues(struct cass_cfq_data *cass_cfqd,
					struct cass_cfq_group *cass_cfqg, bool rt)
{
	unsigned min_q, max_q;
	unsigned mult  = cass_cfq_hist_divisor - 1;
	unsigned round = cass_cfq_hist_divisor / 2;
	unsigned busy = cass_cfq_group_busy_queues_wl(rt, cass_cfqd, cass_cfqg);

	min_q = min(cass_cfqg->busy_queues_avg[rt], busy);
	max_q = max(cass_cfqg->busy_queues_avg[rt], busy);
	cass_cfqg->busy_queues_avg[rt] = (mult * max_q + min_q + round) /
		cass_cfq_hist_divisor;
	return cass_cfqg->busy_queues_avg[rt];
}

static inline u64
cass_cfq_group_slice(struct cass_cfq_data *cass_cfqd, struct cass_cfq_group *cass_cfqg)
{
	return cass_cfqd->cass_cfq_target_latency * cass_cfqg->vfraction >> CASS_CFQ_SERVICE_SHIFT;
}

static inline u64
cass_cfq_scaled_cass_cfqq_slice(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	u64 slice = cass_cfq_prio_to_slice(cass_cfqd, cass_cfqq);
	if (cass_cfqd->cass_cfq_latency) {
		/*
		 * interested queues (we consider only the ones with the same
		 * priority class in the cass_cfq group)
		 */
		unsigned iq = cass_cfq_group_get_avg_queues(cass_cfqd, cass_cfqq->cass_cfqg,
						cass_cfq_class_rt(cass_cfqq));
		u64 sync_slice = cass_cfqd->cass_cfq_slice[1];
		u64 expect_latency = sync_slice * iq;
		u64 group_slice = cass_cfq_group_slice(cass_cfqd, cass_cfqq->cass_cfqg);

		if (expect_latency > group_slice) {
			u64 base_low_slice = 2 * cass_cfqd->cass_cfq_slice_idle;
			u64 low_slice;

			/* scale low_slice according to IO priority
			 * and sync vs async */
			low_slice = div64_u64(base_low_slice*slice, sync_slice);
			low_slice = min(slice, low_slice);
			/* the adapted slice value is scaled to fit all iqs
			 * into the target latency */
			slice = div64_u64(slice*group_slice, expect_latency);
			slice = max(slice, low_slice);
		}
	}
	return slice;
}

static inline void
cass_cfq_set_prio_slice(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	u64 slice = cass_cfq_scaled_cass_cfqq_slice(cass_cfqd, cass_cfqq);
	u64 now = ktime_get_ns();

	cass_cfqq->slice_start = now;
	cass_cfqq->slice_end = now + slice;
	cass_cfqq->allocated_slice = slice;
	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "set_slice=%llu", cass_cfqq->slice_end - now);
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d set_slice=%llu\n", cfqq->cfqg->weight, cfqq->pid, cfqq->slice_end - now);
}

/*
 * We need to wrap this check in cass_cfqq_slice_new(), since ->slice_end
 * isn't valid until the first request from the dispatch is activated
 * and the slice time set.
 */
static inline bool cass_cfq_slice_used(struct cass_cfq_queue *cass_cfqq)
{
	if (cass_cfqq_slice_new(cass_cfqq))
		return false;
	if (ktime_get_ns() < cass_cfqq->slice_end)
		return false;

	return true;
}

/*
 * Lifted from AS - choose which of rq1 and rq2 that is best served now.
 * We choose the request that is closest to the head right now. Distance
 * behind the head is penalized and only allowed to a certain extent.
 */
static struct request *
cass_cfq_choose_req(struct cass_cfq_data *cass_cfqd, struct request *rq1, struct request *rq2, sector_t last)
{
	sector_t s1, s2, d1 = 0, d2 = 0;
	unsigned long back_max;
#define CASS_CFQ_RQ1_WRAP	0x01 /* request 1 wraps */
#define CASS_CFQ_RQ2_WRAP	0x02 /* request 2 wraps */
	unsigned wrap = 0; /* bit mask: requests behind the disk head? */

	if (rq1 == NULL || rq1 == rq2)
		return rq2;
	if (rq2 == NULL)
		return rq1;

	if (rq_is_sync(rq1) != rq_is_sync(rq2))
		return rq_is_sync(rq1) ? rq1 : rq2;

	if ((rq1->cmd_flags ^ rq2->cmd_flags) & REQ_PRIO)
		return rq1->cmd_flags & REQ_PRIO ? rq1 : rq2;

	s1 = blk_rq_pos(rq1);
	s2 = blk_rq_pos(rq2);

	/*
	 * by definition, 1KiB is 2 sectors
	 */
	back_max = cass_cfqd->cass_cfq_back_max * 2;

	/*
	 * Strict one way elevator _except_ in the case where we allow
	 * short backward seeks which are biased as twice the cost of a
	 * similar forward seek.
	 */
	if (s1 >= last)
		d1 = s1 - last;
	else if (s1 + back_max >= last)
		d1 = (last - s1) * cass_cfqd->cass_cfq_back_penalty;
	else
		wrap |= CASS_CFQ_RQ1_WRAP;

	if (s2 >= last)
		d2 = s2 - last;
	else if (s2 + back_max >= last)
		d2 = (last - s2) * cass_cfqd->cass_cfq_back_penalty;
	else
		wrap |= CASS_CFQ_RQ2_WRAP;

	/* Found required data */

	/*
	 * By doing switch() on the bit mask "wrap" we avoid having to
	 * check two variables for all permutations: --> faster!
	 */
	switch (wrap) {
	case 0: /* common case for cass_cfq: rq1 and rq2 not wrapped */
		if (d1 < d2)
			return rq1;
		else if (d2 < d1)
			return rq2;
		else {
			if (s1 >= s2)
				return rq1;
			else
				return rq2;
		}

	case CASS_CFQ_RQ2_WRAP:
		return rq1;
	case CASS_CFQ_RQ1_WRAP:
		return rq2;
	case (CASS_CFQ_RQ1_WRAP|CASS_CFQ_RQ2_WRAP): /* both rqs wrapped */
	default:
		/*
		 * Since both rqs are wrapped,
		 * start with the one that's further behind head
		 * (--> only *one* back seek required),
		 * since back seek takes more time than forward.
		 */
		if (s1 <= s2)
			return rq1;
		else
			return rq2;
	}
}

/*
 * The below is leftmost cache rbtree addon
 */
static struct cass_cfq_queue *cass_cfq_rb_first(struct cass_cfq_rb_root *root)
{
	/* Service tree is empty */
	if (!root->count)
		return NULL;

	if (!root->left)
		root->left = rb_first(&root->rb);

	if (root->left)
		return rb_entry(root->left, struct cass_cfq_queue, rb_node);

	return NULL;
}

static struct cass_cfq_group *cass_cfq_rb_first_group(struct cass_cfq_rb_root *root)
{
	if (!root->left)
		root->left = rb_first(&root->rb);

	if (root->left)
		return rb_entry_cass_cfqg(root->left);

	return NULL;
}

static void rb_erase_init(struct rb_node *n, struct rb_root *root)
{
	rb_erase(n, root);
	RB_CLEAR_NODE(n);
}

static void cass_cfq_rb_erase(struct rb_node *n, struct cass_cfq_rb_root *root)
{
	if (root->left == n)
		root->left = NULL;
	rb_erase_init(n, &root->rb);
	--root->count;
}

/*
 * would be nice to take fifo expire time into account as well
 */
static struct request *
cass_cfq_find_next_rq(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq,
		  struct request *last)
{
	struct rb_node *rbnext = rb_next(&last->rb_node);
	struct rb_node *rbprev = rb_prev(&last->rb_node);
	struct request *next = NULL, *prev = NULL;

	BUG_ON(RB_EMPTY_NODE(&last->rb_node));

	if (rbprev)
		prev = rb_entry_rq(rbprev);

	if (rbnext)
		next = rb_entry_rq(rbnext);
	else {
		rbnext = rb_first(&cass_cfqq->sort_list);
		if (rbnext && rbnext != &last->rb_node)
			next = rb_entry_rq(rbnext);
	}

	return cass_cfq_choose_req(cass_cfqd, next, prev, blk_rq_pos(last));
}

static u64 cass_cfq_slice_offset(struct cass_cfq_data *cass_cfqd,
			    struct cass_cfq_queue *cass_cfqq)
{
	/*
	 * just an approximation, should be ok.
	 */
	return (cass_cfqq->cass_cfqg->nr_cass_cfqq - 1) * (cass_cfq_prio_slice(cass_cfqd, 1, 0) -
		       cass_cfq_prio_slice(cass_cfqd, cass_cfqq_sync(cass_cfqq), cass_cfqq->ioprio));
}

static inline s64
cass_cfqg_key(struct cass_cfq_rb_root *st, struct cass_cfq_group *cass_cfqg)
{
	return cass_cfqg->vdisktime - st->min_vdisktime;
}

static void
__cass_cfq_group_service_tree_add(struct cass_cfq_rb_root *st, struct cass_cfq_group *cass_cfqg)
{
	struct rb_node **node = &st->rb.rb_node;
	struct rb_node *parent = NULL;
	struct cass_cfq_group *__cass_cfqg;
	s64 key = cass_cfqg_key(st, cass_cfqg);
	int left = 1;

	while (*node != NULL) {
		parent = *node;
		__cass_cfqg = rb_entry_cass_cfqg(parent);

		if (key < cass_cfqg_key(st, __cass_cfqg))
			node = &parent->rb_left;
		else {
			node = &parent->rb_right;
			left = 0;
		}
	}

	if (left)
		st->left = &cass_cfqg->rb_node;

	rb_link_node(&cass_cfqg->rb_node, parent, node);
	rb_insert_color(&cass_cfqg->rb_node, &st->rb);
}

static void
__cass_cfq_group_service_tree_print(struct cfq_rb_root *st)
{
	struct rb_root *root = &st->rb;
	struct rb_node *node = rb_first(root);
	struct cfq_group *cfqg = cfq_rb_first_group(st);
	struct cfq_group *__cfqg;

	while(node != NULL){
		__cfqg = rb_entry_cfqg(node);
		trace_printk("Traversal: weight: %d vdisktime: %llu vfraction: %u\n", __cfqg->weight, __cfqg->vdisktime, __cfqg->vfraction);
		node = rb_next(node);
	}
	trace_printk("first group: weight: %d vdisktime: %llu vfraction: %u\n",cfqg->weight,cfqg->vdisktime, cfqg->vfraction);
}

/*
 * This has to be called only on activation of cass_cfqg
 */
static void
cass_cfq_update_group_weight(struct cass_cfq_group *cass_cfqg)
{
	if (cass_cfqg->new_weight) {
		cass_cfqg->weight = cass_cfqg->new_weight;
		cass_cfqg->new_weight = 0;
	}
}

static void
cass_cfq_update_group_leaf_weight(struct cass_cfq_group *cass_cfqg)
{
	BUG_ON(!RB_EMPTY_NODE(&cass_cfqg->rb_node));

	if (cass_cfqg->new_leaf_weight) {
		cass_cfqg->leaf_weight = cass_cfqg->new_leaf_weight;
		cass_cfqg->new_leaf_weight = 0;
	}
}

static void
cass_cfq_group_service_tree_add(struct cass_cfq_rb_root *st, struct cass_cfq_group *cass_cfqg)
{
	unsigned int vfr = 1 << CASS_CFQ_SERVICE_SHIFT;	/* start with 1 */
	struct cass_cfq_group *pos = cass_cfqg;
	struct cass_cfq_group *parent;
	bool propagate;

	/* add to the service tree */
	BUG_ON(!RB_EMPTY_NODE(&cass_cfqg->rb_node));

	/*
	 * Update leaf_weight.  We cannot update weight at this point
	 * because cass_cfqg might already have been activated and is
	 * contributing its current weight to the parent's child_weight.
	 */
	cass_cfq_update_group_leaf_weight(cass_cfqg);
	__cass_cfq_group_service_tree_add(st, cass_cfqg);

	/*
	 * Activate @cass_cfqg and calculate the portion of vfraction @cass_cfqg is
	 * entitled to.  vfraction is calculated by walking the tree
	 * towards the root calculating the fraction it has at each level.
	 * The compounded ratio is how much vfraction @cass_cfqg owns.
	 *
	 * Start with the proportion tasks in this cass_cfqg has against active
	 * children cass_cfqgs - its leaf_weight against children_weight.
	 */
	propagate = !pos->nr_active++;
	pos->children_weight += pos->leaf_weight;
	vfr = vfr * pos->leaf_weight / pos->children_weight;

	/*
	 * Compound ->weight walking up the tree.  Both activation and
	 * vfraction calculation are done in the same loop.  Propagation
	 * stops once an already activated node is met.  vfraction
	 * calculation should always continue to the root.
	 */
	while ((parent = cass_cfqg_parent(pos))) {
		if (propagate) {
			cass_cfq_update_group_weight(pos);
			propagate = !parent->nr_active++;
			parent->children_weight += pos->weight;
		}
		vfr = vfr * pos->weight / parent->children_weight;
		pos = parent;
	}

	cass_cfqg->vfraction = max_t(unsigned, vfr, 1);
}

static void
cass_cfq_group_notify_queue_add(struct cass_cfq_data *cass_cfqd, struct cass_cfq_group *cass_cfqg)
{
	struct cass_cfq_rb_root *st = &cass_cfqd->grp_service_tree;
	struct cass_cfq_group *__cass_cfqg;
	struct rb_node *n;

	cass_cfqg->nr_cass_cfqq++;
	if (!RB_EMPTY_NODE(&cass_cfqg->rb_node))
		return;

	/*
	 * Currently put the group at the end. Later implement something
	 * so that groups get lesser vtime based on their weights, so that
	 * if group does not loose all if it was not continuously backlogged.
	 */
	n = rb_last(&st->rb);
	if (n) {
		__cass_cfqg = rb_entry_cass_cfqg(n);
		cass_cfqg->vdisktime = __cass_cfqg->vdisktime + CASS_CFQ_IDLE_DELAY;
		if(cfqg->weight == 201 || cfqg->weight == 399 || cfqg->weight == 400 || cfqg->weight == 401 || cfqg->weight == 402 || cfqg->weight == 600 || cfqg->weight == 800 || cfqg->weight == 250 || cfqg->weight == 501 || cfqg->weight == 750)
			trace_printk("cfq_group_notify_queue_add: weight: %d, vdisktime: %llu __cfqg->vdisktime: %llu\n",
				cfqg->weight, cfqg->vdisktime, __cfqg->vdisktime);
	} else{
		cass_cfqg->vdisktime = st->min_vdisktime;
		//if(cfqg->weight == 250 || cfqg->weight == 501 || cfqg->weight == 750)
		if(cfqg->weight == 201 || cfqg->weight == 399 || cfqg->weight == 400 || cfqg->weight == 401 || cfqg->weight == 402 || cfqg->weight == 600 || cfqg->weight == 800)
			trace_printk("cfq_group_notify_queue_add: weight: %d vdisktime: %llu st->min_vdisktime\n",
					cfqg->weight, cfqg->vdisktime, st->min_vdisktime);
	}	
	cass_cfq_group_service_tree_add(st, cass_cfqg);
}

static void
cass_cfq_group_service_tree_del(struct cass_cfq_rb_root *st, struct cass_cfq_group *cass_cfqg)
{
	struct cass_cfq_group *pos = cass_cfqg;
	bool propagate;

	/*
	 * Undo activation from cass_cfq_group_service_tree_add().  Deactivate
	 * @cass_cfqg and propagate deactivation upwards.
	 */
	propagate = !--pos->nr_active;
	pos->children_weight -= pos->leaf_weight;

	while (propagate) {
		struct cass_cfq_group *parent = cass_cfqg_parent(pos);

		/* @pos has 0 nr_active at this point */
		WARN_ON_ONCE(pos->children_weight);
		pos->vfraction = 0;

		if (!parent)
			break;

		propagate = !--parent->nr_active;
		parent->children_weight -= pos->weight;
		pos = parent;
	}

	/* remove from the service tree */
	if (!RB_EMPTY_NODE(&cass_cfqg->rb_node))
		cass_cfq_rb_erase(&cass_cfqg->rb_node, st);
}

static void
cass_cfq_group_notify_queue_del(struct cass_cfq_data *cass_cfqd, struct cass_cfq_group *cass_cfqg)
{
	struct cass_cfq_rb_root *st = &cass_cfqd->grp_service_tree;

	BUG_ON(cass_cfqg->nr_cass_cfqq < 1);
	cass_cfqg->nr_cass_cfqq--;

	/* If there are other cass_cfq queues under this group, don't delete it */
	if (cass_cfqg->nr_cass_cfqq)
		return;

	cass_cfq_log_cass_cfqg(cass_cfqd, cass_cfqg, "del_from_rr group");
	if(cfqg->weight == 201 || cfqg->weight == 399 || cfqg->weight == 400 || cfqg->weight == 401 || cfqg->weight == 402 || cfqg->weight == 600 || cfqg->weight == 800 || cfqg->weight == 501 || cfqg->weight == 750 || cfqg->weight == 250)
		trace_printk("weight: %d del_from_rr_group\n", cfqg->weight);
	cass_cfq_group_service_tree_del(st, cass_cfqg);
	cass_cfqg->saved_wl_slice = 0;
	cass_cfqg_stats_update_dequeue(cass_cfqg);
}

static inline u64 cass_cfqq_slice_usage(struct cass_cfq_queue *cass_cfqq,
				       u64 *unaccounted_time)
{
	u64 slice_used;
	u64 now = ktime_get_ns();

	/*
	 * Queue got expired before even a single request completed or
	 * got expired immediately after first request completion.
	 */
	if (!cass_cfqq->slice_start || cass_cfqq->slice_start == now) {
		/*
		 * Also charge the seek time incurred to the group, otherwise
		 * if there are mutiple queues in the group, each can dispatch
		 * a single request on seeky media and cause lots of seek time
		 * and group will never know it.
		 */
		slice_used = max_t(u64, (now - cass_cfqq->dispatch_start),
					jiffies_to_nsecs(1));
	} else {
		slice_used = now - cass_cfqq->slice_start;
		if (slice_used > cass_cfqq->allocated_slice) {
			*unaccounted_time = slice_used - cass_cfqq->allocated_slice;
			slice_used = cass_cfqq->allocated_slice;
		}
		if (cass_cfqq->slice_start > cass_cfqq->dispatch_start)
			*unaccounted_time += cass_cfqq->slice_start -
					cass_cfqq->dispatch_start;
	}

	return slice_used;
}

static void cass_cfq_group_served(struct cass_cfq_data *cass_cfqd, struct cass_cfq_group *cass_cfqg,
				struct cass_cfq_queue *cass_cfqq)
{
	struct cass_cfq_rb_root *st = &cass_cfqd->grp_service_tree;
	u64 used_sl, charge, unaccounted_sl = 0;
	int nr_sync = cass_cfqg->nr_cass_cfqq - cass_cfqg_busy_async_queues(cass_cfqd, cass_cfqg)
			- cass_cfqg->service_tree_idle.count;
	unsigned int vfr;
	u64 now = ktime_get_ns();

	BUG_ON(nr_sync < 0);
	used_sl = charge = cass_cfqq_slice_usage(cass_cfqq, &unaccounted_sl);

	if (iops_mode(cass_cfqd)){
		/* scaling charge to proportionally allocate disk time based on the weight */
		charge = cfqq->slice_dispatch * 1000000000;
		charge = div_u64(charge, cfqg->weight);
	}
	else if (!cass_cfqq_sync(cass_cfqq) && !nr_sync)
		charge = cass_cfqq->allocated_slice;

	/*
	 * Can't update vdisktime while on service tree and cass_cfqg->vfraction
	 * is valid only while on it.  Cache vfr, leave the service tree,
	 * update vdisktime and go back on.  The re-addition to the tree
	 * will also update the weights as necessary.
	 */
	vfr = cass_cfqg->vfraction;
	if(cfqg->weight == 201 || cfqg->weight == 600 || cfqg->weight == 399 || cfqg->weight == 400 || cfqg->weight == 402 || cfqg->weight == 401 || cfqg->weight == 800 || cfqg->weight == 250 || cfqg->weight == 501 || cfqg->weight == 750)
		__cass_cfq_group_service_tree_print(st);
	cass_cfq_group_service_tree_del(st, cass_cfqg);
	if(cfqg->weight == 201 || cfqg->weight == 600 || cfqg->weight == 399 || cfqg->weight == 400 || cfqg->weight == 402 || cfqg->weight == 401 || cfqg->weight == 800 || cfqg->weight == 250 || cfqg->weight == 501 || cfqg->weight == 750)
		trace_printk("weight: %d previous vdisktime: %llu vfraction: %u charge: %llu\n", cfqg->weight, cfqg->vdisktime, cfqg->vfraction, charge);
	cass_cfqg->vdisktime += cass_cfqg_scale_charge(charge, vfr);
	if(cfqg->weight == 201 || cfqg->weight == 600 || cfqg->weight == 399 || cfqg->weight == 400 || cfqg->weight == 402 || cfqg->weight == 401 || cfqg->weight == 800 || cfqg->weight == 250 || cfqg->weight == 501 || cfqg->weight == 750)
		trace_printk("weight: %d  current vdisktime: %llu vfraction: %u\n", cfqg->weight, cfqg->vdisktime, cfqg->vfraction);
	cass_cfq_group_service_tree_add(st, cass_cfqg);
	if(cfqg->weight == 201 || cfqg->weight == 600 || cfqg->weight == 399 || cfqg->weight == 400 || cfqg->weight == 402 || cfqg->weight == 401 || cfqg->weight == 800 || cfqg->weight == 250 || cfqg->weight == 501 || cfqg->weight == 750)
		__cass_cfq_group_service_tree_print(st);

	/* This group is being expired. Save the context */
	if (cass_cfqd->workload_expires > now) {
		cass_cfqg->saved_wl_slice = cass_cfqd->workload_expires - now;
		cass_cfqg->saved_wl_type = cass_cfqd->serving_wl_type;
		cass_cfqg->saved_wl_class = cass_cfqd->serving_wl_class;
	} else
		cass_cfqg->saved_wl_slice = 0;

	cass_cfq_log_cass_cfqg(cass_cfqd, cass_cfqg, "served: vt=%llu min_vt=%llu", cass_cfqg->vdisktime,
					st->min_vdisktime);
	if(cfqg->weight == 201 || cfqg->weight == 600 || cfqg->weight == 399 || cfqg->weight == 400 || cfqg->weight == 402 || cfqg->weight == 401 || cfqg->weight == 800 || cfqg->weight == 250 || cfqg->weight == 501 || cfqg->weight == 750)
		trace_printk("weight: %d served: vt=%llu min_vt=%llu\n", cfqg->weight, cfqg->vdisktime,
			st->min_vdisktime);
	cass_cfq_log_cass_cfqq(cass_cfqq->cass_cfqd, cass_cfqq,
		     "sl_used=%llu disp=%llu charge=%llu iops=%u sect=%lu",
		     used_sl, cass_cfqq->slice_dispatch, charge,
		     iops_mode(cass_cfqd), cass_cfqq->nr_sectors);
	if(cfqg->weight == 201 || cfqg->weight == 600 || cfqg->weight == 399 || cfqg->weight == 400 || cfqg->weight == 402 || cfqg->weight == 401 || cfqg->weight == 800 || cfqg->weight == 250 || cfqg->weight == 501 || cfqg->weight == 750)
		trace_printk("weight: %d pid: %d sl_used=%llu sl_allocated=%llu disp=%llu charge=%llu iops=%u sect=%lu\n",
			 cfqg->weight, cfqq->pid, used_sl, cfqq->allocated_slice, cfqq->slice_dispatch, charge,
			 iops_mode(cfqd), cfqq->nr_sectors);
	cass_cfqg_stats_update_timeslice_used(cass_cfqg, used_sl, unaccounted_sl);
	cass_cfqg_stats_set_start_empty_time(cass_cfqg);
}

/**
 * cass_cfq_init_cass_cfqg_base - initialize base part of a cass_cfq_group
 * @cass_cfqg: cass_cfq_group to initialize
 *
 * Initialize the base part which is used whether %CONFIG_CASS_CFQ_GROUP_IOSCHED
 * is enabled or not.
 */
static void cass_cfq_init_cass_cfqg_base(struct cass_cfq_group *cass_cfqg)
{
	struct cass_cfq_rb_root *st;
	int i, j;

	for_each_cass_cfqg_st(cass_cfqg, i, j, st)
		*st = CASS_CFQ_RB_ROOT;
	RB_CLEAR_NODE(&cass_cfqg->rb_node);

	cass_cfqg->ttime.last_end_request = ktime_get_ns();
}

#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
static int __cass_cfq_set_weight(struct cgroup_subsys_state *css, u64 val,
			    bool on_dfl, bool reset_dev, bool is_leaf_weight);

static void cass_cfqg_stats_exit(struct cass_cfqg_stats *stats)
{
	blkg_rwstat_exit(&stats->merged);
	blkg_rwstat_exit(&stats->service_time);
	blkg_rwstat_exit(&stats->wait_time);
	blkg_rwstat_exit(&stats->queued);
	blkg_stat_exit(&stats->time);
#ifdef CONFIG_DEBUG_BLK_CGROUP
	blkg_stat_exit(&stats->unaccounted_time);
	blkg_stat_exit(&stats->avg_queue_size_sum);
	blkg_stat_exit(&stats->avg_queue_size_samples);
	blkg_stat_exit(&stats->dequeue);
	blkg_stat_exit(&stats->group_wait_time);
	blkg_stat_exit(&stats->idle_time);
	blkg_stat_exit(&stats->empty_time);
#endif
}

static int cass_cfqg_stats_init(struct cass_cfqg_stats *stats, gfp_t gfp)
{
	if (blkg_rwstat_init(&stats->merged, gfp) ||
	    blkg_rwstat_init(&stats->service_time, gfp) ||
	    blkg_rwstat_init(&stats->wait_time, gfp) ||
	    blkg_rwstat_init(&stats->queued, gfp) ||
	    blkg_stat_init(&stats->time, gfp))
		goto err;

#ifdef CONFIG_DEBUG_BLK_CGROUP
	if (blkg_stat_init(&stats->unaccounted_time, gfp) ||
	    blkg_stat_init(&stats->avg_queue_size_sum, gfp) ||
	    blkg_stat_init(&stats->avg_queue_size_samples, gfp) ||
	    blkg_stat_init(&stats->dequeue, gfp) ||
	    blkg_stat_init(&stats->group_wait_time, gfp) ||
	    blkg_stat_init(&stats->idle_time, gfp) ||
	    blkg_stat_init(&stats->empty_time, gfp))
		goto err;
#endif
	return 0;
err:
	cass_cfqg_stats_exit(stats);
	return -ENOMEM;
}

static struct blkcg_policy_data *cass_cfq_cpd_alloc(gfp_t gfp)
{
	struct cass_cfq_group_data *cgd;

	cgd = kzalloc(sizeof(*cgd), gfp);
	if (!cgd)
		return NULL;
	return &cgd->cpd;
}

static void cass_cfq_cpd_init(struct blkcg_policy_data *cpd)
{
	struct cass_cfq_group_data *cgd = cpd_to_cass_cfqgd(cpd);
	unsigned int weight = cgroup_subsys_on_dfl(io_cgrp_subsys) ?
			      CGROUP_WEIGHT_DFL : CASS_CFQ_WEIGHT_LEGACY_DFL;

	if (cpd_to_blkcg(cpd) == &blkcg_root)
		weight *= 2;

	cgd->weight = weight;
	cgd->leaf_weight = weight;
}

static void cass_cfq_cpd_free(struct blkcg_policy_data *cpd)
{
	kfree(cpd_to_cass_cfqgd(cpd));
}

static void cass_cfq_cpd_bind(struct blkcg_policy_data *cpd)
{
	struct blkcg *blkcg = cpd_to_blkcg(cpd);
	bool on_dfl = cgroup_subsys_on_dfl(io_cgrp_subsys);
	unsigned int weight = on_dfl ? CGROUP_WEIGHT_DFL : CASS_CFQ_WEIGHT_LEGACY_DFL;

	if (blkcg == &blkcg_root)
		weight *= 2;

	WARN_ON_ONCE(__cass_cfq_set_weight(&blkcg->css, weight, on_dfl, true, false));
	WARN_ON_ONCE(__cass_cfq_set_weight(&blkcg->css, weight, on_dfl, true, true));
}

static struct blkg_policy_data *cass_cfq_pd_alloc(gfp_t gfp, int node)
{
	struct cass_cfq_group *cass_cfqg;

	cass_cfqg = kzalloc_node(sizeof(*cass_cfqg), gfp, node);
	if (!cass_cfqg)
		return NULL;

	cass_cfq_init_cass_cfqg_base(cass_cfqg);
	if (cass_cfqg_stats_init(&cass_cfqg->stats, gfp)) {
		kfree(cass_cfqg);
		return NULL;
	}

	return &cass_cfqg->pd;
}

static void cass_cfq_pd_init(struct blkg_policy_data *pd)
{
	struct cass_cfq_group *cass_cfqg = pd_to_cass_cfqg(pd);
	struct cass_cfq_group_data *cgd = blkcg_to_cass_cfqgd(pd->blkg->blkcg);

	cass_cfqg->weight = cgd->weight;
	cass_cfqg->leaf_weight = cgd->leaf_weight;
}

static void cass_cfq_pd_offline(struct blkg_policy_data *pd)
{
	struct cass_cfq_group *cass_cfqg = pd_to_cass_cfqg(pd);
	int i;

	for (i = 0; i < IOPRIO_BE_NR; i++) {
		if (cass_cfqg->async_cass_cfqq[0][i])
			cass_cfq_put_queue(cass_cfqg->async_cass_cfqq[0][i]);
		if (cass_cfqg->async_cass_cfqq[1][i])
			cass_cfq_put_queue(cass_cfqg->async_cass_cfqq[1][i]);
	}

	if (cass_cfqg->async_idle_cass_cfqq)
		cass_cfq_put_queue(cass_cfqg->async_idle_cass_cfqq);

	/*
	 * @blkg is going offline and will be ignored by
	 * blkg_[rw]stat_recursive_sum().  Transfer stats to the parent so
	 * that they don't get lost.  If IOs complete after this point, the
	 * stats for them will be lost.  Oh well...
	 */
	cass_cfqg_stats_xfer_dead(cass_cfqg);
}

static void cass_cfq_pd_free(struct blkg_policy_data *pd)
{
	struct cass_cfq_group *cass_cfqg = pd_to_cass_cfqg(pd);

	cass_cfqg_stats_exit(&cass_cfqg->stats);
	return kfree(cass_cfqg);
}

static void cass_cfq_pd_reset_stats(struct blkg_policy_data *pd)
{
	struct cass_cfq_group *cass_cfqg = pd_to_cass_cfqg(pd);

	cass_cfqg_stats_reset(&cass_cfqg->stats);
}

static struct cass_cfq_group *cass_cfq_lookup_cass_cfqg(struct cass_cfq_data *cass_cfqd,
					 struct blkcg *blkcg)
{
	struct blkcg_gq *blkg;

	blkg = blkg_lookup(blkcg, cass_cfqd->queue);
	if (likely(blkg))
		return blkg_to_cass_cfqg(blkg);
	return NULL;
}

static void cass_cfq_link_cass_cfqq_cass_cfqg(struct cass_cfq_queue *cass_cfqq, struct cass_cfq_group *cass_cfqg)
{
	cass_cfqq->cass_cfqg = cass_cfqg;
	/* cass_cfqq reference on cass_cfqg */
	cass_cfqg_get(cass_cfqg);
}

static u64 cass_cfqg_prfill_weight_device(struct seq_file *sf,
				     struct blkg_policy_data *pd, int off)
{
	struct cass_cfq_group *cass_cfqg = pd_to_cass_cfqg(pd);

	if (!cass_cfqg->dev_weight)
		return 0;
	return __blkg_prfill_u64(sf, pd, cass_cfqg->dev_weight);
}

static int cass_cfqg_print_weight_device(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)),
			  cass_cfqg_prfill_weight_device, &blkcg_policy_cass_cfq,
			  0, false);
	return 0;
}

static u64 cass_cfqg_prfill_leaf_weight_device(struct seq_file *sf,
					  struct blkg_policy_data *pd, int off)
{
	struct cass_cfq_group *cass_cfqg = pd_to_cass_cfqg(pd);

	if (!cass_cfqg->dev_leaf_weight)
		return 0;
	return __blkg_prfill_u64(sf, pd, cass_cfqg->dev_leaf_weight);
}

static int cass_cfqg_print_leaf_weight_device(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)),
			  cass_cfqg_prfill_leaf_weight_device, &blkcg_policy_cass_cfq,
			  0, false);
	return 0;
}

static int cass_cfq_print_weight(struct seq_file *sf, void *v)
{
	struct blkcg *blkcg = css_to_blkcg(seq_css(sf));
	struct cass_cfq_group_data *cgd = blkcg_to_cass_cfqgd(blkcg);
	unsigned int val = 0;

	if (cgd)
		val = cgd->weight;

	seq_printf(sf, "%u\n", val);
	return 0;
}

static int cass_cfq_print_leaf_weight(struct seq_file *sf, void *v)
{
	struct blkcg *blkcg = css_to_blkcg(seq_css(sf));
	struct cass_cfq_group_data *cgd = blkcg_to_cass_cfqgd(blkcg);
	unsigned int val = 0;

	if (cgd)
		val = cgd->leaf_weight;

	seq_printf(sf, "%u\n", val);
	return 0;
}

static ssize_t __cass_cfqg_set_weight_device(struct kernfs_open_file *of,
					char *buf, size_t nbytes, loff_t off,
					bool on_dfl, bool is_leaf_weight)
{
	unsigned int min = on_dfl ? CGROUP_WEIGHT_MIN : CASS_CFQ_WEIGHT_LEGACY_MIN;
	unsigned int max = on_dfl ? CGROUP_WEIGHT_MAX : CASS_CFQ_WEIGHT_LEGACY_MAX;
	struct blkcg *blkcg = css_to_blkcg(of_css(of));
	struct blkg_conf_ctx ctx;
	struct cass_cfq_group *cass_cfqg;
	struct cass_cfq_group_data *cass_cfqgd;
	int ret;
	u64 v;

	ret = blkg_conf_prep(blkcg, &blkcg_policy_cass_cfq, buf, &ctx);
	if (ret)
		return ret;

	if (sscanf(ctx.body, "%llu", &v) == 1) {
		/* require "default" on dfl */
		ret = -ERANGE;
		if (!v && on_dfl)
			goto out_finish;
	} else if (!strcmp(strim(ctx.body), "default")) {
		v = 0;
	} else {
		ret = -EINVAL;
		goto out_finish;
	}

	cass_cfqg = blkg_to_cass_cfqg(ctx.blkg);
	cass_cfqgd = blkcg_to_cass_cfqgd(blkcg);

	ret = -ERANGE;
	if (!v || (v >= min && v <= max)) {
		if (!is_leaf_weight) {
			cass_cfqg->dev_weight = v;
			cass_cfqg->new_weight = v ?: cass_cfqgd->weight;
		} else {
			cass_cfqg->dev_leaf_weight = v;
			cass_cfqg->new_leaf_weight = v ?: cass_cfqgd->leaf_weight;
		}
		ret = 0;
	}
out_finish:
	blkg_conf_finish(&ctx);
	return ret ?: nbytes;
}

static ssize_t cass_cfqg_set_weight_device(struct kernfs_open_file *of,
				      char *buf, size_t nbytes, loff_t off)
{
	return __cass_cfqg_set_weight_device(of, buf, nbytes, off, false, false);
}

static ssize_t cass_cfqg_set_leaf_weight_device(struct kernfs_open_file *of,
					   char *buf, size_t nbytes, loff_t off)
{
	return __cass_cfqg_set_weight_device(of, buf, nbytes, off, false, true);
}

static int __cass_cfq_set_weight(struct cgroup_subsys_state *css, u64 val,
			    bool on_dfl, bool reset_dev, bool is_leaf_weight)
{
	unsigned int min = on_dfl ? CGROUP_WEIGHT_MIN : CASS_CFQ_WEIGHT_LEGACY_MIN;
	unsigned int max = on_dfl ? CGROUP_WEIGHT_MAX : CASS_CFQ_WEIGHT_LEGACY_MAX;
	struct blkcg *blkcg = css_to_blkcg(css);
	struct blkcg_gq *blkg;
	struct cass_cfq_group_data *cass_cfqgd;
	int ret = 0;

	if (val < min || val > max)
		return -ERANGE;

	spin_lock_irq(&blkcg->lock);
	cass_cfqgd = blkcg_to_cass_cfqgd(blkcg);
	if (!cass_cfqgd) {
		ret = -EINVAL;
		goto out;
	}

	if (!is_leaf_weight)
		cass_cfqgd->weight = val;
	else
		cass_cfqgd->leaf_weight = val;

	hlist_for_each_entry(blkg, &blkcg->blkg_list, blkcg_node) {
		struct cass_cfq_group *cass_cfqg = blkg_to_cass_cfqg(blkg);

		if (!cass_cfqg)
			continue;

		if (!is_leaf_weight) {
			if (reset_dev)
				cass_cfqg->dev_weight = 0;
			if (!cass_cfqg->dev_weight)
				cass_cfqg->new_weight = cass_cfqgd->weight;
		} else {
			if (reset_dev)
				cass_cfqg->dev_leaf_weight = 0;
			if (!cass_cfqg->dev_leaf_weight)
				cass_cfqg->new_leaf_weight = cass_cfqgd->leaf_weight;
		}
	}

out:
	spin_unlock_irq(&blkcg->lock);
	return ret;
}

static int cass_cfq_set_weight(struct cgroup_subsys_state *css, struct cftype *cft,
			  u64 val)
{
	return __cass_cfq_set_weight(css, val, false, false, false);
}

static int cass_cfq_set_leaf_weight(struct cgroup_subsys_state *css,
			       struct cftype *cft, u64 val)
{
	return __cass_cfq_set_weight(css, val, false, false, true);
}

static int cass_cfqg_print_stat(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)), blkg_prfill_stat,
			  &blkcg_policy_cass_cfq, seq_cft(sf)->private, false);
	return 0;
}

static int cass_cfqg_print_rwstat(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)), blkg_prfill_rwstat,
			  &blkcg_policy_cass_cfq, seq_cft(sf)->private, true);
	return 0;
}

static u64 cass_cfqg_prfill_stat_recursive(struct seq_file *sf,
				      struct blkg_policy_data *pd, int off)
{
	u64 sum = blkg_stat_recursive_sum(pd_to_blkg(pd),
					  &blkcg_policy_cass_cfq, off);
	return __blkg_prfill_u64(sf, pd, sum);
}

static u64 cass_cfqg_prfill_rwstat_recursive(struct seq_file *sf,
					struct blkg_policy_data *pd, int off)
{
	struct blkg_rwstat sum = blkg_rwstat_recursive_sum(pd_to_blkg(pd),
							&blkcg_policy_cass_cfq, off);
	return __blkg_prfill_rwstat(sf, pd, &sum);
}

static int cass_cfqg_print_stat_recursive(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)),
			  cass_cfqg_prfill_stat_recursive, &blkcg_policy_cass_cfq,
			  seq_cft(sf)->private, false);
	return 0;
}

static int cass_cfqg_print_rwstat_recursive(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)),
			  cass_cfqg_prfill_rwstat_recursive, &blkcg_policy_cass_cfq,
			  seq_cft(sf)->private, true);
	return 0;
}

static u64 cass_cfqg_prfill_sectors(struct seq_file *sf, struct blkg_policy_data *pd,
			       int off)
{
	u64 sum = blkg_rwstat_total(&pd->blkg->stat_bytes);

	return __blkg_prfill_u64(sf, pd, sum >> 9);
}

static int cass_cfqg_print_stat_sectors(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)),
			  cass_cfqg_prfill_sectors, &blkcg_policy_cass_cfq, 0, false);
	return 0;
}

static u64 cass_cfqg_prfill_sectors_recursive(struct seq_file *sf,
					 struct blkg_policy_data *pd, int off)
{
	struct blkg_rwstat tmp = blkg_rwstat_recursive_sum(pd->blkg, NULL,
					offsetof(struct blkcg_gq, stat_bytes));
	u64 sum = atomic64_read(&tmp.aux_cnt[BLKG_RWSTAT_READ]) +
		atomic64_read(&tmp.aux_cnt[BLKG_RWSTAT_WRITE]);

	return __blkg_prfill_u64(sf, pd, sum >> 9);
}

static int cass_cfqg_print_stat_sectors_recursive(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)),
			  cass_cfqg_prfill_sectors_recursive, &blkcg_policy_cass_cfq, 0,
			  false);
	return 0;
}

#ifdef CONFIG_DEBUG_BLK_CGROUP
static u64 cass_cfqg_prfill_avg_queue_size(struct seq_file *sf,
				      struct blkg_policy_data *pd, int off)
{
	struct cass_cfq_group *cass_cfqg = pd_to_cass_cfqg(pd);
	u64 samples = blkg_stat_read(&cass_cfqg->stats.avg_queue_size_samples);
	u64 v = 0;

	if (samples) {
		v = blkg_stat_read(&cass_cfqg->stats.avg_queue_size_sum);
		v = div64_u64(v, samples);
	}
	__blkg_prfill_u64(sf, pd, v);
	return 0;
}

/* print avg_queue_size */
static int cass_cfqg_print_avg_queue_size(struct seq_file *sf, void *v)
{
	blkcg_print_blkgs(sf, css_to_blkcg(seq_css(sf)),
			  cass_cfqg_prfill_avg_queue_size, &blkcg_policy_cass_cfq,
			  0, false);
	return 0;
}
#endif	/* CONFIG_DEBUG_BLK_CGROUP */

static struct cftype cass_cfq_blkcg_legacy_files[] = {
	/* on root, weight is mapped to leaf_weight */
	{
		.name = "weight_device",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = cass_cfqg_print_leaf_weight_device,
		.write = cass_cfqg_set_leaf_weight_device,
	},
	{
		.name = "weight",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_show = cass_cfq_print_leaf_weight,
		.write_u64 = cass_cfq_set_leaf_weight,
	},

	/* no such mapping necessary for !roots */
	{
		.name = "weight_device",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = cass_cfqg_print_weight_device,
		.write = cass_cfqg_set_weight_device,
	},
	{
		.name = "weight",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = cass_cfq_print_weight,
		.write_u64 = cass_cfq_set_weight,
	},

	{
		.name = "leaf_weight_device",
		.seq_show = cass_cfqg_print_leaf_weight_device,
		.write = cass_cfqg_set_leaf_weight_device,
	},
	{
		.name = "leaf_weight",
		.seq_show = cass_cfq_print_leaf_weight,
		.write_u64 = cass_cfq_set_leaf_weight,
	},

	/* statistics, covers only the tasks in the cass_cfqg */
	{
		.name = "time",
		.private = offsetof(struct cass_cfq_group, stats.time),
		.seq_show = cass_cfqg_print_stat,
	},
	{
		.name = "sectors",
		.seq_show = cass_cfqg_print_stat_sectors,
	},
	{
		.name = "io_service_bytes",
		.private = (unsigned long)&blkcg_policy_cass_cfq,
		.seq_show = blkg_print_stat_bytes,
	},
	{
		.name = "io_serviced",
		.private = (unsigned long)&blkcg_policy_cass_cfq,
		.seq_show = blkg_print_stat_ios,
	},
	{
		.name = "io_service_time",
		.private = offsetof(struct cass_cfq_group, stats.service_time),
		.seq_show = cass_cfqg_print_rwstat,
	},
	{
		.name = "io_wait_time",
		.private = offsetof(struct cass_cfq_group, stats.wait_time),
		.seq_show = cass_cfqg_print_rwstat,
	},
	{
		.name = "io_merged",
		.private = offsetof(struct cass_cfq_group, stats.merged),
		.seq_show = cass_cfqg_print_rwstat,
	},
	{
		.name = "io_queued",
		.private = offsetof(struct cass_cfq_group, stats.queued),
		.seq_show = cass_cfqg_print_rwstat,
	},

	/* the same statictics which cover the cass_cfqg and its descendants */
	{
		.name = "time_recursive",
		.private = offsetof(struct cass_cfq_group, stats.time),
		.seq_show = cass_cfqg_print_stat_recursive,
	},
	{
		.name = "sectors_recursive",
		.seq_show = cass_cfqg_print_stat_sectors_recursive,
	},
	{
		.name = "io_service_bytes_recursive",
		.private = (unsigned long)&blkcg_policy_cass_cfq,
		.seq_show = blkg_print_stat_bytes_recursive,
	},
	{
		.name = "io_serviced_recursive",
		.private = (unsigned long)&blkcg_policy_cass_cfq,
		.seq_show = blkg_print_stat_ios_recursive,
	},
	{
		.name = "io_service_time_recursive",
		.private = offsetof(struct cass_cfq_group, stats.service_time),
		.seq_show = cass_cfqg_print_rwstat_recursive,
	},
	{
		.name = "io_wait_time_recursive",
		.private = offsetof(struct cass_cfq_group, stats.wait_time),
		.seq_show = cass_cfqg_print_rwstat_recursive,
	},
	{
		.name = "io_merged_recursive",
		.private = offsetof(struct cass_cfq_group, stats.merged),
		.seq_show = cass_cfqg_print_rwstat_recursive,
	},
	{
		.name = "io_queued_recursive",
		.private = offsetof(struct cass_cfq_group, stats.queued),
		.seq_show = cass_cfqg_print_rwstat_recursive,
	},
#ifdef CONFIG_DEBUG_BLK_CGROUP
	{
		.name = "avg_queue_size",
		.seq_show = cass_cfqg_print_avg_queue_size,
	},
	{
		.name = "group_wait_time",
		.private = offsetof(struct cass_cfq_group, stats.group_wait_time),
		.seq_show = cass_cfqg_print_stat,
	},
	{
		.name = "idle_time",
		.private = offsetof(struct cass_cfq_group, stats.idle_time),
		.seq_show = cass_cfqg_print_stat,
	},
	{
		.name = "empty_time",
		.private = offsetof(struct cass_cfq_group, stats.empty_time),
		.seq_show = cass_cfqg_print_stat,
	},
	{
		.name = "dequeue",
		.private = offsetof(struct cass_cfq_group, stats.dequeue),
		.seq_show = cass_cfqg_print_stat,
	},
	{
		.name = "unaccounted_time",
		.private = offsetof(struct cass_cfq_group, stats.unaccounted_time),
		.seq_show = cass_cfqg_print_stat,
	},
#endif	/* CONFIG_DEBUG_BLK_CGROUP */
	{ }	/* terminate */
};

static int cass_cfq_print_weight_on_dfl(struct seq_file *sf, void *v)
{
	struct blkcg *blkcg = css_to_blkcg(seq_css(sf));
	struct cass_cfq_group_data *cgd = blkcg_to_cass_cfqgd(blkcg);

	seq_printf(sf, "default %u\n", cgd->weight);
	blkcg_print_blkgs(sf, blkcg, cass_cfqg_prfill_weight_device,
			  &blkcg_policy_cass_cfq, 0, false);
	return 0;
}

static ssize_t cass_cfq_set_weight_on_dfl(struct kernfs_open_file *of,
				     char *buf, size_t nbytes, loff_t off)
{
	char *endp;
	int ret;
	u64 v;

	buf = strim(buf);

	/* "WEIGHT" or "default WEIGHT" sets the default weight */
	v = simple_strtoull(buf, &endp, 0);
	if (*endp == '\0' || sscanf(buf, "default %llu", &v) == 1) {
		ret = __cass_cfq_set_weight(of_css(of), v, true, false, false);
		return ret ?: nbytes;
	}

	/* "MAJ:MIN WEIGHT" */
	return __cass_cfqg_set_weight_device(of, buf, nbytes, off, true, false);
}

static struct cftype cass_cfq_blkcg_files[] = {
	{
		.name = "weight",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = cass_cfq_print_weight_on_dfl,
		.write = cass_cfq_set_weight_on_dfl,
	},
	{ }	/* terminate */
};

#else /* GROUP_IOSCHED */
static struct cass_cfq_group *cass_cfq_lookup_cass_cfqg(struct cass_cfq_data *cass_cfqd,
					 struct blkcg *blkcg)
{
	return cass_cfqd->root_group;
}

static inline void
cass_cfq_link_cass_cfqq_cass_cfqg(struct cass_cfq_queue *cass_cfqq, struct cass_cfq_group *cass_cfqg) {
	cass_cfqq->cass_cfqg = cass_cfqg;
}

#endif /* GROUP_IOSCHED */

/*
 * The cass_cfqd->service_trees holds all pending cass_cfq_queue's that have
 * requests waiting to be processed. It is sorted in the order that
 * we will service the queues.
 */
static void cass_cfq_service_tree_add(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq,
				 bool add_front)
{
	struct rb_node **p, *parent;
	struct cass_cfq_queue *__cass_cfqq;
	u64 rb_key;
	struct cass_cfq_rb_root *st;
	int left;
	int new_cass_cfqq = 1;
	u64 now = ktime_get_ns();

	st = st_for(cass_cfqq->cass_cfqg, cass_cfqq_class(cass_cfqq), cass_cfqq_type(cass_cfqq));
	if (cass_cfq_class_idle(cass_cfqq)) {
		rb_key = CASS_CFQ_IDLE_DELAY;
		parent = rb_last(&st->rb);
		if (parent && parent != &cass_cfqq->rb_node) {
			__cass_cfqq = rb_entry(parent, struct cass_cfq_queue, rb_node);
			rb_key += __cass_cfqq->rb_key;
		} else
			rb_key += now;
	} else if (!add_front) {
		/*
		 * Get our rb key offset. Subtract any residual slice
		 * value carried from last service. A negative resid
		 * count indicates slice overrun, and this should position
		 * the next service time further away in the tree.
		 */
		rb_key = cass_cfq_slice_offset(cass_cfqd, cass_cfqq) + now;
		rb_key -= cass_cfqq->slice_resid;
		cass_cfqq->slice_resid = 0;
	} else {
		rb_key = -NSEC_PER_SEC;
		__cass_cfqq = cass_cfq_rb_first(st);
		rb_key += __cass_cfqq ? __cass_cfqq->rb_key : now;
	}

	if (!RB_EMPTY_NODE(&cass_cfqq->rb_node)) {
		new_cass_cfqq = 0;
		/*
		 * same position, nothing more to do
		 */
		if (rb_key == cass_cfqq->rb_key && cass_cfqq->service_tree == st)
			return;

		cass_cfq_rb_erase(&cass_cfqq->rb_node, cass_cfqq->service_tree);
		cass_cfqq->service_tree = NULL;
	}

	left = 1;
	parent = NULL;
	cass_cfqq->service_tree = st;
	p = &st->rb.rb_node;
	while (*p) {
		parent = *p;
		__cass_cfqq = rb_entry(parent, struct cass_cfq_queue, rb_node);

		/*
		 * sort by key, that represents service time.
		 */
		if (rb_key < __cass_cfqq->rb_key)
			p = &parent->rb_left;
		else {
			p = &parent->rb_right;
			left = 0;
		}
	}

	if (left)
		st->left = &cass_cfqq->rb_node;

	cass_cfqq->rb_key = rb_key;
	rb_link_node(&cass_cfqq->rb_node, parent, p);
	rb_insert_color(&cass_cfqq->rb_node, &st->rb);
	st->count++;
	if (add_front || !new_cass_cfqq)
		return;
	cass_cfq_group_notify_queue_add(cass_cfqd, cass_cfqq->cass_cfqg);
}

static struct cass_cfq_queue *
cass_cfq_prio_tree_lookup(struct cass_cfq_data *cass_cfqd, struct rb_root *root,
		     sector_t sector, struct rb_node **ret_parent,
		     struct rb_node ***rb_link)
{
	struct rb_node **p, *parent;
	struct cass_cfq_queue *cass_cfqq = NULL;

	parent = NULL;
	p = &root->rb_node;
	while (*p) {
		struct rb_node **n;

		parent = *p;
		cass_cfqq = rb_entry(parent, struct cass_cfq_queue, p_node);

		/*
		 * Sort strictly based on sector.  Smallest to the left,
		 * largest to the right.
		 */
		if (sector > blk_rq_pos(cass_cfqq->next_rq))
			n = &(*p)->rb_right;
		else if (sector < blk_rq_pos(cass_cfqq->next_rq))
			n = &(*p)->rb_left;
		else
			break;
		p = n;
		cass_cfqq = NULL;
	}

	*ret_parent = parent;
	if (rb_link)
		*rb_link = p;
	return cass_cfqq;
}

static void cass_cfq_prio_tree_add(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	struct rb_node **p, *parent;
	struct cass_cfq_queue *__cass_cfqq;

	if (cass_cfqq->p_root) {
		rb_erase(&cass_cfqq->p_node, cass_cfqq->p_root);
		cass_cfqq->p_root = NULL;
	}

	if (cass_cfq_class_idle(cass_cfqq))
		return;
	if (!cass_cfqq->next_rq)
		return;

	cass_cfqq->p_root = &cass_cfqd->prio_trees[cass_cfqq->org_ioprio];
	__cass_cfqq = cass_cfq_prio_tree_lookup(cass_cfqd, cass_cfqq->p_root,
				      blk_rq_pos(cass_cfqq->next_rq), &parent, &p);
	if (!__cass_cfqq) {
		rb_link_node(&cass_cfqq->p_node, parent, p);
		rb_insert_color(&cass_cfqq->p_node, cass_cfqq->p_root);
	} else
		cass_cfqq->p_root = NULL;
}

/*
 * Update cass_cfqq's position in the service tree.
 */
static void cass_cfq_resort_rr_list(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	/*
	 * Resorting requires the cass_cfqq to be on the RR list already.
	 */
	if (cass_cfqq_on_rr(cass_cfqq)) {
		cass_cfq_service_tree_add(cass_cfqd, cass_cfqq, 0);
		cass_cfq_prio_tree_add(cass_cfqd, cass_cfqq);
	}
}

/*
 * add to busy list of queues for service, trying to be fair in ordering
 * the pending list according to last request service
 */
static void cass_cfq_add_cass_cfqq_rr(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "add_to_rr");
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
			trace_printk("weight: %d pid: %d add_to_rr\n", cfqq->cfqg->weight, cfqq->pid);
	BUG_ON(cass_cfqq_on_rr(cass_cfqq));
	cass_cfq_mark_cass_cfqq_on_rr(cass_cfqq);
	cass_cfqd->busy_queues++;
	if (cass_cfqq_sync(cass_cfqq))
		cass_cfqd->busy_sync_queues++;

	cass_cfq_resort_rr_list(cass_cfqd, cass_cfqq);
}

/*
 * Called when the cass_cfqq no longer has requests pending, remove it from
 * the service tree.
 */
static void cass_cfq_del_cass_cfqq_rr(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "del_from_rr");
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
			trace_printk("weight: %d pid: %d del_from_rr\n", cfqq->cfqg->weight, cfqq->pid);
	BUG_ON(!cass_cfqq_on_rr(cass_cfqq));
	cass_cfq_clear_cass_cfqq_on_rr(cass_cfqq);

	if (!RB_EMPTY_NODE(&cass_cfqq->rb_node)) {
		cass_cfq_rb_erase(&cass_cfqq->rb_node, cass_cfqq->service_tree);
		cass_cfqq->service_tree = NULL;
	}
	if (cass_cfqq->p_root) {
		rb_erase(&cass_cfqq->p_node, cass_cfqq->p_root);
		cass_cfqq->p_root = NULL;
	}

	cass_cfq_group_notify_queue_del(cass_cfqd, cass_cfqq->cass_cfqg);
	BUG_ON(!cass_cfqd->busy_queues);
	cass_cfqd->busy_queues--;
	if (cass_cfqq_sync(cass_cfqq))
		cass_cfqd->busy_sync_queues--;
}

/*
 * rb tree support functions
 */
static void cass_cfq_del_rq_rb(struct request *rq)
{
	struct cass_cfq_queue *cass_cfqq = RQ_CASS_CFQQ(rq);
	const int sync = rq_is_sync(rq);

	BUG_ON(!cass_cfqq->queued[sync]);
	cass_cfqq->queued[sync]--;

	elv_rb_del(&cass_cfqq->sort_list, rq);

	if (cass_cfqq_on_rr(cass_cfqq) && RB_EMPTY_ROOT(&cass_cfqq->sort_list)) {
		/*
		 * Queue will be deleted from service tree when we actually
		 * expire it later. Right now just remove it from prio tree
		 * as it is empty.
		 */
		if (cass_cfqq->p_root) {
			rb_erase(&cass_cfqq->p_node, cass_cfqq->p_root);
			cass_cfqq->p_root = NULL;
		}
	}
}

static void cass_cfq_add_rq_rb(struct request *rq)
{
	struct cass_cfq_queue *cass_cfqq = RQ_CASS_CFQQ(rq);
	struct cass_cfq_data *cass_cfqd = cass_cfqq->cass_cfqd;
	struct request *prev;

	cass_cfqq->queued[rq_is_sync(rq)]++;

	elv_rb_add(&cass_cfqq->sort_list, rq);

	if (!cass_cfqq_on_rr(cass_cfqq))
		cass_cfq_add_cass_cfqq_rr(cass_cfqd, cass_cfqq);

	/*
	 * check if this request is a better next-serve candidate
	 */
	prev = cass_cfqq->next_rq;
	cass_cfqq->next_rq = cass_cfq_choose_req(cass_cfqd, cass_cfqq->next_rq, rq, cass_cfqd->last_position);

	/*
	 * adjust priority tree position, if ->next_rq changes
	 */
	if (prev != cass_cfqq->next_rq)
		cass_cfq_prio_tree_add(cass_cfqd, cass_cfqq);

	BUG_ON(!cass_cfqq->next_rq);
}

static void cass_cfq_reposition_rq_rb(struct cass_cfq_queue *cass_cfqq, struct request *rq)
{
	elv_rb_del(&cass_cfqq->sort_list, rq);
	cass_cfqq->queued[rq_is_sync(rq)]--;
	cass_cfqg_stats_update_io_remove(RQ_CASS_CFQG(rq), rq->cmd_flags);
	cass_cfq_add_rq_rb(rq);
	cass_cfqg_stats_update_io_add(RQ_CASS_CFQG(rq), cass_cfqq->cass_cfqd->serving_group,
				 rq->cmd_flags);
}

static struct request *
cass_cfq_find_rq_fmerge(struct cass_cfq_data *cass_cfqd, struct bio *bio)
{
	struct task_struct *tsk = current;
	struct cass_cfq_io_cq *cic;
	struct cass_cfq_queue *cass_cfqq;

	cic = cass_cfq_cic_lookup(cass_cfqd, tsk->io_context);
	if (!cic)
		return NULL;

	cass_cfqq = cic_to_cass_cfqq(cic, op_is_sync(bio->bi_opf));
	if (cass_cfqq)
		return elv_rb_find(&cass_cfqq->sort_list, bio_end_sector(bio));

	return NULL;
}

static void cass_cfq_activate_request(struct request_queue *q, struct request *rq)
{
	struct cass_cfq_data *cass_cfqd = q->elevator->elevator_data;

	cass_cfqd->rq_in_driver++;
	cass_cfq_log_cass_cfqq(cass_cfqd, RQ_CASS_CFQQ(rq), "activate rq, drv=%d",
						cass_cfqd->rq_in_driver);

	if((RQ_CFQQ(rq))->cfqg->weight == 201 || (RQ_CFQQ(rq))->cfqg->weight == 399 || (RQ_CFQQ(rq))->cfqg->weight == 400 || (RQ_CFQQ(rq))->cfqg->weight == 401 || (RQ_CFQQ(rq))->cfqg->weight == 402 || (RQ_CFQQ(rq))->cfqg->weight == 600 || (RQ_CFQQ(rq))->cfqg->weight == 800 || (RQ_CFQQ(rq))->cfqg->weight == 250 || (RQ_CFQQ(rq))->cfqg->weight == 501 || (RQ_CFQQ(rq))->cfqg->weight == 750)
			trace_printk("weight: %d pid: %d activate rq, drv=%d\n", (RQ_CFQQ(rq))->cfqg->weight,
					(RQ_CFQQ(rq))->pid, cfqd->rq_in_driver);
	cass_cfqd->last_position = blk_rq_pos(rq) + blk_rq_sectors(rq);
}

static void cass_cfq_deactivate_request(struct request_queue *q, struct request *rq)
{
	struct cass_cfq_data *cass_cfqd = q->elevator->elevator_data;

	WARN_ON(!cass_cfqd->rq_in_driver);
	cass_cfqd->rq_in_driver--;
	cass_cfq_log_cass_cfqq(cass_cfqd, RQ_CASS_CFQQ(rq), "deactivate rq, drv=%d",
						cass_cfqd->rq_in_driver);

	if((RQ_CFQQ(rq))->cfqg->weight == 201 || (RQ_CFQQ(rq))->cfqg->weight == 399 || (RQ_CFQQ(rq))->cfqg->weight == 400 || (RQ_CFQQ(rq))->cfqg->weight == 401 || (RQ_CFQQ(rq))->cfqg->weight == 402 || (RQ_CFQQ(rq))->cfqg->weight == 600 || (RQ_CFQQ(rq))->cfqg->weight == 800 || (RQ_CFQQ(rq))->cfqg->weight == 250 || (RQ_CFQQ(rq))->cfqg->weight == 501 || (RQ_CFQQ(rq))->cfqg->weight == 750)
			trace_printk("weight: %d pid: %d deactivate rq, drv=%d\n", (RQ_CFQQ(rq))->cfqg->weight,
					(RQ_CFQQ(rq))->pid, cfqd->rq_in_driver);
}

static void cass_cfq_remove_request(struct request *rq)
{
	struct cass_cfq_queue *cass_cfqq = RQ_CASS_CFQQ(rq);

	if (cass_cfqq->next_rq == rq)
		cass_cfqq->next_rq = cass_cfq_find_next_rq(cass_cfqq->cass_cfqd, cass_cfqq, rq);

	list_del_init(&rq->queuelist);
	cass_cfq_del_rq_rb(rq);

	cass_cfqq->cass_cfqd->rq_queued--;
	cass_cfqg_stats_update_io_remove(RQ_CASS_CFQG(rq), rq->cmd_flags);
	if (rq->cmd_flags & REQ_PRIO) {
		WARN_ON(!cass_cfqq->prio_pending);
		cass_cfqq->prio_pending--;
	}
}

static int cass_cfq_merge(struct request_queue *q, struct request **req,
		     struct bio *bio)
{
	struct cass_cfq_data *cass_cfqd = q->elevator->elevator_data;
	struct request *__rq;

	__rq = cass_cfq_find_rq_fmerge(cass_cfqd, bio);
	if (__rq && elv_bio_merge_ok(__rq, bio)) {
		*req = __rq;
		return ELEVATOR_FRONT_MERGE;
	}

	return ELEVATOR_NO_MERGE;
}

static void cass_cfq_merged_request(struct request_queue *q, struct request *req,
			       int type)
{
	if (type == ELEVATOR_FRONT_MERGE) {
		struct cass_cfq_queue *cass_cfqq = RQ_CASS_CFQQ(req);

		cass_cfq_reposition_rq_rb(cass_cfqq, req);
	}
}

static void cass_cfq_bio_merged(struct request_queue *q, struct request *req,
				struct bio *bio)
{
	cass_cfqg_stats_update_io_merged(RQ_CASS_CFQG(req), bio->bi_opf);
}

static void
cass_cfq_merged_requests(struct request_queue *q, struct request *rq,
		    struct request *next)
{
	struct cass_cfq_queue *cass_cfqq = RQ_CASS_CFQQ(rq);
	struct cass_cfq_data *cass_cfqd = q->elevator->elevator_data;

	/*
	 * reposition in fifo if next is older than rq
	 */
	if (!list_empty(&rq->queuelist) && !list_empty(&next->queuelist) &&
	    next->fifo_time < rq->fifo_time &&
	    cass_cfqq == RQ_CASS_CFQQ(next)) {
		list_move(&rq->queuelist, &next->queuelist);
		rq->fifo_time = next->fifo_time;
	}

	if (cass_cfqq->next_rq == next)
		cass_cfqq->next_rq = rq;
	cass_cfq_remove_request(next);
	cass_cfqg_stats_update_io_merged(RQ_CASS_CFQG(rq), next->cmd_flags);

	cass_cfqq = RQ_CASS_CFQQ(next);
	/*
	 * all requests of this queue are merged to other queues, delete it
	 * from the service tree. If it's the active_queue,
	 * cass_cfq_dispatch_requests() will choose to expire it or do idle
	 */
	if (cass_cfqq_on_rr(cass_cfqq) && RB_EMPTY_ROOT(&cass_cfqq->sort_list) &&
	    cass_cfqq != cass_cfqd->active_queue)
		cass_cfq_del_cass_cfqq_rr(cass_cfqd, cass_cfqq);
}

static int cass_cfq_allow_bio_merge(struct request_queue *q, struct request *rq,
			       struct bio *bio)
{
	struct cass_cfq_data *cass_cfqd = q->elevator->elevator_data;
	bool is_sync = op_is_sync(bio->bi_opf);
	struct cass_cfq_io_cq *cic;
	struct cass_cfq_queue *cass_cfqq;

	/*
	 * Disallow merge of a sync bio into an async request.
	 */
	if (is_sync && !rq_is_sync(rq))
		return false;

	/*
	 * Lookup the cass_cfqq that this bio will be queued with and allow
	 * merge only if rq is queued there.
	 */
	cic = cass_cfq_cic_lookup(cass_cfqd, current->io_context);
	if (!cic)
		return false;

	cass_cfqq = cic_to_cass_cfqq(cic, is_sync);
	return cass_cfqq == RQ_CASS_CFQQ(rq);
}

static int cass_cfq_allow_rq_merge(struct request_queue *q, struct request *rq,
			      struct request *next)
{
	return RQ_CASS_CFQQ(rq) == RQ_CASS_CFQQ(next);
}

static inline void cass_cfq_del_timer(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	hrtimer_try_to_cancel(&cass_cfqd->idle_slice_timer);
	cass_cfqg_stats_update_idle_time(cass_cfqq->cass_cfqg);
}

static void __cass_cfq_set_active_queue(struct cass_cfq_data *cass_cfqd,
				   struct cass_cfq_queue *cass_cfqq)
{
	if (cass_cfqq) {
		cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "set_active wl_class:%d wl_type:%d",
				cass_cfqd->serving_wl_class, cass_cfqd->serving_wl_type);
		if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
			trace_printk("weight: %d pid: %d set_active wl_class:%d wl_type:%d\n", cfqq->cfqg->weight, cfqq->pid,
						cfqd->serving_wl_class, cfqd->serving_wl_type);
		cass_cfqg_stats_update_avg_queue_size(cass_cfqq->cass_cfqg);
		cass_cfqq->slice_start = 0;
		cass_cfqq->dispatch_start = ktime_get_ns();
		cass_cfqq->allocated_slice = 0;
		cass_cfqq->slice_end = 0;
		cass_cfqq->slice_dispatch = 0;
		cass_cfqq->nr_sectors = 0;

		cass_cfq_clear_cass_cfqq_wait_request(cass_cfqq);
		cass_cfq_clear_cass_cfqq_must_dispatch(cass_cfqq);
		cass_cfq_clear_cass_cfqq_must_alloc_slice(cass_cfqq);
		cass_cfq_clear_cass_cfqq_fifo_expire(cass_cfqq);
		cass_cfq_mark_cass_cfqq_slice_new(cass_cfqq);

		cass_cfq_del_timer(cass_cfqd, cass_cfqq);
	}

	cass_cfqd->active_queue = cass_cfqq;
}

/*
 * current cass_cfqq expired its slice (or was too idle), select new one
 */
static void
__cass_cfq_slice_expired(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq,
		    bool timed_out)
{
	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "slice expired t=%d", timed_out);
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d slice_expired t=%d\n", cfqq->cfqg->weight, cfqq->pid,
				timed_out);

	if (cass_cfqq_wait_request(cass_cfqq))
		cass_cfq_del_timer(cass_cfqd, cass_cfqq);

	cass_cfq_clear_cass_cfqq_wait_request(cass_cfqq);
	cass_cfq_clear_cass_cfqq_wait_busy(cass_cfqq);

	/*
	 * If this cass_cfqq is shared between multiple processes, check to
	 * make sure that those processes are still issuing I/Os within
	 * the mean seek distance.  If not, it may be time to break the
	 * queues apart again.
	 */
	if (cass_cfqq_coop(cass_cfqq) && CASS_CFQQ_SEEKY(cass_cfqq))
		cass_cfq_mark_cass_cfqq_split_coop(cass_cfqq);

	/*
	 * store what was left of this slice, if the queue idled/timed out
	 */
	if (timed_out) {
		if (cass_cfqq_slice_new(cass_cfqq))
			cass_cfqq->slice_resid = cass_cfq_scaled_cass_cfqq_slice(cass_cfqd, cass_cfqq);
		else
			cass_cfqq->slice_resid = cass_cfqq->slice_end - ktime_get_ns();
		cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "resid=%lld", cass_cfqq->slice_resid);
		if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
			trace_printk("weight: %d pid: %d resid=%lld\n", cfqq->cfqg->weight, cfqq->pid,
					cfqq->slice_resid);
	}

	cass_cfq_group_served(cass_cfqd, cass_cfqq->cass_cfqg, cass_cfqq);

	if (cass_cfqq_on_rr(cass_cfqq) && RB_EMPTY_ROOT(&cass_cfqq->sort_list))
		cass_cfq_del_cass_cfqq_rr(cass_cfqd, cass_cfqq);

	cass_cfq_resort_rr_list(cass_cfqd, cass_cfqq);

	if (cass_cfqq == cass_cfqd->active_queue)
		cass_cfqd->active_queue = NULL;

	if (cass_cfqd->active_cic) {
		put_io_context(cass_cfqd->active_cic->icq.ioc);
		cass_cfqd->active_cic = NULL;
	}
}

static inline void cass_cfq_slice_expired(struct cass_cfq_data *cass_cfqd, bool timed_out)
{
	struct cass_cfq_queue *cass_cfqq = cass_cfqd->active_queue;

	if (cass_cfqq)
		__cass_cfq_slice_expired(cass_cfqd, cass_cfqq, timed_out);
}

/*
 * Get next queue for service. Unless we have a queue preemption,
 * we'll simply select the first cass_cfqq in the service tree.
 */
static struct cass_cfq_queue *cass_cfq_get_next_queue(struct cass_cfq_data *cass_cfqd)
{
	struct cass_cfq_rb_root *st = st_for(cass_cfqd->serving_group,
			cass_cfqd->serving_wl_class, cass_cfqd->serving_wl_type);

	if (!cass_cfqd->rq_queued)
		return NULL;

	/* There is nothing to dispatch */
	if (!st)
		return NULL;
	if (RB_EMPTY_ROOT(&st->rb))
		return NULL;
	return cass_cfq_rb_first(st);
}

static struct cass_cfq_queue *cass_cfq_get_next_queue_forced(struct cass_cfq_data *cass_cfqd)
{
	struct cass_cfq_group *cass_cfqg;
	struct cass_cfq_queue *cass_cfqq;
	int i, j;
	struct cass_cfq_rb_root *st;

	if (!cass_cfqd->rq_queued)
		return NULL;

	cass_cfqg = cass_cfq_get_next_cass_cfqg(cass_cfqd);
	if (!cass_cfqg)
		return NULL;

	for_each_cass_cfqg_st(cass_cfqg, i, j, st)
		if ((cass_cfqq = cass_cfq_rb_first(st)) != NULL)
			return cass_cfqq;
	return NULL;
}

/*
 * Get and set a new active queue for service.
 */
static struct cass_cfq_queue *cass_cfq_set_active_queue(struct cass_cfq_data *cass_cfqd,
					      struct cass_cfq_queue *cass_cfqq)
{
	if (!cass_cfqq)
		cass_cfqq = cass_cfq_get_next_queue(cass_cfqd);

	__cass_cfq_set_active_queue(cass_cfqd, cass_cfqq);
	return cass_cfqq;
}

static inline sector_t cass_cfq_dist_from_last(struct cass_cfq_data *cass_cfqd,
					  struct request *rq)
{
	if (blk_rq_pos(rq) >= cass_cfqd->last_position)
		return blk_rq_pos(rq) - cass_cfqd->last_position;
	else
		return cass_cfqd->last_position - blk_rq_pos(rq);
}

static inline int cass_cfq_rq_close(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq,
			       struct request *rq)
{
	return cass_cfq_dist_from_last(cass_cfqd, rq) <= CASS_CFQQ_CLOSE_THR;
}

static struct cass_cfq_queue *cass_cfqq_close(struct cass_cfq_data *cass_cfqd,
				    struct cass_cfq_queue *cur_cass_cfqq)
{
	struct rb_root *root = &cass_cfqd->prio_trees[cur_cass_cfqq->org_ioprio];
	struct rb_node *parent, *node;
	struct cass_cfq_queue *__cass_cfqq;
	sector_t sector = cass_cfqd->last_position;

	if (RB_EMPTY_ROOT(root))
		return NULL;

	/*
	 * First, if we find a request starting at the end of the last
	 * request, choose it.
	 */
	__cass_cfqq = cass_cfq_prio_tree_lookup(cass_cfqd, root, sector, &parent, NULL);
	if (__cass_cfqq)
		return __cass_cfqq;

	/*
	 * If the exact sector wasn't found, the parent of the NULL leaf
	 * will contain the closest sector.
	 */
	__cass_cfqq = rb_entry(parent, struct cass_cfq_queue, p_node);
	if (cass_cfq_rq_close(cass_cfqd, cur_cass_cfqq, __cass_cfqq->next_rq))
		return __cass_cfqq;

	if (blk_rq_pos(__cass_cfqq->next_rq) < sector)
		node = rb_next(&__cass_cfqq->p_node);
	else
		node = rb_prev(&__cass_cfqq->p_node);
	if (!node)
		return NULL;

	__cass_cfqq = rb_entry(node, struct cass_cfq_queue, p_node);
	if (cass_cfq_rq_close(cass_cfqd, cur_cass_cfqq, __cass_cfqq->next_rq))
		return __cass_cfqq;

	return NULL;
}

/*
 * cass_cfqd - obvious
 * cur_cass_cfqq - passed in so that we don't decide that the current queue is
 * 	      closely cooperating with itself.
 *
 * So, basically we're assuming that that cur_cass_cfqq has dispatched at least
 * one request, and that cass_cfqd->last_position reflects a position on the disk
 * associated with the I/O issued by cur_cass_cfqq.  I'm not sure this is a valid
 * assumption.
 */
static struct cass_cfq_queue *cass_cfq_close_cooperator(struct cass_cfq_data *cass_cfqd,
					      struct cass_cfq_queue *cur_cass_cfqq)
{
	struct cass_cfq_queue *cass_cfqq;

	if (cass_cfq_class_idle(cur_cass_cfqq))
		return NULL;
	if (!cass_cfqq_sync(cur_cass_cfqq))
		return NULL;
	if (CASS_CFQQ_SEEKY(cur_cass_cfqq))
		return NULL;

	/*
	 * Don't search priority tree if it's the only queue in the group.
	 */
	if (cur_cass_cfqq->cass_cfqg->nr_cass_cfqq == 1)
		return NULL;

	/*
	 * We should notice if some of the queues are cooperating, eg
	 * working closely on the same area of the disk. In that case,
	 * we can group them together and don't waste time idling.
	 */
	cass_cfqq = cass_cfqq_close(cass_cfqd, cur_cass_cfqq);
	if (!cass_cfqq)
		return NULL;

	/* If new queue belongs to different cass_cfq_group, don't choose it */
	if (cur_cass_cfqq->cass_cfqg != cass_cfqq->cass_cfqg)
		return NULL;

	/*
	 * It only makes sense to merge sync queues.
	 */
	if (!cass_cfqq_sync(cass_cfqq))
		return NULL;
	if (CASS_CFQQ_SEEKY(cass_cfqq))
		return NULL;

	/*
	 * Do not merge queues of different priority classes
	 */
	if (cass_cfq_class_rt(cass_cfqq) != cass_cfq_class_rt(cur_cass_cfqq))
		return NULL;

	return cass_cfqq;
}

/*
 * Determine whether we should enforce idle window for this queue.
 */

static bool cass_cfq_should_idle(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	enum wl_class_t wl_class = cass_cfqq_class(cass_cfqq);
	struct cass_cfq_rb_root *st = cass_cfqq->service_tree;

	BUG_ON(!st);
	BUG_ON(!st->count);

	if (!cass_cfqd->cass_cfq_slice_idle)
		return false;

	/* We never do for idle class queues. */
	if (wl_class == IDLE_WORKLOAD)
		return false;

	/* We do for queues that were marked with idle window flag. */
	if (cass_cfqq_idle_window(cass_cfqq) &&
	   !(blk_queue_nonrot(cass_cfqd->queue) && cass_cfqd->hw_tag))
		return true;

	/*
	 * Otherwise, we do only if they are the last ones
	 * in their service tree.
	 */
	if (st->count == 1 && cass_cfqq_sync(cass_cfqq) &&
	   !cass_cfq_io_thinktime_big(cass_cfqd, &st->ttime, false))
		return true;
	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "Not idling. st->count:%d", st->count);
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d Not idling. st->count:%d\n", cfqq->cfqg->weight, cfqq->pid,
				st->count);
	return false;
}

static void cass_cfq_arm_slice_timer(struct cass_cfq_data *cass_cfqd)
{
	struct cass_cfq_queue *cass_cfqq = cass_cfqd->active_queue;
	struct cass_cfq_rb_root *st = cass_cfqq->service_tree;
	struct cass_cfq_io_cq *cic;
	u64 sl, group_idle = 0;
	u64 now = ktime_get_ns();

	/*
	 * SSD device without seek penalty, disable idling. But only do so
	 * for devices that support queuing, otherwise we still have a problem
	 * with sync vs async workloads.
	 */
	if (blk_queue_nonrot(cass_cfqd->queue) && cass_cfqd->hw_tag)
		return;

	WARN_ON(!RB_EMPTY_ROOT(&cass_cfqq->sort_list));
	WARN_ON(cass_cfqq_slice_new(cass_cfqq));

	/*
	 * idle is disabled, either manually or by past process history
	 */
	if (!cass_cfq_should_idle(cass_cfqd, cass_cfqq)) {
		/* no queue idling. Check for group idling */
		if (cass_cfqd->cass_cfq_group_idle)
			group_idle = cass_cfqd->cass_cfq_group_idle;
		else
			return;
	}

	/*
	 * still active requests from this queue, don't idle
	 */
	if (cass_cfqq->dispatched)
		return;

	/*
	 * task has exited, don't wait
	 */
	cic = cass_cfqd->active_cic;
	if (!cic || !atomic_read(&cic->icq.ioc->active_ref))
		return;

	/*
	 * If our average think time is larger than the remaining time
	 * slice, then don't idle. This avoids overrunning the allotted
	 * time slice.
	 */
	if (sample_valid(cic->ttime.ttime_samples) &&
	    (cass_cfqq->slice_end - now < cic->ttime.ttime_mean)) {
		cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "Not idling. think_time:%llu",
			     cic->ttime.ttime_mean);
		if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
			trace_printk("weight: %d pid: %d Not idling. think_time:%llu\n", cfqq->cfqg->weight, cfqq->pid,
					cic->ttime.ttime_mean);
		return;
	}

	/*
	 * There are other queues in the group or this is the only group and
	 * it has too big thinktime, don't do group idle.
	 */
	if (group_idle &&
	    (cass_cfqq->cass_cfqg->nr_cass_cfqq > 1 ||
	     cass_cfq_io_thinktime_big(cass_cfqd, &st->ttime, true)))
		return;

	cass_cfq_mark_cass_cfqq_wait_request(cass_cfqq);

	if (group_idle)
		sl = cass_cfqd->cass_cfq_group_idle;
	else
		sl = cass_cfqd->cass_cfq_slice_idle;

	hrtimer_start(&cass_cfqd->idle_slice_timer, ns_to_ktime(sl),
		      HRTIMER_MODE_REL);
	cass_cfqg_stats_set_start_idle_time(cass_cfqq->cass_cfqg);
	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "arm_idle: %llu group_idle: %d", sl,
			group_idle ? 1 : 0);
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d arm_idle: %llu group_idle: %d\n", cfqq->cfqg->weight, cfqq->pid,
				sl, group_idle ? 1: 0);
}

/*
 * Move request from internal lists to the request queue dispatch list.
 */
static void cass_cfq_dispatch_insert(struct request_queue *q, struct request *rq)
{
	struct cass_cfq_data *cass_cfqd = q->elevator->elevator_data;
	struct cass_cfq_queue *cass_cfqq = RQ_CASS_CFQQ(rq);

	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "dispatch_insert");
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || fqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d dispatch_insert\n", cfqq->cfqg->weight, cfqq->pid);

	cass_cfqq->next_rq = cass_cfq_find_next_rq(cass_cfqd, cass_cfqq, rq);
	cass_cfq_remove_request(rq);
	cass_cfqq->dispatched++;
	(RQ_CASS_CFQG(rq))->dispatched++;
	elv_dispatch_sort(q, rq);

	cass_cfqd->rq_in_flight[cass_cfqq_sync(cass_cfqq)]++;
	cass_cfqq->nr_sectors += blk_rq_sectors(rq);

}

/*
 * return expired entry, or NULL to just start from scratch in rbtree
 */
static struct request *cass_cfq_check_fifo(struct cass_cfq_queue *cass_cfqq)
{
	struct request *rq = NULL;

	if (cass_cfqq_fifo_expire(cass_cfqq))
		return NULL;

	cass_cfq_mark_cass_cfqq_fifo_expire(cass_cfqq);

	if (list_empty(&cass_cfqq->fifo))
		return NULL;

	rq = rq_entry_fifo(cass_cfqq->fifo.next);
	if (ktime_get_ns() < rq->fifo_time)
		rq = NULL;

	return rq;
}

static inline int
cass_cfq_prio_to_maxrq(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	const int base_rq = cass_cfqd->cass_cfq_slice_async_rq;

	WARN_ON(cass_cfqq->ioprio >= IOPRIO_BE_NR);

	return 2 * base_rq * (IOPRIO_BE_NR - cass_cfqq->ioprio);
}

/*
 * Must be called with the queue_lock held.
 */
static int cass_cfqq_process_refs(struct cass_cfq_queue *cass_cfqq)
{
	int process_refs, io_refs;

	io_refs = cass_cfqq->allocated[READ] + cass_cfqq->allocated[WRITE];
	process_refs = cass_cfqq->ref - io_refs;
	BUG_ON(process_refs < 0);
	return process_refs;
}

static void cass_cfq_setup_merge(struct cass_cfq_queue *cass_cfqq, struct cass_cfq_queue *new_cass_cfqq)
{
	int process_refs, new_process_refs;
	struct cass_cfq_queue *__cass_cfqq;

	/*
	 * If there are no process references on the new_cass_cfqq, then it is
	 * unsafe to follow the ->new_cass_cfqq chain as other cass_cfqq's in the
	 * chain may have dropped their last reference (not just their
	 * last process reference).
	 */
	if (!cass_cfqq_process_refs(new_cass_cfqq))
		return;

	/* Avoid a circular list and skip interim queue merges */
	while ((__cass_cfqq = new_cass_cfqq->new_cass_cfqq)) {
		if (__cass_cfqq == cass_cfqq)
			return;
		new_cass_cfqq = __cass_cfqq;
	}

	process_refs = cass_cfqq_process_refs(cass_cfqq);
	new_process_refs = cass_cfqq_process_refs(new_cass_cfqq);
	/*
	 * If the process for the cass_cfqq has gone away, there is no
	 * sense in merging the queues.
	 */
	if (process_refs == 0 || new_process_refs == 0)
		return;

	/*
	 * Merge in the direction of the lesser amount of work.
	 */
	if (new_process_refs >= process_refs) {
		cass_cfqq->new_cass_cfqq = new_cass_cfqq;
		new_cass_cfqq->ref += process_refs;
	} else {
		new_cass_cfqq->new_cass_cfqq = cass_cfqq;
		cass_cfqq->ref += new_process_refs;
	}
}

static enum wl_type_t cass_cfq_choose_wl_type(struct cass_cfq_data *cass_cfqd,
			struct cass_cfq_group *cass_cfqg, enum wl_class_t wl_class)
{
	struct cass_cfq_queue *queue;
	int i;
	bool key_valid = false;
	u64 lowest_key = 0;
	enum wl_type_t cur_best = SYNC_NOIDLE_WORKLOAD;

	for (i = 0; i <= SYNC_WORKLOAD; ++i) {
		/* select the one with lowest rb_key */
		queue = cass_cfq_rb_first(st_for(cass_cfqg, wl_class, i));
		if (queue &&
		    (!key_valid || queue->rb_key < lowest_key)) {
			lowest_key = queue->rb_key;
			cur_best = i;
			key_valid = true;
		}
	}

	return cur_best;
}

static void
choose_wl_class_and_type(struct cass_cfq_data *cass_cfqd, struct cass_cfq_group *cass_cfqg)
{
	u64 slice;
	unsigned count;
	struct cass_cfq_rb_root *st;
	u64 group_slice;
	enum wl_class_t original_class = cass_cfqd->serving_wl_class;
	u64 now = ktime_get_ns();

	/* Choose next priority. RT > BE > IDLE */
	if (cass_cfq_group_busy_queues_wl(RT_WORKLOAD, cass_cfqd, cass_cfqg))
		cass_cfqd->serving_wl_class = RT_WORKLOAD;
	else if (cass_cfq_group_busy_queues_wl(BE_WORKLOAD, cass_cfqd, cass_cfqg))
		cass_cfqd->serving_wl_class = BE_WORKLOAD;
	else {
		cass_cfqd->serving_wl_class = IDLE_WORKLOAD;
		cass_cfqd->workload_expires = now + jiffies_to_nsecs(1);
		return;
	}

	if (original_class != cass_cfqd->serving_wl_class)
		goto new_workload;

	/*
	 * For RT and BE, we have to choose also the type
	 * (SYNC, SYNC_NOIDLE, ASYNC), and to compute a workload
	 * expiration time
	 */
	st = st_for(cass_cfqg, cass_cfqd->serving_wl_class, cass_cfqd->serving_wl_type);
	count = st->count;

	/*
	 * check workload expiration, and that we still have other queues ready
	 */
	if (count && !(now > cass_cfqd->workload_expires))
		return;

new_workload:
	/* otherwise select new workload type */
	cass_cfqd->serving_wl_type = cass_cfq_choose_wl_type(cass_cfqd, cass_cfqg,
					cass_cfqd->serving_wl_class);
	st = st_for(cass_cfqg, cass_cfqd->serving_wl_class, cass_cfqd->serving_wl_type);
	count = st->count;

	/*
	 * the workload slice is computed as a fraction of target latency
	 * proportional to the number of queues in that workload, over
	 * all the queues in the same priority class
	 */
	group_slice = cass_cfq_group_slice(cass_cfqd, cass_cfqg);

	slice = div_u64(group_slice * count,
		max_t(unsigned, cass_cfqg->busy_queues_avg[cass_cfqd->serving_wl_class],
		      cass_cfq_group_busy_queues_wl(cass_cfqd->serving_wl_class, cass_cfqd,
					cass_cfqg)));

	if (cass_cfqd->serving_wl_type == ASYNC_WORKLOAD) {
		u64 tmp;

		/*
		 * Async queues are currently system wide. Just taking
		 * proportion of queues with-in same group will lead to higher
		 * async ratio system wide as generally root group is going
		 * to have higher weight. A more accurate thing would be to
		 * calculate system wide asnc/sync ratio.
		 */
		tmp = cass_cfqd->cass_cfq_target_latency *
			cass_cfqg_busy_async_queues(cass_cfqd, cass_cfqg);
		tmp = div_u64(tmp, cass_cfqd->busy_queues);
		slice = min_t(u64, slice, tmp);

		/* async workload slice is scaled down according to
		 * the sync/async slice ratio. */
		slice = div64_u64(slice*cass_cfqd->cass_cfq_slice[0], cass_cfqd->cass_cfq_slice[1]);
	} else
		/* sync workload slice is at least 2 * cass_cfq_slice_idle */
		slice = max(slice, 2 * cass_cfqd->cass_cfq_slice_idle);

	slice = max_t(u64, slice, CASS_CFQ_MIN_TT);
	cass_cfq_log(cass_cfqd, "workload slice:%llu", slice);
	cass_cfqd->workload_expires = now + slice;
}

static struct cass_cfq_group *cass_cfq_get_next_cass_cfqg(struct cass_cfq_data *cass_cfqd)
{
	struct cass_cfq_rb_root *st = &cass_cfqd->grp_service_tree;
	struct cass_cfq_group *cass_cfqg;

	if (RB_EMPTY_ROOT(&st->rb))
		return NULL;
	cass_cfqg = cass_cfq_rb_first_group(st);
	update_min_vdisktime(st);
	return cass_cfqg;
}

static void cass_cfq_choose_cass_cfqg(struct cass_cfq_data *cass_cfqd)
{
	struct cass_cfq_group *cass_cfqg = cass_cfq_get_next_cass_cfqg(cass_cfqd);
	u64 now = ktime_get_ns();

	if(cfqd->serving_group && cfqd->serving_group != cfqg){
		cfqd->serving_group->end_time_ns = now;
		if(cfqd->serving_group->weight == 201 || cfqd->serving_group->weight == 399 || cfqd->serving_group->weight == 400 || cfqd->serving_group->weight == 401 || cfqd->serving_group->weight == 402 || cfqd->serving_group->weight == 600 || cfqd->serving_group->weight == 800 || cfqd->serving_group->weight == 250 || cfqd->serving_group->weight == 501 || cfqd->serving_group->weight == 750)
			trace_printk("\nweight: %d start_time_ns: %lu end_time_ns: %lu time_spent: %lu\n\n", cfqd->serving_group->weight,
				cfqd->serving_group->start_time_ns, cfqd->serving_group->end_time_ns, cfqd->serving_group->end_time_ns-cfqd->serving_group->start_time_ns);
		cfqg->start_time_ns = now;
	}

	cass_cfqd->serving_group = cass_cfqg;

	/* Restore the workload type data */
	if (cass_cfqg->saved_wl_slice) {
		cass_cfqd->workload_expires = now + cass_cfqg->saved_wl_slice;
		cass_cfqd->serving_wl_type = cass_cfqg->saved_wl_type;
		cass_cfqd->serving_wl_class = cass_cfqg->saved_wl_class;
	} else
		cass_cfqd->workload_expires = now - 1;

	choose_wl_class_and_type(cass_cfqd, cass_cfqg);
}

/*
 * Select a queue for service. If we have a current active queue,
 * check whether to continue servicing it, or retrieve and set a new one.
 */
static struct cass_cfq_queue *cass_cfq_select_queue(struct cass_cfq_data *cass_cfqd)
{
	struct cass_cfq_queue *cass_cfqq, *new_cass_cfqq = NULL;
	u64 now = ktime_get_ns();

	cass_cfqq = cass_cfqd->active_queue;
	if (!cass_cfqq)
		goto new_queue;

	if (!cass_cfqd->rq_queued)
		return NULL;

	/*
	 * We were waiting for group to get backlogged. Expire the queue
	 */
	if (cass_cfqq_wait_busy(cass_cfqq) && !RB_EMPTY_ROOT(&cass_cfqq->sort_list))
		goto expire;

	/*
	 * The active queue has run out of time, expire it and select new.
	 */
	if (cass_cfq_slice_used(cass_cfqq) && !cass_cfqq_must_dispatch(cass_cfqq)) {
		/*
		 * If slice had not expired at the completion of last request
		 * we might not have turned on wait_busy flag. Don't expire
		 * the queue yet. Allow the group to get backlogged.
		 *
		 * The very fact that we have used the slice, that means we
		 * have been idling all along on this queue and it should be
		 * ok to wait for this request to complete.
		 */
		if (cass_cfqq->cass_cfqg->nr_cass_cfqq == 1 && RB_EMPTY_ROOT(&cass_cfqq->sort_list)
		    && cass_cfqq->dispatched && cass_cfq_should_idle(cass_cfqd, cass_cfqq)) {
			cass_cfqq = NULL;
			goto keep_queue;
		} else
			goto check_group_idle;
	}

	/*
	 * The active queue has requests and isn't expired, allow it to
	 * dispatch.
	 */
	if (!RB_EMPTY_ROOT(&cass_cfqq->sort_list))
		goto keep_queue;

	/*
	 * If another queue has a request waiting within our mean seek
	 * distance, let it run.  The expire code will check for close
	 * cooperators and put the close queue at the front of the service
	 * tree.  If possible, merge the expiring queue with the new cass_cfqq.
	 */
	new_cass_cfqq = cass_cfq_close_cooperator(cass_cfqd, cass_cfqq);
	if (new_cass_cfqq) {
		if (!cass_cfqq->new_cass_cfqq)
			cass_cfq_setup_merge(cass_cfqq, new_cass_cfqq);
		goto expire;
	}

	/*
	 * No requests pending. If the active queue still has requests in
	 * flight or is idling for a new request, allow either of these
	 * conditions to happen (or time out) before selecting a new queue.
	 */
	if (hrtimer_active(&cass_cfqd->idle_slice_timer)) {
		cass_cfqq = NULL;
		goto keep_queue;
	}

	/*
	 * This is a deep seek queue, but the device is much faster than
	 * the queue can deliver, don't idle
	 **/
	if (CASS_CFQQ_SEEKY(cass_cfqq) && cass_cfqq_idle_window(cass_cfqq) &&
	    (cass_cfqq_slice_new(cass_cfqq) ||
	    (cass_cfqq->slice_end - now > now - cass_cfqq->slice_start))) {
		cass_cfq_clear_cass_cfqq_deep(cass_cfqq);
		cass_cfq_clear_cass_cfqq_idle_window(cass_cfqq);
	}

	if (cass_cfqq->dispatched && cass_cfq_should_idle(cass_cfqd, cass_cfqq)) {
		cass_cfqq = NULL;
		goto keep_queue;
	}

	/*
	 * If group idle is enabled and there are requests dispatched from
	 * this group, wait for requests to complete.
	 */
check_group_idle:
	if (cass_cfqd->cass_cfq_group_idle && cass_cfqq->cass_cfqg->nr_cass_cfqq == 1 &&
	    cass_cfqq->cass_cfqg->dispatched &&
	    !cass_cfq_io_thinktime_big(cass_cfqd, &cass_cfqq->cass_cfqg->ttime, true)) {
		cass_cfqq = NULL;
		goto keep_queue;
	}

expire:
	cass_cfq_slice_expired(cass_cfqd, 0);
new_queue:
	/*
	 * Current queue expired. Check if we have to switch to a new
	 * service tree
	 */
	if (!new_cass_cfqq)
		cass_cfq_choose_cass_cfqg(cass_cfqd);

	cass_cfqq = cass_cfq_set_active_queue(cass_cfqd, new_cass_cfqq);
keep_queue:
	return cass_cfqq;
}

static int __cass_cfq_forced_dispatch_cass_cfqq(struct cass_cfq_queue *cass_cfqq)
{
	int dispatched = 0;

	while (cass_cfqq->next_rq) {
		cass_cfq_dispatch_insert(cass_cfqq->cass_cfqd->queue, cass_cfqq->next_rq);
		dispatched++;
	}

	BUG_ON(!list_empty(&cass_cfqq->fifo));

	/* By default cass_cfqq is not expired if it is empty. Do it explicitly */
	__cass_cfq_slice_expired(cass_cfqq->cass_cfqd, cass_cfqq, 0);
	return dispatched;
}

/*
 * Drain our current requests. Used for barriers and when switching
 * io schedulers on-the-fly.
 */
static int cass_cfq_forced_dispatch(struct cass_cfq_data *cass_cfqd)
{
	struct cass_cfq_queue *cass_cfqq;
	int dispatched = 0;

	/* Expire the timeslice of the current active queue first */
	cass_cfq_slice_expired(cass_cfqd, 0);
	while ((cass_cfqq = cass_cfq_get_next_queue_forced(cass_cfqd)) != NULL) {
		__cass_cfq_set_active_queue(cass_cfqd, cass_cfqq);
		dispatched += __cass_cfq_forced_dispatch_cass_cfqq(cass_cfqq);
	}

	BUG_ON(cass_cfqd->busy_queues);

	cass_cfq_log(cass_cfqd, "forced_dispatch=%d", dispatched);
	return dispatched;
}

static inline bool cass_cfq_slice_used_soon(struct cass_cfq_data *cass_cfqd,
	struct cass_cfq_queue *cass_cfqq)
{
	u64 now = ktime_get_ns();

	/* the queue hasn't finished any request, can't estimate */
	if (cass_cfqq_slice_new(cass_cfqq))
		return true;
	if (now + cass_cfqd->cass_cfq_slice_idle * cass_cfqq->dispatched > cass_cfqq->slice_end)
		return true;

	return false;
}

static bool cass_cfq_may_dispatch(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	unsigned int max_dispatch;

	if (cass_cfqq_must_dispatch(cass_cfqq))
		return true;

	/*
	 * Drain async requests before we start sync IO
	 */
	if (cass_cfq_should_idle(cass_cfqd, cass_cfqq) && cass_cfqd->rq_in_flight[BLK_RW_ASYNC])
		return false;

	/*
	 * If this is an async queue and we have sync IO in flight, let it wait
	 */
	if (cass_cfqd->rq_in_flight[BLK_RW_SYNC] && !cass_cfqq_sync(cass_cfqq))
		return false;

	max_dispatch = max_t(unsigned int, cass_cfqd->cass_cfq_quantum / 2, 1);
	if (cass_cfq_class_idle(cass_cfqq))
		max_dispatch = 1;

	/*
	 * Does this cass_cfqq already have too much IO in flight?
	 */
	if (cass_cfqq->dispatched >= max_dispatch) {
		bool promote_sync = false;
		/*
		 * idle queue must always only have a single IO in flight
		 */
		if (cass_cfq_class_idle(cass_cfqq))
			return false;

		/*
		 * If there is only one sync queue
		 * we can ignore async queue here and give the sync
		 * queue no dispatch limit. The reason is a sync queue can
		 * preempt async queue, limiting the sync queue doesn't make
		 * sense. This is useful for aiostress test.
		 */
		if (cass_cfqq_sync(cass_cfqq) && cass_cfqd->busy_sync_queues == 1)
			promote_sync = true;

		/*
		 * We have other queues, don't allow more IO from this one
		 */
		if (cass_cfqd->busy_queues > 1 && cass_cfq_slice_used_soon(cass_cfqd, cass_cfqq) &&
				!promote_sync)
			return false;

		/*
		 * Sole queue user, no limit
		 */
		if (cass_cfqd->busy_queues == 1 || promote_sync)
			max_dispatch = -1;
		else
			/*
			 * Normally we start throttling cass_cfqq when cass_cfq_quantum/2
			 * requests have been dispatched. But we can drive
			 * deeper queue depths at the beginning of slice
			 * subjected to upper limit of cass_cfq_quantum.
			 * */
			max_dispatch = cass_cfqd->cass_cfq_quantum;
	}

	/*
	 * Async queues must wait a bit before being allowed dispatch.
	 * We also ramp up the dispatch depth gradually for async IO,
	 * based on the last sync IO we serviced
	 */
	if (!cass_cfqq_sync(cass_cfqq) && cass_cfqd->cass_cfq_latency) {
		u64 last_sync = ktime_get_ns() - cass_cfqd->last_delayed_sync;
		unsigned int depth;

		depth = div64_u64(last_sync, cass_cfqd->cass_cfq_slice[1]);
		if (!depth && !cass_cfqq->dispatched)
			depth = 1;
		if (depth < max_dispatch)
			max_dispatch = depth;
	}

	/*
	 * If we're below the current max, allow a dispatch
	 */
	return cass_cfqq->dispatched < max_dispatch;
}

/*
 * Dispatch a request from cass_cfqq, moving them to the request queue
 * dispatch list.
 */
static bool cass_cfq_dispatch_request(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	struct request *rq;

	BUG_ON(RB_EMPTY_ROOT(&cass_cfqq->sort_list));

	rq = cass_cfq_check_fifo(cass_cfqq);
	if (rq)
		cass_cfq_mark_cass_cfqq_must_dispatch(cass_cfqq);

	if (!cass_cfq_may_dispatch(cass_cfqd, cass_cfqq))
		return false;

	/*
	 * follow expired path, else get first next available
	 */
	if (!rq)
		rq = cass_cfqq->next_rq;
	else{
		cass_cfq_log_cass_cfqq(cass_cfqq->cass_cfqd, cass_cfqq, "fifo=%p", rq);
		if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
			trace_printk("weight: %d pid: %d fifo=%p\n", cfqq->cfqg->weight, cfqq->pid,rq);
	}

	/*
	 * insert request into driver dispatch list
	 */
	cass_cfq_dispatch_insert(cass_cfqd->queue, rq);

	if (!cass_cfqd->active_cic) {
		struct cass_cfq_io_cq *cic = RQ_CIC(rq);

		atomic_long_inc(&cic->icq.ioc->refcount);
		cass_cfqd->active_cic = cic;
	}

	return true;
}

/*
 * Find the cass_cfqq that we need to service and move a request from that to the
 * dispatch list
 */
static int cass_cfq_dispatch_requests(struct request_queue *q, int force)
{
	struct cass_cfq_data *cass_cfqd = q->elevator->elevator_data;
	struct cass_cfq_queue *cass_cfqq;

	if (!cass_cfqd->busy_queues)
		return 0;

	if (unlikely(force))
		return cass_cfq_forced_dispatch(cass_cfqd);

	cass_cfqq = cass_cfq_select_queue(cass_cfqd);
	if (!cass_cfqq)
		return 0;

	/*
	 * Dispatch a request from this cass_cfqq, if it is allowed
	 */
	if (!cass_cfq_dispatch_request(cass_cfqd, cass_cfqq))
		return 0;

	cass_cfqq->slice_dispatch++;
	cass_cfq_clear_cass_cfqq_must_dispatch(cass_cfqq);

	/*
	 * expire an async queue immediately if it has used up its slice. idle
	 * queue always expire after 1 dispatch round.
	 */
	if (cass_cfqd->busy_queues > 1 && ((!cass_cfqq_sync(cass_cfqq) &&
	    cass_cfqq->slice_dispatch >= cass_cfq_prio_to_maxrq(cass_cfqd, cass_cfqq)) ||
	    cass_cfq_class_idle(cass_cfqq))) {
		cass_cfqq->slice_end = ktime_get_ns() + 1;
		cass_cfq_slice_expired(cass_cfqd, 0);
	}

	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "dispatched a request");
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d dispatched a request\n", cfqq->cfqg->weight, cfqq->pid);
	return 1;
}

/*
 * task holds one reference to the queue, dropped when task exits. each rq
 * in-flight on this queue also holds a reference, dropped when rq is freed.
 *
 * Each cass_cfq queue took a reference on the parent group. Drop it now.
 * queue lock must be held here.
 */
static void cass_cfq_put_queue(struct cass_cfq_queue *cass_cfqq)
{
	struct cass_cfq_data *cass_cfqd = cass_cfqq->cass_cfqd;
	struct cass_cfq_group *cass_cfqg;

	BUG_ON(cass_cfqq->ref <= 0);

	cass_cfqq->ref--;
	if (cass_cfqq->ref)
		return;

	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "put_queue");
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d put_queue\n", cfqq->cfqg->weight, cfqq->pid);
	BUG_ON(rb_first(&cass_cfqq->sort_list));
	BUG_ON(cass_cfqq->allocated[READ] + cass_cfqq->allocated[WRITE]);
	cass_cfqg = cass_cfqq->cass_cfqg;

	if (unlikely(cass_cfqd->active_queue == cass_cfqq)) {
		__cass_cfq_slice_expired(cass_cfqd, cass_cfqq, 0);
		cass_cfq_schedule_dispatch(cass_cfqd);
	}

	BUG_ON(cass_cfqq_on_rr(cass_cfqq));
	kmem_cache_free(cass_cfq_pool, cass_cfqq);
	cass_cfqg_put(cass_cfqg);
}

static void cass_cfq_put_cooperator(struct cass_cfq_queue *cass_cfqq)
{
	struct cass_cfq_queue *__cass_cfqq, *next;

	/*
	 * If this queue was scheduled to merge with another queue, be
	 * sure to drop the reference taken on that queue (and others in
	 * the merge chain).  See cass_cfq_setup_merge and cass_cfq_merge_cass_cfqqs.
	 */
	__cass_cfqq = cass_cfqq->new_cass_cfqq;
	while (__cass_cfqq) {
		if (__cass_cfqq == cass_cfqq) {
			WARN(1, "cass_cfqq->new_cass_cfqq loop detected\n");
			break;
		}
		next = __cass_cfqq->new_cass_cfqq;
		cass_cfq_put_queue(__cass_cfqq);
		__cass_cfqq = next;
	}
}

static void cass_cfq_exit_cass_cfqq(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	if (unlikely(cass_cfqq == cass_cfqd->active_queue)) {
		__cass_cfq_slice_expired(cass_cfqd, cass_cfqq, 0);
		cass_cfq_schedule_dispatch(cass_cfqd);
	}

	cass_cfq_put_cooperator(cass_cfqq);

	cass_cfq_put_queue(cass_cfqq);
}

static void cass_cfq_init_icq(struct io_cq *icq)
{
	struct cass_cfq_io_cq *cic = icq_to_cic(icq);

	cic->ttime.last_end_request = ktime_get_ns();
}

static void cass_cfq_exit_icq(struct io_cq *icq)
{
	struct cass_cfq_io_cq *cic = icq_to_cic(icq);
	struct cass_cfq_data *cass_cfqd = cic_to_cass_cfqd(cic);

	if (cic_to_cass_cfqq(cic, false)) {
		cass_cfq_exit_cass_cfqq(cass_cfqd, cic_to_cass_cfqq(cic, false));
		cic_set_cass_cfqq(cic, NULL, false);
	}

	if (cic_to_cass_cfqq(cic, true)) {
		cass_cfq_exit_cass_cfqq(cass_cfqd, cic_to_cass_cfqq(cic, true));
		cic_set_cass_cfqq(cic, NULL, true);
	}
}

static void cass_cfq_init_prio_data(struct cass_cfq_queue *cass_cfqq, struct cass_cfq_io_cq *cic)
{
	struct task_struct *tsk = current;
	int ioprio_class;

	if (!cass_cfqq_prio_changed(cass_cfqq))
		return;

	ioprio_class = IOPRIO_PRIO_CLASS(cic->ioprio);
	switch (ioprio_class) {
	default:
		printk(KERN_ERR "cass_cfq: bad prio %x\n", ioprio_class);
	case IOPRIO_CLASS_NONE:
		/*
		 * no prio set, inherit CPU scheduling settings
		 */
		cass_cfqq->ioprio = task_nice_ioprio(tsk);
		cass_cfqq->ioprio_class = task_nice_ioclass(tsk);
		break;
	case IOPRIO_CLASS_RT:
		cass_cfqq->ioprio = IOPRIO_PRIO_DATA(cic->ioprio);
		cass_cfqq->ioprio_class = IOPRIO_CLASS_RT;
		break;
	case IOPRIO_CLASS_BE:
		cass_cfqq->ioprio = IOPRIO_PRIO_DATA(cic->ioprio);
		cass_cfqq->ioprio_class = IOPRIO_CLASS_BE;
		break;
	case IOPRIO_CLASS_IDLE:
		cass_cfqq->ioprio_class = IOPRIO_CLASS_IDLE;
		cass_cfqq->ioprio = 7;
		cass_cfq_clear_cass_cfqq_idle_window(cass_cfqq);
		break;
	}

	/*
	 * keep track of original prio settings in case we have to temporarily
	 * elevate the priority of this queue
	 */
	cass_cfqq->org_ioprio = cass_cfqq->ioprio;
	cass_cfqq->org_ioprio_class = cass_cfqq->ioprio_class;
	cass_cfq_clear_cass_cfqq_prio_changed(cass_cfqq);
}

static void check_ioprio_changed(struct cass_cfq_io_cq *cic, struct bio *bio)
{
	int ioprio = cic->icq.ioc->ioprio;
	struct cass_cfq_data *cass_cfqd = cic_to_cass_cfqd(cic);
	struct cass_cfq_queue *cass_cfqq;

	/*
	 * Check whether ioprio has changed.  The condition may trigger
	 * spuriously on a newly created cic but there's no harm.
	 */
	if (unlikely(!cass_cfqd) || likely(cic->ioprio == ioprio))
		return;

	cass_cfqq = cic_to_cass_cfqq(cic, false);
	if (cass_cfqq) {
		cass_cfq_put_queue(cass_cfqq);
		cass_cfqq = cass_cfq_get_queue(cass_cfqd, BLK_RW_ASYNC, cic, bio);
		cic_set_cass_cfqq(cic, cass_cfqq, false);
	}

	cass_cfqq = cic_to_cass_cfqq(cic, true);
	if (cass_cfqq)
		cass_cfq_mark_cass_cfqq_prio_changed(cass_cfqq);

	cic->ioprio = ioprio;
}

static void cass_cfq_init_cass_cfqq(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq,
			  pid_t pid, bool is_sync)
{
	RB_CLEAR_NODE(&cass_cfqq->rb_node);
	RB_CLEAR_NODE(&cass_cfqq->p_node);
	INIT_LIST_HEAD(&cass_cfqq->fifo);

	cass_cfqq->ref = 0;
	cass_cfqq->cass_cfqd = cass_cfqd;

	cass_cfq_mark_cass_cfqq_prio_changed(cass_cfqq);

	if (is_sync) {
		if (!cass_cfq_class_idle(cass_cfqq))
			cass_cfq_mark_cass_cfqq_idle_window(cass_cfqq);
		cass_cfq_mark_cass_cfqq_sync(cass_cfqq);
	}
	cass_cfqq->pid = pid;
}

#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
static bool check_blkcg_changed(struct cass_cfq_io_cq *cic, struct bio *bio)
{
	struct cass_cfq_data *cass_cfqd = cic_to_cass_cfqd(cic);
	struct cass_cfq_queue *cass_cfqq;
	uint64_t serial_nr;
	bool nonroot_cg;

	rcu_read_lock();
	serial_nr = bio_blkcg(bio)->css.serial_nr;
	nonroot_cg = bio_blkcg(bio) != &blkcg_root;
	rcu_read_unlock();

	/*
	 * Check whether blkcg has changed.  The condition may trigger
	 * spuriously on a newly created cic but there's no harm.
	 */
	if (unlikely(!cass_cfqd) || likely(cic->blkcg_serial_nr == serial_nr))
		return nonroot_cg;

	/*
	 * Drop reference to queues.  New queues will be assigned in new
	 * group upon arrival of fresh requests.
	 */
	cass_cfqq = cic_to_cass_cfqq(cic, false);
	if (cass_cfqq) {
		cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "changed cgroup");
		if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
			trace_printk("weight: %d pid: %d changed cgroup\n", cfqq->cfqg->weight, cfqq->pid);
		cic_set_cass_cfqq(cic, NULL, false);
		cass_cfq_put_queue(cass_cfqq);
	}

	cass_cfqq = cic_to_cass_cfqq(cic, true);
	if (cass_cfqq) {
		cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "changed cgroup");
		if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
			trace_printk("weight: %d pid: %d changed cgroup\n", cfqq->cfqg->weight, cfqq->pid);
		cic_set_cass_cfqq(cic, NULL, true);
		cass_cfq_put_queue(cass_cfqq);
	}

	cic->blkcg_serial_nr = serial_nr;
	return nonroot_cg;
}
#else
static inline bool check_blkcg_changed(struct cass_cfq_io_cq *cic, struct bio *bio)
{
	return false;
}
#endif  /* CONFIG_CASS_CFQ_GROUP_IOSCHED */

static struct cass_cfq_queue **
cass_cfq_async_queue_prio(struct cass_cfq_group *cass_cfqg, int ioprio_class, int ioprio)
{
	switch (ioprio_class) {
	case IOPRIO_CLASS_RT:
		return &cass_cfqg->async_cass_cfqq[0][ioprio];
	case IOPRIO_CLASS_NONE:
		ioprio = IOPRIO_NORM;
		/* fall through */
	case IOPRIO_CLASS_BE:
		return &cass_cfqg->async_cass_cfqq[1][ioprio];
	case IOPRIO_CLASS_IDLE:
		return &cass_cfqg->async_idle_cass_cfqq;
	default:
		BUG();
	}
}

static struct cass_cfq_queue *
cass_cfq_get_queue(struct cass_cfq_data *cass_cfqd, bool is_sync, struct cass_cfq_io_cq *cic,
	      struct bio *bio)
{
	int ioprio_class = IOPRIO_PRIO_CLASS(cic->ioprio);
	int ioprio = IOPRIO_PRIO_DATA(cic->ioprio);
	struct cass_cfq_queue **async_cass_cfqq = NULL;
	struct cass_cfq_queue *cass_cfqq;
	struct cass_cfq_group *cass_cfqg;

	rcu_read_lock();
	cass_cfqg = cass_cfq_lookup_cass_cfqg(cass_cfqd, bio_blkcg(bio));
	if (!cass_cfqg) {
		cass_cfqq = &cass_cfqd->oom_cass_cfqq;
		goto out;
	}

	if (!is_sync) {
		if (!ioprio_valid(cic->ioprio)) {
			struct task_struct *tsk = current;
			ioprio = task_nice_ioprio(tsk);
			ioprio_class = task_nice_ioclass(tsk);
		}
		async_cass_cfqq = cass_cfq_async_queue_prio(cass_cfqg, ioprio_class, ioprio);
		cass_cfqq = *async_cass_cfqq;
		if (cass_cfqq)
			goto out;
	}

	cass_cfqq = kmem_cache_alloc_node(cass_cfq_pool,
				     GFP_NOWAIT | __GFP_ZERO | __GFP_NOWARN,
				     cass_cfqd->queue->node);
	if (!cass_cfqq) {
		cass_cfqq = &cass_cfqd->oom_cass_cfqq;
		goto out;
	}

	cass_cfq_init_cass_cfqq(cass_cfqd, cass_cfqq, current->pid, is_sync);
	cass_cfq_init_prio_data(cass_cfqq, cic);
	cass_cfq_link_cass_cfqq_cass_cfqg(cass_cfqq, cass_cfqg);
	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "alloced");
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d alloced\n", cfqq->cfqg->weight, cfqq->pid);

	if (async_cass_cfqq) {
		/* a new async queue is created, pin and remember */
		cass_cfqq->ref++;
		*async_cass_cfqq = cass_cfqq;
	}
out:
	cass_cfqq->ref++;
	rcu_read_unlock();
	return cass_cfqq;
}

static void
__cass_cfq_update_io_thinktime(struct cass_cfq_ttime *ttime, u64 slice_idle)
{
	u64 elapsed = ktime_get_ns() - ttime->last_end_request;
	elapsed = min(elapsed, 2UL * slice_idle);

	ttime->ttime_samples = (7*ttime->ttime_samples + 256) / 8;
	ttime->ttime_total = div_u64(7*ttime->ttime_total + 256*elapsed,  8);
	ttime->ttime_mean = div64_ul(ttime->ttime_total + 128,
				     ttime->ttime_samples);
}

static void
cass_cfq_update_io_thinktime(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq,
			struct cass_cfq_io_cq *cic)
{
	if (cass_cfqq_sync(cass_cfqq)) {
		__cass_cfq_update_io_thinktime(&cic->ttime, cass_cfqd->cass_cfq_slice_idle);
		__cass_cfq_update_io_thinktime(&cass_cfqq->service_tree->ttime,
			cass_cfqd->cass_cfq_slice_idle);
	}
#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
	__cass_cfq_update_io_thinktime(&cass_cfqq->cass_cfqg->ttime, cass_cfqd->cass_cfq_group_idle);
#endif
}

static void
cass_cfq_update_io_seektime(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq,
		       struct request *rq)
{
	sector_t sdist = 0;
	sector_t n_sec = blk_rq_sectors(rq);
	if (cass_cfqq->last_request_pos) {
		if (cass_cfqq->last_request_pos < blk_rq_pos(rq))
			sdist = blk_rq_pos(rq) - cass_cfqq->last_request_pos;
		else
			sdist = cass_cfqq->last_request_pos - blk_rq_pos(rq);
	}

	cass_cfqq->seek_history <<= 1;
	if (blk_queue_nonrot(cass_cfqd->queue))
		cass_cfqq->seek_history |= (n_sec < CASS_CFQQ_SECT_THR_NONROT);
	else
		cass_cfqq->seek_history |= (sdist > CASS_CFQQ_SEEK_THR);
}

static inline bool req_noidle(struct request *req)
{
	return req_op(req) == REQ_OP_WRITE &&
		(req->cmd_flags & (REQ_SYNC | REQ_IDLE)) == REQ_SYNC;
}

/*
 * Disable idle window if the process thinks too long or seeks so much that
 * it doesn't matter
 */
static void
cass_cfq_update_idle_window(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq,
		       struct cass_cfq_io_cq *cic)
{
	int old_idle, enable_idle;

	/*
	 * Don't idle for async or idle io prio class
	 */
	if (!cass_cfqq_sync(cass_cfqq) || cass_cfq_class_idle(cass_cfqq))
		return;

	enable_idle = old_idle = cass_cfqq_idle_window(cass_cfqq);

	if (cass_cfqq->queued[0] + cass_cfqq->queued[1] >= 4)
		cass_cfq_mark_cass_cfqq_deep(cass_cfqq);

	if (cass_cfqq->next_rq && req_noidle(cass_cfqq->next_rq))
		enable_idle = 0;
	else if (!atomic_read(&cic->icq.ioc->active_ref) ||
		 !cass_cfqd->cass_cfq_slice_idle ||
		 (!cass_cfqq_deep(cass_cfqq) && CASS_CFQQ_SEEKY(cass_cfqq)))
		enable_idle = 0;
	else if (sample_valid(cic->ttime.ttime_samples)) {
		if (cic->ttime.ttime_mean > cass_cfqd->cass_cfq_slice_idle)
			enable_idle = 0;
		else
			enable_idle = 1;
	}

	if (old_idle != enable_idle) {
		cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "idle=%d", enable_idle);
		if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
			trace_printk("weight: %d pid: %d idle=%d\n", cfqq->cfqg->weight, cfqq->pid, enable_idle);
		if (enable_idle)
			cass_cfq_mark_cass_cfqq_idle_window(cass_cfqq);
		else
			cass_cfq_clear_cass_cfqq_idle_window(cass_cfqq);
	}
}

/*
 * Check if new_cass_cfqq should preempt the currently active queue. Return 0 for
 * no or if we aren't sure, a 1 will cause a preempt.
 */
static bool
cass_cfq_should_preempt(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *new_cass_cfqq,
		   struct request *rq)
{
	struct cass_cfq_queue *cass_cfqq;

	cass_cfqq = cass_cfqd->active_queue;
	if (!cass_cfqq)
		return false;

	if (cass_cfq_class_idle(new_cass_cfqq))
		return false;

	if (cass_cfq_class_idle(cass_cfqq))
		return true;

	/*
	 * Don't allow a non-RT request to preempt an ongoing RT cass_cfqq timeslice.
	 */
	if (cass_cfq_class_rt(cass_cfqq) && !cass_cfq_class_rt(new_cass_cfqq))
		return false;

	/*
	 * if the new request is sync, but the currently running queue is
	 * not, let the sync request have priority.
	 */
	if (rq_is_sync(rq) && !cass_cfqq_sync(cass_cfqq) && !cass_cfqq_must_dispatch(cass_cfqq))
		return true;

	/*
	 * Treat ancestors of current cgroup the same way as current cgroup.
	 * For anybody else we disallow preemption to guarantee service
	 * fairness among cgroups.
	 */
	if (!cass_cfqg_is_descendant(cass_cfqq->cass_cfqg, new_cass_cfqq->cass_cfqg))
		return false;

	if (cass_cfq_slice_used(cass_cfqq))
		return true;

	/*
	 * Allow an RT request to pre-empt an ongoing non-RT cass_cfqq timeslice.
	 */
	if (cass_cfq_class_rt(new_cass_cfqq) && !cass_cfq_class_rt(cass_cfqq))
		return true;

	WARN_ON_ONCE(cass_cfqq->ioprio_class != new_cass_cfqq->ioprio_class);
	/* Allow preemption only if we are idling on sync-noidle tree */
	if (cass_cfqd->serving_wl_type == SYNC_NOIDLE_WORKLOAD &&
	    cass_cfqq_type(new_cass_cfqq) == SYNC_NOIDLE_WORKLOAD &&
	    RB_EMPTY_ROOT(&cass_cfqq->sort_list))
		return true;

	/*
	 * So both queues are sync. Let the new request get disk time if
	 * it's a metadata request and the current queue is doing regular IO.
	 */
	if ((rq->cmd_flags & REQ_PRIO) && !cass_cfqq->prio_pending)
		return true;

	/* An idle queue should not be idle now for some reason */
	if (RB_EMPTY_ROOT(&cass_cfqq->sort_list) && !cass_cfq_should_idle(cass_cfqd, cass_cfqq))
		return true;

	if (!cass_cfqd->active_cic || !cass_cfqq_wait_request(cass_cfqq))
		return false;

	/*
	 * if this request is as-good as one we would expect from the
	 * current cass_cfqq, let it preempt
	 */
	if (cass_cfq_rq_close(cass_cfqd, cass_cfqq, rq))
		return true;

	return false;
}

/*
 * cass_cfqq preempts the active queue. if we allowed preempt with no slice left,
 * let it have half of its nominal slice.
 */
static void cass_cfq_preempt_queue(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	enum wl_type_t old_type = cass_cfqq_type(cass_cfqd->active_queue);

	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "preempt");
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d preempt\n", cfqq->cfqg->weight, cfqq->pid);
	cass_cfq_slice_expired(cass_cfqd, 1);

	/*
	 * workload type is changed, don't save slice, otherwise preempt
	 * doesn't happen
	 */
	if (old_type != cass_cfqq_type(cass_cfqq))
		cass_cfqq->cass_cfqg->saved_wl_slice = 0;

	/*
	 * Put the new queue at the front of the of the current list,
	 * so we know that it will be selected next.
	 */
	BUG_ON(!cass_cfqq_on_rr(cass_cfqq));

	cass_cfq_service_tree_add(cass_cfqd, cass_cfqq, 1);

	cass_cfqq->slice_end = 0;
	cass_cfq_mark_cass_cfqq_slice_new(cass_cfqq);
}

/*
 * Called when a new fs request (rq) is added (to cass_cfqq). Check if there's
 * something we should do about it
 */
static void
cass_cfq_rq_enqueued(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq,
		struct request *rq)
{
	struct cass_cfq_io_cq *cic = RQ_CIC(rq);

	cass_cfqd->rq_queued++;
	if (rq->cmd_flags & REQ_PRIO)
		cass_cfqq->prio_pending++;

	cass_cfq_update_io_thinktime(cass_cfqd, cass_cfqq, cic);
	cass_cfq_update_io_seektime(cass_cfqd, cass_cfqq, rq);
	cass_cfq_update_idle_window(cass_cfqd, cass_cfqq, cic);

	cass_cfqq->last_request_pos = blk_rq_pos(rq) + blk_rq_sectors(rq);

	if (cass_cfqq == cass_cfqd->active_queue) {
		/*
		 * Remember that we saw a request from this process, but
		 * don't start queuing just yet. Otherwise we risk seeing lots
		 * of tiny requests, because we disrupt the normal plugging
		 * and merging. If the request is already larger than a single
		 * page, let it rip immediately. For that case we assume that
		 * merging is already done. Ditto for a busy system that
		 * has other work pending, don't risk delaying until the
		 * idle timer unplug to continue working.
		 */
		if (cass_cfqq_wait_request(cass_cfqq)) {
			if (blk_rq_bytes(rq) > PAGE_SIZE ||
			    cass_cfqd->busy_queues > 1) {
				cass_cfq_del_timer(cass_cfqd, cass_cfqq);
				cass_cfq_clear_cass_cfqq_wait_request(cass_cfqq);
				__blk_run_queue(cass_cfqd->queue);
			} else {
				cass_cfqg_stats_update_idle_time(cass_cfqq->cass_cfqg);
				cass_cfq_mark_cass_cfqq_must_dispatch(cass_cfqq);
			}
		}
	} else if (cass_cfq_should_preempt(cass_cfqd, cass_cfqq, rq)) {
		/*
		 * not the active queue - expire current slice if it is
		 * idle and has expired it's mean thinktime or this new queue
		 * has some old slice time left and is of higher priority or
		 * this new queue is RT and the current one is BE
		 */
		cass_cfq_preempt_queue(cass_cfqd, cass_cfqq);
		__blk_run_queue(cass_cfqd->queue);
	}
}

static void cass_cfq_insert_request(struct request_queue *q, struct request *rq)
{
	struct cass_cfq_data *cass_cfqd = q->elevator->elevator_data;
	struct cass_cfq_queue *cass_cfqq = RQ_CASS_CFQQ(rq);

	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "insert_request");
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d insert_request\n", cfqq->cfqg->weight, cfqq->pid);
	cass_cfq_init_prio_data(cass_cfqq, RQ_CIC(rq));

	rq->fifo_time = ktime_get_ns() + cass_cfqd->cass_cfq_fifo_expire[rq_is_sync(rq)];
	list_add_tail(&rq->queuelist, &cass_cfqq->fifo);
	cass_cfq_add_rq_rb(rq);
	cass_cfqg_stats_update_io_add(RQ_CASS_CFQG(rq), cass_cfqd->serving_group,
				 rq->cmd_flags);
	cass_cfq_rq_enqueued(cass_cfqd, cass_cfqq, rq);

}

/*
 * Update hw_tag based on peak queue depth over 50 samples under
 * sufficient load.
 */
static void cass_cfq_update_hw_tag(struct cass_cfq_data *cass_cfqd)
{
	struct cass_cfq_queue *cass_cfqq = cass_cfqd->active_queue;

	if (cass_cfqd->rq_in_driver > cass_cfqd->hw_tag_est_depth)
		cass_cfqd->hw_tag_est_depth = cass_cfqd->rq_in_driver;

	if (cass_cfqd->hw_tag == 1)
		return;

	if (cass_cfqd->rq_queued <= CASS_CFQ_HW_QUEUE_MIN &&
	    cass_cfqd->rq_in_driver <= CASS_CFQ_HW_QUEUE_MIN)
		return;

	/*
	 * If active queue hasn't enough requests and can idle, cass_cfq might not
	 * dispatch sufficient requests to hardware. Don't zero hw_tag in this
	 * case
	 */
	if (cass_cfqq && cass_cfqq_idle_window(cass_cfqq) &&
	    cass_cfqq->dispatched + cass_cfqq->queued[0] + cass_cfqq->queued[1] <
	    CASS_CFQ_HW_QUEUE_MIN && cass_cfqd->rq_in_driver < CASS_CFQ_HW_QUEUE_MIN)
		return;

	if (cass_cfqd->hw_tag_samples++ < 50)
		return;

	if (cass_cfqd->hw_tag_est_depth >= CASS_CFQ_HW_QUEUE_MIN)
		cass_cfqd->hw_tag = 1;
	else
		cass_cfqd->hw_tag = 0;
}

static bool cass_cfq_should_wait_busy(struct cass_cfq_data *cass_cfqd, struct cass_cfq_queue *cass_cfqq)
{
	struct cass_cfq_io_cq *cic = cass_cfqd->active_cic;
	u64 now = ktime_get_ns();

	/* If the queue already has requests, don't wait */
	if (!RB_EMPTY_ROOT(&cass_cfqq->sort_list))
		return false;

	/* If there are other queues in the group, don't wait */
	if (cass_cfqq->cass_cfqg->nr_cass_cfqq > 1)
		return false;

	/* the only queue in the group, but think time is big */
	if (cass_cfq_io_thinktime_big(cass_cfqd, &cass_cfqq->cass_cfqg->ttime, true))
		return false;

	if (cass_cfq_slice_used(cass_cfqq))
		return true;

	/* if slice left is less than think time, wait busy */
	if (cic && sample_valid(cic->ttime.ttime_samples)
	    && (cass_cfqq->slice_end - now < cic->ttime.ttime_mean))
		return true;

	/*
	 * If think times is less than a jiffy than ttime_mean=0 and above
	 * will not be true. It might happen that slice has not expired yet
	 * but will expire soon (4-5 ns) during select_queue(). To cover the
	 * case where think time is less than a jiffy, mark the queue wait
	 * busy if only 1 jiffy is left in the slice.
	 */
	if (cass_cfqq->slice_end - now <= jiffies_to_nsecs(1))
		return true;

	return false;
}

static void cass_cfq_completed_request(struct request_queue *q, struct request *rq)
{
	struct cass_cfq_queue *cass_cfqq = RQ_CASS_CFQQ(rq);
	struct cass_cfq_data *cass_cfqd = cass_cfqq->cass_cfqd;
	const int sync = rq_is_sync(rq);
	u64 now = ktime_get_ns();

	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "complete rqnoidle %d", req_noidle(rq));
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d complete rqnoidle %d\n", cfqq->cfqg->weight, cfqq->pid,req_noidle(rq));

	cass_cfq_update_hw_tag(cass_cfqd);

	WARN_ON(!cass_cfqd->rq_in_driver);
	WARN_ON(!cass_cfqq->dispatched);
	cass_cfqd->rq_in_driver--;
	cass_cfqq->dispatched--;
	(RQ_CASS_CFQG(rq))->dispatched--;
	cass_cfqg_stats_update_completion(cass_cfqq->cass_cfqg, rq_start_time_ns(rq),
				     rq_io_start_time_ns(rq), rq->cmd_flags);

	cass_cfqd->rq_in_flight[cass_cfqq_sync(cass_cfqq)]--;

	if (sync) {
		struct cass_cfq_rb_root *st;

		RQ_CIC(rq)->ttime.last_end_request = now;

		if (cass_cfqq_on_rr(cass_cfqq))
			st = cass_cfqq->service_tree;
		else
			st = st_for(cass_cfqq->cass_cfqg, cass_cfqq_class(cass_cfqq),
					cass_cfqq_type(cass_cfqq));

		st->ttime.last_end_request = now;
		/*
		 * We have to do this check in jiffies since start_time is in
		 * jiffies and it is not trivial to convert to ns. If
		 * cass_cfq_fifo_expire[1] ever comes close to 1 jiffie, this test
		 * will become problematic but so far we are fine (the default
		 * is 128 ms).
		 */
		if (!time_after(rq->start_time +
				  nsecs_to_jiffies(cass_cfqd->cass_cfq_fifo_expire[1]),
				jiffies))
			cass_cfqd->last_delayed_sync = now;
	}

#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
	cass_cfqq->cass_cfqg->ttime.last_end_request = now;
#endif

	/*
	 * If this is the active queue, check if it needs to be expired,
	 * or if we want to idle in case it has no pending requests.
	 */
	if (cass_cfqd->active_queue == cass_cfqq) {
		const bool cass_cfqq_empty = RB_EMPTY_ROOT(&cass_cfqq->sort_list);

		if (cass_cfqq_slice_new(cass_cfqq)) {
			cass_cfq_set_prio_slice(cass_cfqd, cass_cfqq);
			cass_cfq_clear_cass_cfqq_slice_new(cass_cfqq);
		}

		/*
		 * Should we wait for next request to come in before we expire
		 * the queue.
		 */
		if (cass_cfq_should_wait_busy(cass_cfqd, cass_cfqq)) {
			u64 extend_sl = cass_cfqd->cass_cfq_slice_idle;
			if (!cass_cfqd->cass_cfq_slice_idle)
				extend_sl = cass_cfqd->cass_cfq_group_idle;
			cass_cfqq->slice_end = now + extend_sl;
			cass_cfq_mark_cass_cfqq_wait_busy(cass_cfqq);
			cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "will busy wait");
			if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
				trace_printk("weight: %d pid: %d will busy wait\n", cfqq->cfqg->weight, cfqq->pid);
		}

		/*
		 * Idling is not enabled on:
		 * - expired queues
		 * - idle-priority queues
		 * - async queues
		 * - queues with still some requests queued
		 * - when there is a close cooperator
		 */
		if (cass_cfq_slice_used(cass_cfqq) || cass_cfq_class_idle(cass_cfqq))
			cass_cfq_slice_expired(cass_cfqd, 1);
		else if (sync && cass_cfqq_empty &&
			 !cass_cfq_close_cooperator(cass_cfqd, cass_cfqq)) {
			cass_cfq_arm_slice_timer(cass_cfqd);
		}
	}

	if (!cass_cfqd->rq_in_driver)
		cass_cfq_schedule_dispatch(cass_cfqd);
}

static void cass_cfqq_boost_on_prio(struct cass_cfq_queue *cass_cfqq, unsigned int op)
{
	/*
	 * If REQ_PRIO is set, boost class and prio level, if it's below
	 * BE/NORM. If prio is not set, restore the potentially boosted
	 * class/prio level.
	 */
	if (!(op & REQ_PRIO)) {
		cass_cfqq->ioprio_class = cass_cfqq->org_ioprio_class;
		cass_cfqq->ioprio = cass_cfqq->org_ioprio;
	} else {
		if (cass_cfq_class_idle(cass_cfqq))
			cass_cfqq->ioprio_class = IOPRIO_CLASS_BE;
		if (cass_cfqq->ioprio > IOPRIO_NORM)
			cass_cfqq->ioprio = IOPRIO_NORM;
	}
}

static inline int __cass_cfq_may_queue(struct cass_cfq_queue *cass_cfqq)
{
	if (cass_cfqq_wait_request(cass_cfqq) && !cass_cfqq_must_alloc_slice(cass_cfqq)) {
		cass_cfq_mark_cass_cfqq_must_alloc_slice(cass_cfqq);
		return ELV_MQUEUE_MUST;
	}

	return ELV_MQUEUE_MAY;
}

static int cass_cfq_may_queue(struct request_queue *q, unsigned int op)
{
	struct cass_cfq_data *cass_cfqd = q->elevator->elevator_data;
	struct task_struct *tsk = current;
	struct cass_cfq_io_cq *cic;
	struct cass_cfq_queue *cass_cfqq;

	/*
	 * don't force setup of a queue from here, as a call to may_queue
	 * does not necessarily imply that a request actually will be queued.
	 * so just lookup a possibly existing queue, or return 'may queue'
	 * if that fails
	 */
	cic = cass_cfq_cic_lookup(cass_cfqd, tsk->io_context);
	if (!cic)
		return ELV_MQUEUE_MAY;

	cass_cfqq = cic_to_cass_cfqq(cic, op_is_sync(op));
	if (cass_cfqq) {
		cass_cfq_init_prio_data(cass_cfqq, cic);
		cass_cfqq_boost_on_prio(cass_cfqq, op);

		return __cass_cfq_may_queue(cass_cfqq);
	}

	return ELV_MQUEUE_MAY;
}

/*
 * queue lock held here
 */
static void cass_cfq_put_request(struct request *rq)
{
	struct cass_cfq_queue *cass_cfqq = RQ_CASS_CFQQ(rq);

	if (cass_cfqq) {
		const int rw = rq_data_dir(rq);

		BUG_ON(!cass_cfqq->allocated[rw]);
		cass_cfqq->allocated[rw]--;

		/* Put down rq reference on cass_cfqg */
		cass_cfqg_put(RQ_CASS_CFQG(rq));
		rq->elv.priv[0] = NULL;
		rq->elv.priv[1] = NULL;

		cass_cfq_put_queue(cass_cfqq);
	}
}

static struct cass_cfq_queue *
cass_cfq_merge_cass_cfqqs(struct cass_cfq_data *cass_cfqd, struct cass_cfq_io_cq *cic,
		struct cass_cfq_queue *cass_cfqq)
{
	cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "merging with queue %p", cass_cfqq->new_cass_cfqq);
	if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
		trace_printk("weight: %d pid: %d merging with queue %p\n", cfqq->cfqg->weight, cfqq->pid, cfqq->new_cfqq);
	cic_set_cass_cfqq(cic, cass_cfqq->new_cass_cfqq, 1);
	cass_cfq_mark_cass_cfqq_coop(cass_cfqq->new_cass_cfqq);
	cass_cfq_put_queue(cass_cfqq);
	return cic_to_cass_cfqq(cic, 1);
}

/*
 * Returns NULL if a new cass_cfqq should be allocated, or the old cass_cfqq if this
 * was the last process referring to said cass_cfqq.
 */
static struct cass_cfq_queue *
split_cass_cfqq(struct cass_cfq_io_cq *cic, struct cass_cfq_queue *cass_cfqq)
{
	if (cass_cfqq_process_refs(cass_cfqq) == 1) {
		cass_cfqq->pid = current->pid;
		cass_cfq_clear_cass_cfqq_coop(cass_cfqq);
		cass_cfq_clear_cass_cfqq_split_coop(cass_cfqq);
		return cass_cfqq;
	}

	cic_set_cass_cfqq(cic, NULL, 1);

	cass_cfq_put_cooperator(cass_cfqq);

	cass_cfq_put_queue(cass_cfqq);
	return NULL;
}
/*
 * Allocate cass_cfq data structures associated with this request.
 */
static int
cass_cfq_set_request(struct request_queue *q, struct request *rq, struct bio *bio,
		gfp_t gfp_mask)
{
	struct cass_cfq_data *cass_cfqd = q->elevator->elevator_data;
	struct cass_cfq_io_cq *cic = icq_to_cic(rq->elv.icq);
	const int rw = rq_data_dir(rq);
	const bool is_sync = rq_is_sync(rq);
	struct cass_cfq_queue *cass_cfqq;
	bool disable_wbt;

	spin_lock_irq(q->queue_lock);

	check_ioprio_changed(cic, bio);
	disable_wbt = check_blkcg_changed(cic, bio);
new_queue:
	cass_cfqq = cic_to_cass_cfqq(cic, is_sync);
	if (!cass_cfqq || cass_cfqq == &cass_cfqd->oom_cass_cfqq) {
		if (cass_cfqq)
			cass_cfq_put_queue(cass_cfqq);
		cass_cfqq = cass_cfq_get_queue(cass_cfqd, is_sync, cic, bio);
		cic_set_cass_cfqq(cic, cass_cfqq, is_sync);
	} else {
		/*
		 * If the queue was seeky for too long, break it apart.
		 */
		if (cass_cfqq_coop(cass_cfqq) && cass_cfqq_split_coop(cass_cfqq)) {
			cass_cfq_log_cass_cfqq(cass_cfqd, cass_cfqq, "breaking apart cass_cfqq");
			if(cfqq->cfqg->weight == 201 || cfqq->cfqg->weight == 399 || cfqq->cfqg->weight == 400 || cfqq->cfqg->weight == 401 || cfqq->cfqg->weight == 402 || cfqq->cfqg->weight == 600 || cfqq->cfqg->weight == 800 || cfqq->cfqg->weight == 250 || cfqq->cfqg->weight == 501 || cfqq->cfqg->weight == 750)
				trace_printk("weight: %d pid: %d breaking apart cfqq\n", cfqq->cfqg->weight, cfqq->pid);
			cass_cfqq = split_cass_cfqq(cic, cass_cfqq);
			if (!cass_cfqq)
				goto new_queue;
		}

		/*
		 * Check to see if this queue is scheduled to merge with
		 * another, closely cooperating queue.  The merging of
		 * queues happens here as it must be done in process context.
		 * The reference on new_cass_cfqq was taken in merge_cass_cfqqs.
		 */
		if (cass_cfqq->new_cass_cfqq)
			cass_cfqq = cass_cfq_merge_cass_cfqqs(cass_cfqd, cic, cass_cfqq);
	}

	cass_cfqq->allocated[rw]++;

	cass_cfqq->ref++;
	cass_cfqg_get(cass_cfqq->cass_cfqg);
	rq->elv.priv[0] = cass_cfqq;
	rq->elv.priv[1] = cass_cfqq->cass_cfqg;
	spin_unlock_irq(q->queue_lock);

	if (disable_wbt)
		wbt_disable_default(q);

	return 0;
}

static void cass_cfq_kick_queue(struct work_struct *work)
{
	struct cass_cfq_data *cass_cfqd =
		container_of(work, struct cass_cfq_data, unplug_work);
	struct request_queue *q = cass_cfqd->queue;

	spin_lock_irq(q->queue_lock);
	__blk_run_queue(cass_cfqd->queue);
	spin_unlock_irq(q->queue_lock);
}

/*
 * Timer running if the active_queue is currently idling inside its time slice
 */
static enum hrtimer_restart cass_cfq_idle_slice_timer(struct hrtimer *timer)
{
	struct cass_cfq_data *cass_cfqd = container_of(timer, struct cass_cfq_data,
					     idle_slice_timer);
	struct cass_cfq_queue *cass_cfqq;
	unsigned long flags;
	int timed_out = 1;

	cass_cfq_log(cass_cfqd, "idle timer fired");

	spin_lock_irqsave(cass_cfqd->queue->queue_lock, flags);

	cass_cfqq = cass_cfqd->active_queue;
	if (cass_cfqq) {
		timed_out = 0;

		/*
		 * We saw a request before the queue expired, let it through
		 */
		if (cass_cfqq_must_dispatch(cass_cfqq))
			goto out_kick;

		/*
		 * expired
		 */
		if (cass_cfq_slice_used(cass_cfqq))
			goto expire;

		/*
		 * only expire and reinvoke request handler, if there are
		 * other queues with pending requests
		 */
		if (!cass_cfqd->busy_queues)
			goto out_cont;

		/*
		 * not expired and it has a request pending, let it dispatch
		 */
		if (!RB_EMPTY_ROOT(&cass_cfqq->sort_list))
			goto out_kick;

		/*
		 * Queue depth flag is reset only when the idle didn't succeed
		 */
		cass_cfq_clear_cass_cfqq_deep(cass_cfqq);
	}
expire:
	cass_cfq_slice_expired(cass_cfqd, timed_out);
out_kick:
	cass_cfq_schedule_dispatch(cass_cfqd);
out_cont:
	spin_unlock_irqrestore(cass_cfqd->queue->queue_lock, flags);
	return HRTIMER_NORESTART;
}

static void cass_cfq_shutdown_timer_wq(struct cass_cfq_data *cass_cfqd)
{
	hrtimer_cancel(&cass_cfqd->idle_slice_timer);
	cancel_work_sync(&cass_cfqd->unplug_work);
}

static void cass_cfq_exit_queue(struct elevator_queue *e)
{
	struct cass_cfq_data *cass_cfqd = e->elevator_data;
	struct request_queue *q = cass_cfqd->queue;

	cass_cfq_shutdown_timer_wq(cass_cfqd);

	spin_lock_irq(q->queue_lock);

	if (cass_cfqd->active_queue)
		__cass_cfq_slice_expired(cass_cfqd, cass_cfqd->active_queue, 0);

	spin_unlock_irq(q->queue_lock);

	cass_cfq_shutdown_timer_wq(cass_cfqd);

#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
	blkcg_deactivate_policy(q, &blkcg_policy_cass_cfq);
#else
	kfree(cass_cfqd->root_group);
#endif
	kfree(cass_cfqd);
}

static int cass_cfq_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct cass_cfq_data *cass_cfqd;
	struct blkcg_gq *blkg __maybe_unused;
	int i, ret;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	cass_cfqd = kzalloc_node(sizeof(*cass_cfqd), GFP_KERNEL, q->node);
	if (!cass_cfqd) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
	eq->elevator_data = cass_cfqd;

	cass_cfqd->queue = q;
	spin_lock_irq(q->queue_lock);
	q->elevator = eq;
	spin_unlock_irq(q->queue_lock);

	/* Init root service tree */
	cass_cfqd->grp_service_tree = CASS_CFQ_RB_ROOT;

	/* Init root group and prefer root group over other groups by default */
#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
	ret = blkcg_activate_policy(q, &blkcg_policy_cass_cfq);
	if (ret)
		goto out_free;

	cass_cfqd->root_group = blkg_to_cass_cfqg(q->root_blkg);
#else
	ret = -ENOMEM;
	cass_cfqd->root_group = kzalloc_node(sizeof(*cass_cfqd->root_group),
					GFP_KERNEL, cass_cfqd->queue->node);
	if (!cass_cfqd->root_group)
		goto out_free;

	cass_cfq_init_cass_cfqg_base(cass_cfqd->root_group);
	cass_cfqd->root_group->weight = 2 * CASS_CFQ_WEIGHT_LEGACY_DFL;
	cass_cfqd->root_group->leaf_weight = 2 * CASS_CFQ_WEIGHT_LEGACY_DFL;
#endif

	/*
	 * Not strictly needed (since RB_ROOT just clears the node and we
	 * zeroed cass_cfqd on alloc), but better be safe in case someone decides
	 * to add magic to the rb code
	 */
	for (i = 0; i < CASS_CFQ_PRIO_LISTS; i++)
		cass_cfqd->prio_trees[i] = RB_ROOT;

	/*
	 * Our fallback cass_cfqq if cass_cfq_get_queue() runs into OOM issues.
	 * Grab a permanent reference to it, so that the normal code flow
	 * will not attempt to free it.  oom_cass_cfqq is linked to root_group
	 * but shouldn't hold a reference as it'll never be unlinked.  Lose
	 * the reference from linking right away.
	 */
	cass_cfq_init_cass_cfqq(cass_cfqd, &cass_cfqd->oom_cass_cfqq, 1, 0);
	cass_cfqd->oom_cass_cfqq.ref++;

	spin_lock_irq(q->queue_lock);
	cass_cfq_link_cass_cfqq_cass_cfqg(&cass_cfqd->oom_cass_cfqq, cass_cfqd->root_group);
	cass_cfqg_put(cass_cfqd->root_group);
	spin_unlock_irq(q->queue_lock);

	hrtimer_init(&cass_cfqd->idle_slice_timer, CLOCK_MONOTONIC,
		     HRTIMER_MODE_REL);
	cass_cfqd->idle_slice_timer.function = cass_cfq_idle_slice_timer;

	INIT_WORK(&cass_cfqd->unplug_work, cass_cfq_kick_queue);

	cass_cfqd->cass_cfq_quantum = cass_cfq_quantum;
	cass_cfqd->cass_cfq_fifo_expire[0] = cass_cfq_fifo_expire[0];
	cass_cfqd->cass_cfq_fifo_expire[1] = cass_cfq_fifo_expire[1];
	cass_cfqd->cass_cfq_back_max = cass_cfq_back_max;
	cass_cfqd->cass_cfq_back_penalty = cass_cfq_back_penalty;
	cass_cfqd->cass_cfq_slice[0] = cass_cfq_slice_async;
	cass_cfqd->cass_cfq_slice[1] = cass_cfq_slice_sync;
	cass_cfqd->cass_cfq_target_latency = cass_cfq_target_latency;
	cass_cfqd->cass_cfq_slice_async_rq = cass_cfq_slice_async_rq;
	cass_cfqd->cass_cfq_slice_idle = cass_cfq_slice_idle;
	cass_cfqd->cass_cfq_group_idle = cass_cfq_group_idle;
	cass_cfqd->cass_cfq_latency = 1;
	cass_cfqd->hw_tag = -1;
	/*
	 * we optimistically start assuming sync ops weren't delayed in last
	 * second, in order to have larger depth for async operations.
	 */
	cass_cfqd->last_delayed_sync = ktime_get_ns() - NSEC_PER_SEC;
	return 0;

out_free:
	kfree(cass_cfqd);
	kobject_put(&eq->kobj);
	return ret;
}

static void cass_cfq_registered_queue(struct request_queue *q)
{
	struct elevator_queue *e = q->elevator;
	struct cass_cfq_data *cass_cfqd = e->elevator_data;

	/*
	 * Default to IOPS mode with no idling for SSDs
	 */
	if (blk_queue_nonrot(q))
		cass_cfqd->cass_cfq_slice_idle = 0;
}

/*
 * sysfs parts below -->
 */
static ssize_t
cass_cfq_var_show(unsigned int var, char *page)
{
	return sprintf(page, "%u\n", var);
}

static ssize_t
cass_cfq_var_store(unsigned int *var, const char *page, size_t count)
{
	char *p = (char *) page;

	*var = simple_strtoul(p, &p, 10);
	return count;
}

#define SHOW_FUNCTION(__FUNC, __VAR, __CONV)				\
static ssize_t __FUNC(struct elevator_queue *e, char *page)		\
{									\
	struct cass_cfq_data *cass_cfqd = e->elevator_data;			\
	u64 __data = __VAR;						\
	if (__CONV)							\
		__data = div_u64(__data, NSEC_PER_MSEC);			\
	return cass_cfq_var_show(__data, (page));				\
}
SHOW_FUNCTION(cass_cfq_quantum_show, cass_cfqd->cass_cfq_quantum, 0);
SHOW_FUNCTION(cass_cfq_fifo_expire_sync_show, cass_cfqd->cass_cfq_fifo_expire[1], 1);
SHOW_FUNCTION(cass_cfq_fifo_expire_async_show, cass_cfqd->cass_cfq_fifo_expire[0], 1);
SHOW_FUNCTION(cass_cfq_back_seek_max_show, cass_cfqd->cass_cfq_back_max, 0);
SHOW_FUNCTION(cass_cfq_back_seek_penalty_show, cass_cfqd->cass_cfq_back_penalty, 0);
SHOW_FUNCTION(cass_cfq_slice_idle_show, cass_cfqd->cass_cfq_slice_idle, 1);
SHOW_FUNCTION(cass_cfq_group_idle_show, cass_cfqd->cass_cfq_group_idle, 1);
SHOW_FUNCTION(cass_cfq_slice_sync_show, cass_cfqd->cass_cfq_slice[1], 1);
SHOW_FUNCTION(cass_cfq_slice_async_show, cass_cfqd->cass_cfq_slice[0], 1);
SHOW_FUNCTION(cass_cfq_slice_async_rq_show, cass_cfqd->cass_cfq_slice_async_rq, 0);
SHOW_FUNCTION(cass_cfq_low_latency_show, cass_cfqd->cass_cfq_latency, 0);
SHOW_FUNCTION(cass_cfq_target_latency_show, cass_cfqd->cass_cfq_target_latency, 1);
#undef SHOW_FUNCTION

#define USEC_SHOW_FUNCTION(__FUNC, __VAR)				\
static ssize_t __FUNC(struct elevator_queue *e, char *page)		\
{									\
	struct cass_cfq_data *cass_cfqd = e->elevator_data;			\
	u64 __data = __VAR;						\
	__data = div_u64(__data, NSEC_PER_USEC);			\
	return cass_cfq_var_show(__data, (page));				\
}
USEC_SHOW_FUNCTION(cass_cfq_slice_idle_us_show, cass_cfqd->cass_cfq_slice_idle);
USEC_SHOW_FUNCTION(cass_cfq_group_idle_us_show, cass_cfqd->cass_cfq_group_idle);
USEC_SHOW_FUNCTION(cass_cfq_slice_sync_us_show, cass_cfqd->cass_cfq_slice[1]);
USEC_SHOW_FUNCTION(cass_cfq_slice_async_us_show, cass_cfqd->cass_cfq_slice[0]);
USEC_SHOW_FUNCTION(cass_cfq_target_latency_us_show, cass_cfqd->cass_cfq_target_latency);
#undef USEC_SHOW_FUNCTION

#define STORE_FUNCTION(__FUNC, __PTR, MIN, MAX, __CONV)			\
static ssize_t __FUNC(struct elevator_queue *e, const char *page, size_t count)	\
{									\
	struct cass_cfq_data *cass_cfqd = e->elevator_data;			\
	unsigned int __data;						\
	int ret = cass_cfq_var_store(&__data, (page), count);		\
	if (__data < (MIN))						\
		__data = (MIN);						\
	else if (__data > (MAX))					\
		__data = (MAX);						\
	if (__CONV)							\
		*(__PTR) = (u64)__data * NSEC_PER_MSEC;			\
	else								\
		*(__PTR) = __data;					\
	return ret;							\
}
STORE_FUNCTION(cass_cfq_quantum_store, &cass_cfqd->cass_cfq_quantum, 1, UINT_MAX, 0);
STORE_FUNCTION(cass_cfq_fifo_expire_sync_store, &cass_cfqd->cass_cfq_fifo_expire[1], 1,
		UINT_MAX, 1);
STORE_FUNCTION(cass_cfq_fifo_expire_async_store, &cass_cfqd->cass_cfq_fifo_expire[0], 1,
		UINT_MAX, 1);
STORE_FUNCTION(cass_cfq_back_seek_max_store, &cass_cfqd->cass_cfq_back_max, 0, UINT_MAX, 0);
STORE_FUNCTION(cass_cfq_back_seek_penalty_store, &cass_cfqd->cass_cfq_back_penalty, 1,
		UINT_MAX, 0);
STORE_FUNCTION(cass_cfq_slice_idle_store, &cass_cfqd->cass_cfq_slice_idle, 0, UINT_MAX, 1);
STORE_FUNCTION(cass_cfq_group_idle_store, &cass_cfqd->cass_cfq_group_idle, 0, UINT_MAX, 1);
STORE_FUNCTION(cass_cfq_slice_sync_store, &cass_cfqd->cass_cfq_slice[1], 1, UINT_MAX, 1);
STORE_FUNCTION(cass_cfq_slice_async_store, &cass_cfqd->cass_cfq_slice[0], 1, UINT_MAX, 1);
STORE_FUNCTION(cass_cfq_slice_async_rq_store, &cass_cfqd->cass_cfq_slice_async_rq, 1,
		UINT_MAX, 0);
STORE_FUNCTION(cass_cfq_low_latency_store, &cass_cfqd->cass_cfq_latency, 0, 1, 0);
STORE_FUNCTION(cass_cfq_target_latency_store, &cass_cfqd->cass_cfq_target_latency, 1, UINT_MAX, 1);
#undef STORE_FUNCTION

#define USEC_STORE_FUNCTION(__FUNC, __PTR, MIN, MAX)			\
static ssize_t __FUNC(struct elevator_queue *e, const char *page, size_t count)	\
{									\
	struct cass_cfq_data *cass_cfqd = e->elevator_data;			\
	unsigned int __data;						\
	int ret = cass_cfq_var_store(&__data, (page), count);		\
	if (__data < (MIN))						\
		__data = (MIN);						\
	else if (__data > (MAX))					\
		__data = (MAX);						\
	*(__PTR) = (u64)__data * NSEC_PER_USEC;				\
	return ret;							\
}
USEC_STORE_FUNCTION(cass_cfq_slice_idle_us_store, &cass_cfqd->cass_cfq_slice_idle, 0, UINT_MAX);
USEC_STORE_FUNCTION(cass_cfq_group_idle_us_store, &cass_cfqd->cass_cfq_group_idle, 0, UINT_MAX);
USEC_STORE_FUNCTION(cass_cfq_slice_sync_us_store, &cass_cfqd->cass_cfq_slice[1], 1, UINT_MAX);
USEC_STORE_FUNCTION(cass_cfq_slice_async_us_store, &cass_cfqd->cass_cfq_slice[0], 1, UINT_MAX);
USEC_STORE_FUNCTION(cass_cfq_target_latency_us_store, &cass_cfqd->cass_cfq_target_latency, 1, UINT_MAX);
#undef USEC_STORE_FUNCTION

#define CASS_CFQ_ATTR(name) \
	__ATTR(name, S_IRUGO|S_IWUSR, cass_cfq_##name##_show, cass_cfq_##name##_store)

static struct elv_fs_entry cass_cfq_attrs[] = {
	CASS_CFQ_ATTR(quantum),
	CASS_CFQ_ATTR(fifo_expire_sync),
	CASS_CFQ_ATTR(fifo_expire_async),
	CASS_CFQ_ATTR(back_seek_max),
	CASS_CFQ_ATTR(back_seek_penalty),
	CASS_CFQ_ATTR(slice_sync),
	CASS_CFQ_ATTR(slice_sync_us),
	CASS_CFQ_ATTR(slice_async),
	CASS_CFQ_ATTR(slice_async_us),
	CASS_CFQ_ATTR(slice_async_rq),
	CASS_CFQ_ATTR(slice_idle),
	CASS_CFQ_ATTR(slice_idle_us),
	CASS_CFQ_ATTR(group_idle),
	CASS_CFQ_ATTR(group_idle_us),
	CASS_CFQ_ATTR(low_latency),
	CASS_CFQ_ATTR(target_latency),
	CASS_CFQ_ATTR(target_latency_us),
	__ATTR_NULL
};

static struct elevator_type iosched_cass_cfq = {
	.ops = {
		.elevator_merge_fn = 		cass_cfq_merge,
		.elevator_merged_fn =		cass_cfq_merged_request,
		.elevator_merge_req_fn =	cass_cfq_merged_requests,
		.elevator_allow_bio_merge_fn =	cass_cfq_allow_bio_merge,
		.elevator_allow_rq_merge_fn =	cass_cfq_allow_rq_merge,
		.elevator_bio_merged_fn =	cass_cfq_bio_merged,
		.elevator_dispatch_fn =		cass_cfq_dispatch_requests,
		.elevator_add_req_fn =		cass_cfq_insert_request,
		.elevator_activate_req_fn =	cass_cfq_activate_request,
		.elevator_deactivate_req_fn =	cass_cfq_deactivate_request,
		.elevator_completed_req_fn =	cass_cfq_completed_request,
		.elevator_former_req_fn =	elv_rb_former_request,
		.elevator_latter_req_fn =	elv_rb_latter_request,
		.elevator_init_icq_fn =		cass_cfq_init_icq,
		.elevator_exit_icq_fn =		cass_cfq_exit_icq,
		.elevator_set_req_fn =		cass_cfq_set_request,
		.elevator_put_req_fn =		cass_cfq_put_request,
		.elevator_may_queue_fn =	cass_cfq_may_queue,
		.elevator_init_fn =		cass_cfq_init_queue,
		.elevator_exit_fn =		cass_cfq_exit_queue,
		.elevator_registered_fn =	cass_cfq_registered_queue,
	},
	.icq_size	=	sizeof(struct cass_cfq_io_cq),
	.icq_align	=	__alignof__(struct cass_cfq_io_cq),
	.elevator_attrs =	cass_cfq_attrs,
	.elevator_name	=	"cass_cfq",
	.elevator_owner =	THIS_MODULE,
};

#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
static struct blkcg_policy blkcg_policy_cass_cfq = {
	.dfl_cftypes		= cass_cfq_blkcg_files,
	.legacy_cftypes		= cass_cfq_blkcg_legacy_files,

	.cpd_alloc_fn		= cass_cfq_cpd_alloc,
	.cpd_init_fn		= cass_cfq_cpd_init,
	.cpd_free_fn		= cass_cfq_cpd_free,
	.cpd_bind_fn		= cass_cfq_cpd_bind,

	.pd_alloc_fn		= cass_cfq_pd_alloc,
	.pd_init_fn		= cass_cfq_pd_init,
	.pd_offline_fn		= cass_cfq_pd_offline,
	.pd_free_fn		= cass_cfq_pd_free,
	.pd_reset_stats_fn	= cass_cfq_pd_reset_stats,
};
#endif

static int __init cass_cfq_init(void)
{
	int ret;

#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
	ret = blkcg_policy_register(&blkcg_policy_cass_cfq);
	if (ret)
		return ret;
#else
	cass_cfq_group_idle = 0;
#endif

	ret = -ENOMEM;
	cass_cfq_pool = KMEM_CACHE(cass_cfq_queue, 0);
	if (!cass_cfq_pool)
		goto err_pol_unreg;

	ret = elv_register(&iosched_cass_cfq);
	printk(KERN_INFO "elv_register: ret: %d\n",ret);
	if (ret)
		goto err_free_pool;

	return 0;

err_free_pool:
	kmem_cache_destroy(cass_cfq_pool);
err_pol_unreg:
#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
	blkcg_policy_unregister(&blkcg_policy_cass_cfq);
#endif
	return ret;
}

static void __exit cass_cfq_exit(void)
{
#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
	blkcg_policy_unregister(&blkcg_policy_cass_cfq);
#endif
	elv_unregister(&iosched_cass_cfq);
	kmem_cache_destroy(cass_cfq_pool);
}

module_init(cass_cfq_init);
module_exit(cass_cfq_exit);

MODULE_AUTHOR("Jens Axboe");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Completely Fair Queueing IO scheduler");


#include <linux/module.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/ktime.h>
#include <linux/rbtree.h>
#include <linux/ioprio.h>
#include <linux/blktrace_api.h>
#include <linux/blk-cgroup.h>
#include <linux/notifier.h>

/*
 * tunables
 */
/* max queue in one round of service */
static const int cass_cfq_quantum = 8;
static const u64 cass_cfq_fifo_expire[2] = { NSEC_PER_SEC / 4, NSEC_PER_SEC / 8 };
/* maximum backwards seek, in KiB */
static const int cass_cfq_back_max = 16 * 1024;
/* penalty of a backwards seek */
static const int cass_cfq_back_penalty = 2;
static const u64 cass_cfq_slice_sync = NSEC_PER_SEC / 10;
static u64 cass_cfq_slice_async = NSEC_PER_SEC / 25;
static const int cass_cfq_slice_async_rq = 2;
static u64 cass_cfq_slice_idle = NSEC_PER_SEC / 125;
static u64 cass_cfq_group_idle = NSEC_PER_SEC / 125;
static const u64 cass_cfq_target_latency = (u64)NSEC_PER_SEC * 3/10; /* 300 ms */
static const int cass_cfq_hist_divisor = 4;

/*
 * offset from end of service tree
 */
#define CASS_CFQ_IDLE_DELAY		(NSEC_PER_SEC / 5)

/*
 * below this threshold, we consider thinktime immediate
 */
#define CASS_CFQ_MIN_TT		(2 * NSEC_PER_SEC / HZ)

#define CASS_CFQ_SLICE_SCALE		(5)
#define CASS_CFQ_HW_QUEUE_MIN	(5)
#define CASS_CFQ_SERVICE_SHIFT       12

#define CASS_CFQQ_SEEK_THR		(sector_t)(8 * 100)
#define CASS_CFQQ_CLOSE_THR		(sector_t)(8 * 1024)
#define CASS_CFQQ_SECT_THR_NONROT	(sector_t)(2 * 32)
#define CASS_CFQQ_SEEKY(cass_cfqq)	(hweight32(cass_cfqq->seek_history) > 32/8)

#define RQ_CIC(rq)		icq_to_cic((rq)->elv.icq)
#define RQ_CASS_CFQQ(rq)		(struct cass_cfq_queue *) ((rq)->elv.priv[0])
#define RQ_CASS_CFQG(rq)		(struct cass_cfq_group *) ((rq)->elv.priv[1])

static struct kmem_cache *cass_cfq_pool;

#define CASS_CFQ_PRIO_LISTS		IOPRIO_BE_NR
#define cass_cfq_class_idle(cass_cfqq)	((cass_cfqq)->ioprio_class == IOPRIO_CLASS_IDLE)
#define cass_cfq_class_rt(cass_cfqq)	((cass_cfqq)->ioprio_class == IOPRIO_CLASS_RT)

#define sample_valid(samples)	((samples) > 80)
#define rb_entry_cass_cfqg(node)	rb_entry((node), struct cass_cfq_group, rb_node)

/* blkio-related constants */
#define CASS_CFQ_WEIGHT_LEGACY_MIN	10
#define CASS_CFQ_WEIGHT_LEGACY_DFL	500
#define CASS_CFQ_WEIGHT_LEGACY_MAX	1000

struct cass_cfq_ttime {
	u64 last_end_request;

	u64 ttime_total;
	u64 ttime_mean;
	unsigned long ttime_samples;
};

/*
 * Most of our rbtree usage is for sorting with min extraction, so
 * if we cache the leftmost node we don't have to walk down the tree
 * to find it. Idea borrowed from Ingo Molnars CFS scheduler. We should
 * move this into the elevator for the rq sorting as well.
 */
struct cass_cfq_rb_root {
	struct rb_root rb;
	struct rb_node *left;
	unsigned count;
	u64 min_vdisktime;
	struct cass_cfq_ttime ttime;
};
#define CASS_CFQ_RB_ROOT	(struct cass_cfq_rb_root) { .rb = RB_ROOT, \
			.ttime = {.last_end_request = ktime_get_ns(),},}

/*
 * Per process-grouping structure
 */
struct cass_cfq_queue {
	/* reference count */
	int ref;
	/* various state flags, see below */
	unsigned int flags;
	/* parent cass_cfq_data */
	struct cass_cfq_data *cass_cfqd;
	/* service_tree member */
	struct rb_node rb_node;
	/* service_tree key */
	u64 rb_key;
	/* prio tree member */
	struct rb_node p_node;
	/* prio tree root we belong to, if any */
	struct rb_root *p_root;
	/* sorted list of pending requests */
	struct rb_root sort_list;
	/* if fifo isn't expired, next request to serve */
	struct request *next_rq;
	/* requests queued in sort_list */
	int queued[2];
	/* currently allocated requests */
	int allocated[2];
	/* fifo list of requests in sort_list */
	struct list_head fifo;

	/* time when queue got scheduled in to dispatch first request. */
	u64 dispatch_start;
	u64 allocated_slice;
	u64 slice_dispatch;
	/* time when first request from queue completed and slice started. */
	u64 slice_start;
	u64 slice_end;
	s64 slice_resid;

	/* pending priority requests */
	int prio_pending;
	/* number of requests that are on the dispatch list or inside driver */
	int dispatched;

	/* io prio of this group */
	unsigned short ioprio, org_ioprio;
	unsigned short ioprio_class, org_ioprio_class;

	pid_t pid;

	u32 seek_history;
	sector_t last_request_pos;

	struct cass_cfq_rb_root *service_tree;
	struct cass_cfq_queue *new_cass_cfqq;
	struct cass_cfq_group *cass_cfqg;
	/* Number of sectors dispatched from queue in single dispatch round */
	unsigned long nr_sectors;
};

/*
 * First index in the service_trees.
 * IDLE is handled separately, so it has negative index
 */
enum wl_class_t {
	BE_WORKLOAD = 0,
	RT_WORKLOAD = 1,
	IDLE_WORKLOAD = 2,
	CASS_CFQ_PRIO_NR,
};

/*
 * Second index in the service_trees.
 */
enum wl_type_t {
	ASYNC_WORKLOAD = 0,
	SYNC_NOIDLE_WORKLOAD = 1,
	SYNC_WORKLOAD = 2
};

struct cass_cfqg_stats {
#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
	/* number of ios merged */
	struct blkg_rwstat		merged;
	/* total time spent on device in ns, may not be accurate w/ queueing */
	struct blkg_rwstat		service_time;
	/* total time spent waiting in scheduler queue in ns */
	struct blkg_rwstat		wait_time;
	/* number of IOs queued up */
	struct blkg_rwstat		queued;
	/* total disk time and nr sectors dispatched by this group */
	struct blkg_stat		time;
#ifdef CONFIG_DEBUG_BLK_CGROUP
	/* time not charged to this cgroup */
	struct blkg_stat		unaccounted_time;
	/* sum of number of ios queued across all samples */
	struct blkg_stat		avg_queue_size_sum;
	/* count of samples taken for average */
	struct blkg_stat		avg_queue_size_samples;
	/* how many times this group has been removed from service tree */
	struct blkg_stat		dequeue;
	/* total time spent waiting for it to be assigned a timeslice. */
	struct blkg_stat		group_wait_time;
	/* time spent idling for this blkcg_gq */
	struct blkg_stat		idle_time;
	/* total time with empty current active q with other requests queued */
	struct blkg_stat		empty_time;
	/* fields after this shouldn't be cleared on stat reset */
	uint64_t			start_group_wait_time;
	uint64_t			start_idle_time;
	uint64_t			start_empty_time;
	uint16_t			flags;
#endif	/* CONFIG_DEBUG_BLK_CGROUP */
#endif	/* CONFIG_CASS_CFQ_GROUP_IOSCHED */
};

/* Per-cgroup data */
struct cass_cfq_group_data {
	/* must be the first member */
	struct blkcg_policy_data cpd;

	unsigned int weight;
	unsigned int leaf_weight;
};

/* This is per cgroup per device grouping structure */
struct cass_cfq_group {
	/* must be the first member */
	struct blkg_policy_data pd;

	/* group service_tree member */
	struct rb_node rb_node;

	/* group service_tree key */
	u64 vdisktime;

	/*
	 * The number of active cass_cfqgs and sum of their weights under this
	 * cass_cfqg.  This covers this cass_cfqg's leaf_weight and all children's
	 * weights, but does not cover weights of further descendants.
	 *
	 * If a cass_cfqg is on the service tree, it's active.  An active cass_cfqg
	 * also activates its parent and contributes to the children_weight
	 * of the parent.
	 */
	int nr_active;
	unsigned int children_weight;

	/*
	 * vfraction is the fraction of vdisktime that the tasks in this
	 * cass_cfqg are entitled to.  This is determined by compounding the
	 * ratios walking up from this cass_cfqg to the root.
	 *
	 * It is in fixed point w/ CASS_CFQ_SERVICE_SHIFT and the sum of all
	 * vfractions on a service tree is approximately 1.  The sum may
	 * deviate a bit due to rounding errors and fluctuations caused by
	 * cass_cfqgs entering and leaving the service tree.
	 */
	unsigned int vfraction;

	/*
	 * There are two weights - (internal) weight is the weight of this
	 * cass_cfqg against the sibling cass_cfqgs.  leaf_weight is the wight of
	 * this cass_cfqg against the child cass_cfqgs.  For the root cass_cfqg, both
	 * weights are kept in sync for backward compatibility.
	 */
	unsigned int weight;
	unsigned int new_weight;
	unsigned int dev_weight;

	unsigned int leaf_weight;
	unsigned int new_leaf_weight;
	unsigned int dev_leaf_weight;

	/* number of cass_cfqq currently on this group */
	int nr_cass_cfqq;

	/*
	 * Per group busy queues average. Useful for workload slice calc. We
	 * create the array for each prio class but at run time it is used
	 * only for RT and BE class and slot for IDLE class remains unused.
	 * This is primarily done to avoid confusion and a gcc warning.
	 */
	unsigned int busy_queues_avg[CASS_CFQ_PRIO_NR];
	/*
	 * rr lists of queues with requests. We maintain service trees for
	 * RT and BE classes. These trees are subdivided in subclasses
	 * of SYNC, SYNC_NOIDLE and ASYNC based on workload type. For IDLE
	 * class there is no subclassification and all the cass_cfq queues go on
	 * a single tree service_tree_idle.
	 * Counts are embedded in the cass_cfq_rb_root
	 */
	struct cass_cfq_rb_root service_trees[2][3];
	struct cass_cfq_rb_root service_tree_idle;

	u64 saved_wl_slice;
	enum wl_type_t saved_wl_type;
	enum wl_class_t saved_wl_class;

	/* number of requests that are on the dispatch list or inside driver */
	int dispatched;
	struct cass_cfq_ttime ttime;
	struct cass_cfqg_stats stats;	/* stats for this cass_cfqg */

	/* async queue for each priority case */
	struct cass_cfq_queue *async_cass_cfqq[2][IOPRIO_BE_NR];
	struct cass_cfq_queue *async_idle_cass_cfqq;

	struct cass_cfq_data *cass_cfqd;
	unsigned int group_no;
	u64 iops;
	unsigned long long start_time_ns;
	unsigned long long finish_time_ns;
};

struct cass_cfq_io_cq {
	struct io_cq		icq;		/* must be the first member */
	struct cass_cfq_queue	*cass_cfqq[2];
	struct cass_cfq_ttime	ttime;
	int			ioprio;		/* the current ioprio */
#ifdef CONFIG_CASS_CFQ_GROUP_IOSCHED
	uint64_t		blkcg_serial_nr; /* the current blkcg serial */
#endif
};

struct cass_cfq_groups_rb_root {
	struct rb_root rb;
	unsigned count;
	unsigned int weight;
};
#define CASS_CFQ_GROUPS_RB_ROOT	(struct cass_cfq_groups_rb_root) { .rb = RB_ROOT, \
			.count = 0,}

/*
 * Per block device queue structure
 */
struct cass_cfq_data {
	struct request_queue *queue;
	/* Root service tree for cass_cfq_groups */
	struct cass_cfq_rb_root grp_service_tree;
	struct cass_cfq_group *root_group;

	/*
	 * The priority currently being served
	 */
	enum wl_class_t serving_wl_class;
	enum wl_type_t serving_wl_type;
	u64 workload_expires;
	struct cass_cfq_group *serving_group;

	/*
	 * Each priority tree is sorted by next_request position.  These
	 * trees are used when determining if two or more queues are
	 * interleaving requests (see cass_cfq_close_cooperator).
	 */
	struct rb_root prio_trees[CASS_CFQ_PRIO_LISTS];

	unsigned int busy_queues;
	unsigned int busy_sync_queues;

	int rq_in_driver;
	int rq_in_flight[2];

	/*
	 * queue-depth detection
	 */
	int rq_queued;
	int hw_tag;
	/*
	 * hw_tag can be
	 * -1 => indeterminate, (cass_cfq will behave as if NCQ is present, to allow better detection)
	 *  1 => NCQ is present (hw_tag_est_depth is the estimated max depth)
	 *  0 => no NCQ
	 */
	int hw_tag_est_depth;
	unsigned int hw_tag_samples;

	/*
	 * idle window management
	 */
	struct hrtimer idle_slice_timer;
	struct work_struct unplug_work;

	struct cass_cfq_queue *active_queue;
	struct cass_cfq_io_cq *active_cic;

	sector_t last_position;

	/*
	 * tunables, see top of file
	 */
	unsigned int cass_cfq_quantum;
	unsigned int cass_cfq_back_penalty;
	unsigned int cass_cfq_back_max;
	unsigned int cass_cfq_slice_async_rq;
	unsigned int cass_cfq_latency;
	u64 cass_cfq_fifo_expire[2];
	u64 cass_cfq_slice[2];
	u64 cass_cfq_slice_idle;
	u64 cass_cfq_group_idle;
	u64 cass_cfq_target_latency;

	/*
	 * Fallback dummy cass_cfqq for extreme OOM conditions
	 */
	struct cass_cfq_queue oom_cass_cfqq;

	u64 last_delayed_sync;

	struct blocking_notifier_head cass_cfq_notifier_list;

	struct cass_cfq_groups_rb_root groups_rb_root;
};

static struct cass_cfq_group *cass_cfq_get_next_cass_cfqg(struct cass_cfq_data *cass_cfqd);
static void cass_cfq_put_queue(struct cass_cfq_queue *cass_cfqq);

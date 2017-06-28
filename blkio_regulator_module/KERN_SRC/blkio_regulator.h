
#define DRIVER_NAME "blkio_regulator"
#define PDEBUG(fmt,args...) printk(KERN_DEBUG"%s:"fmt,DRIVER_NAME, ##args)
#define PERR(fmt,args...) printk(KERN_ERR"%s:"fmt,DRIVER_NAME,##args)
#define PINFO(fmt,args...) printk(KERN_INFO"%s:"fmt,DRIVER_NAME, ##args)
#include<linux/init.h>
#include<linux/module.h>
#include <linux/device.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <linux/elevator.h>
#include <linux/cfq_iosched.h>
#include <linux/ktime.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

#define ALPHA 2
#define BETA 1
#define MAX_CFTYPE_NAME		64

/*struct registered_devices {
	char *type;
	struct device *dev;
	struct gendisk *disk;
	struct list_head list;
};*/

struct dispatched_requests{
	unsigned long int data_len;
	spinlock_t list_lck;
	struct list_head list;
};

struct dispatched_requests_list{
	struct list_head head;
};

struct regulator_data{
	bool flag;
	spinlock_t list_lck;
	unsigned long latency;
	unsigned long latency_thrld;
	char disk_name[MAX_CFTYPE_NAME];
	struct request_queue *q;
	struct timer_list fb_timer;
	struct dispatched_requests_list dsp_req_head;
	unsigned long int data_len;
};

struct blk_device_list {
	struct list_head head;
};

static inline struct registered_devices *blk_device_list_pop(struct blk_device_list *bdl)
{
	struct registered_devices *reg_blk_dev = list_first_entry(&bdl->head, struct registered_devices, list);

	if (reg_blk_dev) {
		list_del(&reg_blk_dev->list);
	}

	return reg_blk_dev;
}

static inline struct dispatched_requests *dispatched_requests_list_pop(struct dispatched_requests_list *drl)
{
	unsigned int flags;
	struct dispatched_requests* dsp_reqs= list_first_entry(&drl->head, struct dispatched_requests, list);

	if (dsp_reqs) {
		spin_lock_irqsave(&dsp_reqs->list_lck,flags);
		list_del(&dsp_reqs->list);
		spin_unlock_irqrestore(&dsp_reqs->list_lck,flags);
	}

	return dsp_reqs;
}

/*
===============================================================================
Driver Name		:		blkio_regulator
Author			:		VAMSEE
License			:		GPL
Description		:		LINUX DEVICE DRIVER PROJECT
===============================================================================
*/

#include"blkio_regulator.h"
#include<linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("VAMSEE");

extern void printk_all_disks(struct list_head *blk_reg_head);
extern void cfq_register_notifier(struct request_queue *q, struct notifier_block *nb);
extern void cfq_unregister_notifier(struct request_queue *q, struct notifier_block *nb);

#define ALPHA 2
#define BETA 1

/*struct registered_devices {
	char *type;
	struct device *dev;
	struct gendisk *disk;
	struct list_head list;
};*/

struct regulator_data{
	struct request_queue *q;
	//struct hrtimer fb_timer;
	struct timer_list fb_timer;
	struct list_head blk_reg_head;
	unsigned long latency;
	unsigned long latency_thrld;
	bool flag;
};

struct regulator_data *rgld = NULL;
static char *device = "sda";
//MODULE_PARM(device, "s");

static int alloc_regulator(void){
	rgld = (struct regulator_data *)kmalloc(sizeof(
			struct regulator_data),GFP_KERNEL);
	if(!rgld)
		return 1;

	rgld->flag = false;
	return 0;
}

static void unalloc_regulator(void){
	kfree(rgld);
}

/*
 * Whenever the average latency l > L, our method decreases the IOPS
 * rate. When the overload subsides and l < L , the IOPS rate is increased.
 *
 * r(t) is iops at time t
 * r(t+1) = (1 − γ)r(t) + γ(L/l)r(t) ; γ ∈ [0, 1] (0.25)
 *
 */
static void update_iops(struct request_queue *q){
	struct cfq_data *cfqd;
	unsigned int iops;

	cfqd = q->elevator->elevator_data;
	iops = cfqd->cfq_slice_async_rq; //it is a constant which is always set to 2

	if(rgld->latency){
		iops = (4-BETA) * iops + BETA * (rgld->latency_thrld/rgld->latency) * iops;
		iops = (int)iops/4;
	}

	//printk(KERN_INFO "threshold: %lu, current latency: %lu, iops: %u, slice_async_rq: %u\n",rgld->latency_thrld,rgld->latency,iops,cfqd->cfq_slice_async_rq);

	//if(iops)
		//cfqd->cfq_slice_async_rq = iops;
	return;
}

/*
 * calc_latency - calculate the latency of a block device using the requests send to
 * a specific block device (request queue)
 * @q: 	request queue allocated to a block device
 *
 * return value:	calculated/estimated latency of a block device.
 *
 * L is the DataNode-wide latency threshold which is proportional to the size of requests.
 * L = 9.63 for a request size of 128K
 *
 * Given a new latency observation
 * l(t) = (1 − α)l + αl(t−1) ; α ∈ [0, 1] (0.5)
 */
static void calc_latency(struct request_queue *q){
	struct request *rq;
	struct list_head *queue_head;
	struct cfq_data *cfqd;
	unsigned int data = 0;
	int count = 0;

	queue_head = &q->queue_head;

	list_for_each_entry(rq, queue_head, queuelist) {
		if(rq == NULL)
			PINFO("null\n");
		else{
			count++;
			data += rq->__data_len;
		}
	}

	cfqd = q->elevator->elevator_data;
	printk(KERN_INFO "cfqd->hw_tag: %d cfqd->slice: %d\n", cfqd->hw_tag, cfqd->cfq_slice_idle);
	rgld->latency_thrld = q->nr_requests * 1024; //128KB
	//rgld->latency = (4-ALPHA) * data + ALPHA * rgld->latency;
	rgld->latency = data;
	return;
}

static int cfq_notification_handler (struct notifier_block *nb, unsigned long action, void *data){

	struct request_queue *q;

	q = (struct request_queue *)data;

	if(action != 2)
		return 0;
	calc_latency(q);

	update_iops(q);
	return 0;
}

static struct notifier_block cfq_notifier = {
	.notifier_call = cfq_notification_handler,
};

/*
 * scan_and_get_blk_device - scan all the block devices registered with
 * the block io and search for a specific device of interest as of now.
 * @list : registered block devices list
 *
 * return value : request queue of block device in interest
 */
static struct request_queue *scan_and_get_blk_device(struct list_head *dev_list){
	struct registered_devices *blk_reg_dev;

	list_for_each_entry(blk_reg_dev,dev_list,list){
		if(likely(strcmp(blk_reg_dev->disk->disk_name, "sda") == 0)){
			printk(KERN_INFO "disk name: %s\n", blk_reg_dev->disk->disk_name);
			return blk_reg_dev->disk->queue;
		}
	}
	return NULL;
}

static int __init blkio_regulator_init(void)
{

	PINFO("INIT\n");
	if(alloc_regulator()){
		printk(KERN_INFO "Error allocting regulator data\n");
		return 0;
	}

	INIT_LIST_HEAD(&rgld->blk_reg_head);
	printk_all_disks(&rgld->blk_reg_head);

	rgld->q = scan_and_get_blk_device(&rgld->blk_reg_head);
	if(rgld->q == NULL)
		return 0;

	/* register for cfq_notifier */
	cfq_register_notifier(rgld->q,&cfq_notifier);

	return 0;
}

static void __exit blkio_regulator_exit(void)
{	
	PINFO("EXIT\n");

	if(rgld->q != NULL)
		cfq_unregister_notifier(rgld->q,&cfq_notifier);
	unalloc_regulator();
}

module_init(blkio_regulator_init);
module_exit(blkio_regulator_exit);

/*static enum hrtimer_restart feedback_timer(struct hrtimer *timer)
{
	unsigned long int latency;

	printk(KERN_INFO "hrtimer\n");

	PINFO("Max number of requests for this device is : %lu\n",rgl_data->q->nr_requests);
	//rgl_data->q = scan_and_get_blk_device(&rgl_data->blk_reg_head);
	//latency = calc_latency(rgl_data->q);
	// if latency is too large or too slow update cfq_iops
	//update_cfq_iops(rgl_data->q, latency);

	return HRTIMER_RESTART;
}

void feedback_timer(unsigned long int data)
{
	unsigned long int latency;
	PINFO("Max number of requests for this device is : %lu\n",rgl_data->q->nr_requests);
	latency = calc_latency(rgl_data->q);
	//update_cfq_iops(rgl_data->q, latency);
	mod_timer(&rgl_data->fb_timer,jiffies+5*HZ);
}

	rgl_data->fb_timer.expires = jiffies + 5*HZ;
	rgl_data->fb_timer.function = feedback_timer;
	init_timer(&rgl_data->fb_timer);
	add_timer(&rgl_data->fb_timer);

	hrtimer_init(&rgl_data->fb_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	rgl_data->fb_timer.function = feedback_timer;
	hrtimer_start(&rgl_data->fb_timer, ms_to_ktime(10000), HRTIMER_MODE_REL);

	while(hrtimer_active(&rgl_data->fb_timer));
	del_timer_sync(&rgl_data->fb_timer);
	hrtimer_cancel(&rgl_data->fb_timer);
*/

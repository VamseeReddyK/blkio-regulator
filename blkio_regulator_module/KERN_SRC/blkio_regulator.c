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

struct blk_device_list bdl;
struct regulator_data *rgld;

static struct regulator_data *alloc_regulator(void){

	return (struct regulator_data *)kmalloc(sizeof(
			struct regulator_data),GFP_KERNEL);
}

static void unalloc_regulator(struct regulator_data *rgld){
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
static void update_iops(struct regulator_data *rgld){
	struct cfq_data *cfqd = rgld->q->elevator->elevator_data;
	unsigned int iops =cfqd->cfq_slice_async_rq; //it is a constant which is always set to 2

	if(rgld->latency){
		iops = (4-BETA) * iops + BETA * (rgld->latency_thrld/rgld->latency) * iops;
		iops = (int)iops/4;
	}

	printk(KERN_INFO "threshold: %lu, current latency: %lu, iops: %u, slice_async_rq: %u\n",rgld->latency_thrld,rgld->latency,iops,cfqd->cfq_slice_async_rq);

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
static void calc_latency(struct regulator_data *rgld){
	struct request_queue *q = rgld->q;
	//struct dispatched_requests *dsp_reqs;
	unsigned long int data_len;

	//dsp_reqs = dispatched_requests_list_pop(&rgld->dsp_req_head);
	data_len = rgld->data_len;
	rgld->data_len = 0;

	rgld->latency_thrld = q->nr_requests * 1024; //128KB
	rgld->latency = (4-ALPHA) * data_len + ALPHA * rgld->latency;
	return;
}

static int cfq_notification_handler (struct notifier_block *nb, unsigned long action, void *data)
{
	struct request *rq = (struct request*)data;
	//struct request_queue *q;
	//struct regulator_data *rgld;

	if(action != 2)
		return 0;

	//rgld = (struct regulator_data *)container_of(q, struct regulator_data, q);

	if(rq)
		rgld->data_len += rq->__data_len;
	printk(KERN_INFO "rgld->data_len: %lu",rgld->data_len);
	return 0;
}

static struct notifier_block cfq_notifier = {
	.notifier_call = cfq_notification_handler,
};

void feedback_timer(unsigned long int data)
{
	struct regulator_data *rgl_data;

	rgl_data = (struct regulator_data *)data;
	calc_latency(rgl_data);
	update_iops(rgl_data);

	mod_timer(&rgl_data->fb_timer,jiffies+1*HZ/10);
}

static void init_regulator(struct regulator_data *rgld)
{
	rgld->flag = false;
	rgld->data_len = 0;
	rgld->latency = 0;
	//spin_lock_init(&rgld->list_lck);
	//INIT_LIST_HEAD(&rgld->dsp_req_head);

	/* feedback timer to monitor iops for fair proportionality*/
	rgld->fb_timer.expires = jiffies + 1*HZ/10;
	rgld->fb_timer.function = feedback_timer;
	rgld->fb_timer.data = (unsigned long int)rgld;
	init_timer(&rgld->fb_timer);
	add_timer(&rgld->fb_timer);

	/* register for cfq_notifier */
	cfq_register_notifier(rgld->q,&cfq_notifier);
	return;
}

/*
 * scan_and_get_blk_device - scan all the block devices registered with
 * the block io and search for a specific device of interest as of now.
 * @list : registered block devices list
 *
 * return value : request queue of block device in interest
 */
static int init_regulator_for_all(struct blk_device_list *bdl){
	struct registered_devices *reg_blk_dev;

	//for (reg_blk_dev = blk_device_list_pop(bdl);reg_blk_dev;
	//		reg_blk_dev = blk_device_list_pop(bdl)) {
	list_for_each_entry(reg_blk_dev,&bdl->head,list){

		if(likely(strcmp(reg_blk_dev->disk->disk_name, "sda") == 0)){

			rgld = alloc_regulator();
			if(!rgld){
				printk(KERN_INFO "Error allocting regulator data\n");
				goto err_alloc;
			}
			printk(KERN_INFO "disk name: %s\n", reg_blk_dev->disk->disk_name);
			strcpy(rgld->disk_name,reg_blk_dev->disk->disk_name);
			rgld->q = reg_blk_dev->disk->queue;
			init_regulator(rgld);
			return 0;
		}
	}
	return 0;

err_alloc:
	return 1;
}

static int __init blkio_regulator_init(void)
{
	PINFO("INIT\n");
	int ret = 0;

	INIT_LIST_HEAD(&bdl.head);
	printk_all_disks(&bdl.head);

	ret = init_regulator_for_all(&bdl);
	if(ret)
		return 0;

	return 0;
}

static void __exit blkio_regulator_exit(void)
{	
	PINFO("EXIT\n");

	del_timer_sync(&rgld->fb_timer);

	if(rgld->q != NULL)
		cfq_unregister_notifier(rgld->q,&cfq_notifier);
	unalloc_regulator(rgld);
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

	hrtimer_init(&rgl_data->fb_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	rgl_data->fb_timer.function = feedback_timer;
	hrtimer_start(&rgl_data->fb_timer, ms_to_ktime(10000), HRTIMER_MODE_REL);

	while(hrtimer_active(&rgl_data->fb_timer));
	hrtimer_cancel(&rgl_data->fb_timer);
*/

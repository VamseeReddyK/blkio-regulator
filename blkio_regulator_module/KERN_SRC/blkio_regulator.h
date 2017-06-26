
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

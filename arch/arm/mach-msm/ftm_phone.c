/*
 *     ftm_phone.c - FTM Phone Driver
 *
 *     Copyright (C) 2010 Henry MC Wang <henrymcwang@fihtdc.com>
 *     Copyright (C) 2010 FIH CO., Inc.
 *
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; version 2 of the License.
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <mach/gpio.h>
#include <linux/miscdevice.h>
#include <linux/platform_device.h>
#include <linux/fs.h>
#include <asm/ioctl.h>
#include "proc_comm.h"

static int ftm_phone_dev_open( struct inode * inodep, struct file * filep )
{
	printk( KERN_INFO "%s\n", __func__);

	return 0;
}

static int ftm_phone_dev_release( struct inode * inodep, struct file * filep )
{
	printk( KERN_INFO "%s\n", __func__);
    
	return 0;
}

static ssize_t ftm_phone_dev_read( struct file * filep, char __user * buffer, size_t size, loff_t * f_pos )
{
	int result = 0;
    
	printk( KERN_INFO "%s\n", __func__);

	return result;    
}

static ssize_t ftm_phone_dev_write( struct file * filep, const char __user * buffer, size_t size, loff_t * f_pos )
{
	int result = 0;

	printk( KERN_INFO "%s\n", __func__);

	return result;
}

static int ftm_phone_dev_ioctl( struct inode * inodep, struct file * filep, unsigned int cmd, unsigned long arg )
{
	int rc = 0;
	printk( KERN_INFO "%s: Command = %d\n", __func__, cmd);
	
	switch(cmd)
	{
		case 0:
			rc = proc_comm_phone_online();
			break;
		case 1:
			rc = proc_comm_phone_setpref();
			break;
		case 2:
			rc = proc_comm_phone_dialemergency();
			break;
		case 3:
			rc = proc_comm_phone_getsimstatus();
			printk(KERN_INFO "%s: get sim status = %d\r\n", __func__, rc);
			break;
		default:
			rc = 1;
			printk(KERN_INFO "%s: Unknown Command = %d\r\n", __func__, cmd);
	}

	return rc;
}

static struct file_operations ftm_phone_dev_fops = {
	.open = ftm_phone_dev_open,
	.read = ftm_phone_dev_read,
	.write =  ftm_phone_dev_write,
	.ioctl =  ftm_phone_dev_ioctl,
	.release =  ftm_phone_dev_release,
};

static struct miscdevice ftm_phone_cdev = {
	MISC_DYNAMIC_MINOR,
	"ftm_phone",
	&ftm_phone_dev_fops
};

static int ftm_phone_probe(struct platform_device *pdev)
{
	printk(KERN_INFO "%s ftm_phone_probe\r\n", __func__);
	misc_register(&ftm_phone_cdev);
	return 0;
}

static int __devexit ftm_phone_remove(struct platform_device *pdev)
{
	printk(KERN_INFO "%s ftm_phone_remove\r\n", __func__);
	return 0;
}

static struct platform_driver ftm_phone_driver = {
	.probe		= ftm_phone_probe,
	.remove		= __devexit_p(ftm_phone_remove),
	.driver		= {
		.name	= "ftm_phone",
		.owner	= THIS_MODULE,
	},
};

static int __init ftm_phone_init(void)
{
	return platform_driver_register(&ftm_phone_driver);
}

static void __exit ftm_phone_exit(void)
{
	platform_driver_unregister(&ftm_phone_driver);
}

module_init(ftm_phone_init);
module_exit(ftm_phone_exit);


MODULE_AUTHOR("Henry Wang <HenryMCWang@fihtdc.com>");
MODULE_DESCRIPTION("FTM Phone driver");
MODULE_LICENSE("GPL");

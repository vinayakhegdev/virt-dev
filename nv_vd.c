#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/wait.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/init.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/suspend.h>
#include <linux/freezer.h>
#include <linux/mutex.h>
#include <linux/writeback.h>
#include <linux/completion.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/splice.h>
#include <linux/sysfs.h>
#include <linux/miscdevice.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include "nv_internal.h"
#include "nv_device.h"

#include <asm/uaccess.h>

static DEFINE_IDR(nv_vd_index_idr);
static DEFINE_MUTEX(nv_vd_index_mutex);

static int nv_vd_max_part;
static int nv_vd_part_shift;
static int nv_vd_max;
static int gb = 32;

static int 
nv_vd_open(struct block_device *bdev, fmode_t mode) {
    nv_virtual_device_t *vd = NULL;
	int err = 0;

    pr_crit("Enter opening block device\n");
	vd = bdev->bd_disk->private_data;
	if(!vd) {
		err = -ENXIO;
		goto out;
	}

	mutex_lock(&vd->vd_ctl_mutex);
	vd->vd_refcnt++;
	mutex_unlock(&vd->vd_ctl_mutex);
out:

    pr_crit("Exit opening block device\n");
	return err;
}

static void 
nv_vd_release(struct gendisk *disk, fmode_t mode) {
    nv_virtual_device_t *vd = disk->private_data;

    pr_crit("Enter releasing block device\n");
	mutex_lock(&vd->vd_ctl_mutex);

	if(--vd->vd_refcnt) {
		goto out;
    }

out:

    pr_crit("Exit releasing block device\n");
	mutex_unlock(&vd->vd_ctl_mutex);
}

static const struct block_device_operations nv_vd_fops = {
	.owner =	THIS_MODULE,
	.open =		nv_vd_open,
	.release =	nv_vd_release,
	.ioctl =	NULL,
#ifdef CONFIG_COMPAT
	.compat_ioctl =	NULL,
#endif
};

/*
 * And now the modules code and kernel interface.
 */
module_param(nv_vd_max, int, S_IRUGO);
MODULE_PARM_DESC(nv_vd_max, "Maximum number of nv virtual devices");
module_param(nv_vd_max_part, int, S_IRUGO);
MODULE_PARM_DESC(nv_vd_max_part, "Maximum number of partitions per nv device");
MODULE_LICENSE("GPL");
static int nv_vd_major = 0;
MODULE_ALIAS_MISCDEV(NV_CTRL_MINOR);
static int bs = 512;
module_param(bs, int, S_IRUGO);
MODULE_PARM_DESC(bs, "Block size (in bytes)");

void
nv_virtual_io_end(void *arg) {
    nv_cmd_t *cmd = (nv_cmd_t *) arg;
    blk_mq_complete_request(cmd->rq);
    
    return;
}

static void 
nv_vd_handle_cmd(nv_cmd_t *cmd) {
	int ret = 0;
    sector_t start_sector = 0;

    pr_crit("entering vd handle cmd\n");
    blk_mq_start_request(cmd->rq);
    
    start_sector = cmd->rq->bio->bi_iter.bi_sector;

    if(cmd->rq->cmd_flags & REQ_WRITE) {
        pr_crit("entering write %llu\n", start_sector);
        ret = nv_block_write(cmd, 0); 
    } else {
        pr_crit("entering read %llu\n", start_sector);
        ret = nv_block_read(cmd, 0); 
    } 
    
    pr_crit("exiting vd handle cmd\n");
    return;
}

static int 
nv_vd_queue_rq(struct blk_mq_hw_ctx *hctx,
		             const struct blk_mq_queue_data *bd) {
    nv_cmd_t *cmd = blk_mq_rq_to_pdu(bd->rq);
    //nv_virtual_device_t *vd = cmd->rq->q->queuedata;

	cmd->rq = bd->rq;
    cmd->virtual_io_end = &nv_virtual_io_end;
    
    nv_vd_handle_cmd(cmd);

	return BLK_MQ_RQ_QUEUE_OK;
}

static int 
nv_vd_init_request(void *data, struct request *rq,
		unsigned int hctx_idx, unsigned int request_idx,
		unsigned int numa_node) {
    nv_cmd_t *cmd = blk_mq_rq_to_pdu(rq);
    pr_crit("Entering init request\n");

	cmd->rq = rq;
    cmd->virtual_io_end = &nv_virtual_io_end;
    	
    pr_crit("Exiting init request\n");
    return 0;
}

static inline void 
nv_vd_request_done(struct request *req) {
    int error = 0;
    blk_mq_end_request(req, error);
}

static struct blk_mq_ops nv_vd_mq_ops = {
	.queue_rq       = nv_vd_queue_rq,
	.map_queue      = blk_mq_map_queue,
	.init_request	= nv_vd_init_request,
    .complete = nv_vd_request_done,
};

static int 
nv_vd_add(nv_virtual_device_t **l, int i) {
    nv_virtual_device_t *vd = NULL;
	struct gendisk *disk = NULL;
	int err = 0;
    sector_t size = 0;

	err = -ENOMEM;
	vd = kmalloc(sizeof(*vd), GFP_KERNEL);  
	
    if(!vd) {
        pr_crit("memory allocation failed for virtual device\n");
		goto out;
    }

    memset(vd, 0, sizeof(*vd));

	vd->vd_state = vd_unbound;

	if(i >= 0) {
        err = idr_alloc(&nv_vd_index_idr, 
                        vd, i, i + 1, GFP_KERNEL);
		if(err == -ENOSPC) {
			err = -EEXIST;
        }     
	} else {
		err = idr_alloc(&nv_vd_index_idr, vd, 0, 0, 
                        GFP_KERNEL);
	}
	
    if(err < 0) {
		pr_crit("idr allcoation failed %d\n", i);
        goto out_free_dev;
    }

	i = err;

	err = -ENOMEM;
	vd->tag_set.ops = &nv_vd_mq_ops;
	vd->tag_set.nr_hw_queues = 64;
	vd->tag_set.queue_depth = 64;
	vd->tag_set.numa_node = NUMA_NO_NODE;
	vd->tag_set.cmd_size = sizeof(nv_cmd_t);
	vd->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_SG_MERGE;
	vd->tag_set.driver_data = vd;

	err = blk_mq_alloc_tag_set(&vd->tag_set);
	if(err) {
        pr_crit("mq alloc tag set failed %d error %d\n", i, err);
		goto out_free_idr;
    }

	vd->vd_queue = blk_mq_init_queue(&vd->tag_set);
	if(IS_ERR_OR_NULL(vd->vd_queue)) {
		err = PTR_ERR(vd->vd_queue);
        pr_crit("mq queue init failed %d\n", i);
		goto out_cleanup_tags;
	}
	vd->vd_queue->queuedata = vd;

	disk = vd->vd_disk = alloc_disk(1 << nv_vd_part_shift);
	if(!disk) {
        pr_crit("alloc disk failed %d\n", i);
		goto out_free_queue;
    }
	
	disk->flags |= GENHD_FL_EXT_DEVT | GENHD_FL_SUPPRESS_PARTITION_INFO;
	mutex_init(&vd->vd_ctl_mutex);
	vd->vd_number		= i;
	spin_lock_init(&vd->vd_lock);
	disk->major		= nv_vd_major;
	disk->first_minor	= i << nv_vd_part_shift;
	disk->fops		= &nv_vd_fops;
	disk->private_data	= vd;
	disk->queue		= vd->vd_queue;
	
    queue_flag_set_unlocked(QUEUE_FLAG_NONROT, vd->vd_queue);
    queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, vd->vd_queue);

    size = gb * 1024 * 1024 * 1024ULL;
    sector_div(size, bs);
    set_capacity(disk, size);
    
    sprintf(disk->disk_name, "nv_vd%d", i);
	pr_crit("adding disk %llu\n", i);
    add_disk(disk);
	*l = vd;
	return vd->vd_number;

out_free_queue:
	blk_cleanup_queue(vd->vd_queue);
out_cleanup_tags:
	blk_mq_free_tag_set(&vd->tag_set);
out_free_idr:
	idr_remove(&nv_vd_index_idr, i);
out_free_dev:
	kfree(vd);
out:
	return err;
}

static void 
nv_vd_remove(nv_virtual_device_t *vd) {
	del_gendisk(vd->vd_disk);
	blk_cleanup_queue(vd->vd_queue);
	blk_mq_free_tag_set(&vd->tag_set);
	put_disk(vd->vd_disk);
	kfree(vd);
}

static int 
find_free_cb(int id, void *ptr, void *data) {
    nv_virtual_device_t *vd = ptr;    
    nv_virtual_device_t **l = data;

	if (vd->vd_state == vd_unbound) {
		*l = vd;
		return 1;
	}
	return 0;
}

static int 
nv_vd_lookup(nv_virtual_device_t **l, int i) {
    nv_virtual_device_t *vd = NULL;
	int ret = -ENODEV;

	if(i < 0) {
		int err = 0;

		err = idr_for_each(&nv_vd_index_idr, &find_free_cb, &vd);
		if(err == 1) {
			*l = vd;
			ret = vd->vd_number;
		}
		goto out;
	}

	/* lookup and return a specific i */
	vd = idr_find(&nv_vd_index_idr, i);
	if(vd) {
        *l = vd;
		ret = vd->vd_number;
	}
out:
	return ret;
}

static struct kobject *
nv_vd_probe(dev_t dev, int *part, void *data) {
    nv_virtual_device_t *vd = NULL;
	struct kobject *kobj = NULL;
	int err = 0;;

	mutex_lock(&nv_vd_index_mutex);
	pr_crit("entering probe\n");
    err = nv_vd_lookup(&vd, MINOR(dev) >> nv_vd_part_shift);
	if(err < 0) {
		err = nv_vd_add(&vd, MINOR(dev) >> nv_vd_part_shift);
	}
    if(err < 0) {
		kobj = NULL;
    } else {
		kobj = get_disk(vd->vd_disk);
    }     
	mutex_unlock(&nv_vd_index_mutex);

	*part = 0;
    pr_crit("exiting probe\n");
	return kobj;
}

static long 
nv_control_ioctl(struct file *file, unsigned int cmd,
	     		       unsigned long parm) {
    nv_virtual_device_t *vd = NULL;
	int ret = -ENOSYS;

	mutex_lock(&nv_vd_index_mutex);
	switch(cmd) {
	    case NV_CTL_ADD:
		    ret = nv_vd_lookup(&vd, parm);
		    if(ret >= 0) {
			    ret = -EEXIST;
			    break;
		    }
		    ret = nv_vd_add(&vd, parm);
		    break;
	    case NV_CTL_REMOVE:
		    ret = nv_vd_lookup(&vd, parm);
		    if(ret < 0) {
			    break;
		    }
            mutex_lock(&vd->vd_ctl_mutex);
		    if(vd->vd_state != vd_unbound) {
			    ret = -EBUSY;
                mutex_unlock(&vd->vd_ctl_mutex);
			    break;  
            }
    
            if(vd->vd_refcnt > 0) {
		        ret = -EBUSY;
			    mutex_unlock(&vd->vd_ctl_mutex);
			    break;
		    }
		    vd->vd_disk->private_data = NULL;
		    mutex_unlock(&vd->vd_ctl_mutex);
		    idr_remove(&nv_vd_index_idr, vd->vd_number);
		    nv_vd_remove(vd);
		    break;
	    case NV_CTL_GET_FREE:
		    ret = nv_vd_lookup(&vd, -1);
		    if(ret >= 0) {
			    break;
		    }
            ret = nv_vd_add(&vd, -1);
	}
	mutex_unlock(&nv_vd_index_mutex);

	return ret;
}

static const struct file_operations nv_ctl_fops = {
	.open		= nonseekable_open,
	.unlocked_ioctl	= nv_control_ioctl,
	.compat_ioctl	= nv_control_ioctl,
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
};

static struct miscdevice nv_vd_misc = {
	.minor		= NV_CTRL_MINOR,
	.name		= "nv-control",
	.fops		= &nv_ctl_fops,
};


static int __init nv_vd_init(void) {
	int i, nr;
	unsigned long range;    
    nv_virtual_device_t *vd;
	int err;

    err = nv_dev_init();
    if(err) {
        pr_crit("registering nv dev failed\n");
        goto end;
    }

    err = nv_block_init();
    if(err) {
        pr_crit("failed to init the nv block device\n");
        goto clean_block;
    }
	
    err = misc_register(&nv_vd_misc);
	if(err < 0) {
        pr_crit("registering misc device failed\n");    
        goto clean_dev;
    }       

	nv_vd_part_shift = 0;
	if(nv_vd_max_part > 0) {
		nv_vd_part_shift = fls(nv_vd_max_part);
        nv_vd_max_part = (1UL << nv_vd_part_shift) - 1;
	}

	if((1UL << nv_vd_part_shift) > DISK_MAX_PARTS) {
		err = -EINVAL;
		goto misc_out;
	}

	if(nv_vd_max > 1UL << (MINORBITS - nv_vd_part_shift)) {
		err = -EINVAL;
		goto misc_out;
	}

	if(nv_vd_max) {
		nr = nv_vd_max;
		range = nv_vd_max << nv_vd_part_shift;
	} else {
		nr = CONFIG_VD_DEV_NV_MIN_COUNT;
		range = 1UL << MINORBITS;
	}

	nv_vd_major = register_blkdev(0, "nv_vd");
    pr_crit("major number allocated %d\n", nv_vd_major);
    if(nv_vd_major < 0) {
		err = -EIO;
		goto misc_out;
	}

	blk_register_region(MKDEV(nv_vd_major, 0), range,
				  THIS_MODULE, nv_vd_probe, NULL, NULL);

	
    mutex_lock(&nv_vd_index_mutex);
    pr_crit("number of device %d\n", nr);
	for(i = 0; i < nr; i++) {
        pr_crit("starting vd add %d\n", i);
        nv_vd_add(&vd, i);
        pr_crit("ending vd add %d\n", i);
    }      
    
	mutex_unlock(&nv_vd_index_mutex);

    pr_crit("nv vd module loaded\n");
    err = 0;
    goto end;

misc_out:
	misc_deregister(&nv_vd_misc);
clean_block:
    nv_block_finish();
clean_dev:
    nv_dev_cleanup();
end:	
    return err;
}

static int 
nv_vd_exit_cb(int id, void *ptr, 
                     void *data) {
	nv_virtual_device_t *vd = ptr;

	nv_vd_remove(vd);
	return 0;
}

static void __exit nv_vd_exit(void) {
	unsigned long range;

    nv_dev_cleanup();

    range = nv_vd_max ? nv_vd_max << nv_vd_part_shift : 1UL << MINORBITS;

	idr_for_each(&nv_vd_index_idr, &nv_vd_exit_cb, NULL);
	idr_destroy(&nv_vd_index_idr);

	blk_unregister_region(MKDEV(nv_vd_major, 0), range);
	unregister_blkdev(nv_vd_major, "nv_vd");

	misc_deregister(&nv_vd_misc);
    nv_block_finish();

    return;
}

module_init(nv_vd_init);
module_exit(nv_vd_exit);


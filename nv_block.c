#include <linux/string.h>
#include <linux/parser.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/file.h>
#include <linux/module.h>
#include <asm/unaligned.h>
#include "nv_device.h"

/* right now we have 2 devices 
 * drbd1
 * drbd9
 */

nv_device_t *nv_device;

int 
nv_block_init(void) {
    int rc = 0;
    nv_device = nv_device_register(NV_PR_DEV_NAME);

    if(!nv_device) {
        pr_crit("pr deivce registration failed\n");
        goto end;
    }

    /*nv_devices[1] = nv_device_register(NV_PRBACK_DEV_NAME);
    if(nv_devices[1]) {
        pr_crit("pr backup device registration failed\n");
    }*/

end:
    return rc;
}

void
nv_block_finish(void) {
    int rc = 0;
    rc = nv_device_unregister(nv_device);    
    if(!rc) {
        pr_crit("deregistering pr device failed\n");
    }      
    /*rc = nv_device_unregister(nv_devices[1]);
    if(!rc) {
        pr_crit("deregistering pr backup device failed\n");
    } */     

    return;
}

int
nv_block_open(struct inode *inode, 
                    struct file *file) {
    return 0;
}

int 
nv_blck_release(struct inode *inode,
                      struct file *file) {
    return 0;
}

int
nv_merged_block_read(struct scatterlist *sgl,
                           u32 sgl_nents,
                           sector_t start_sector,
                           nv_cmd_t *cmd,
                           int wait_req) {
    int rc = 0;
    sector_t block_lba = 0;

    if(!nv_device) {
        pr_crit("no nv device present\n");
        rc = -EINVAL;
        goto end;
    }

    pr_crit("entering merged block read %d\n", sgl_nents);
    block_lba = start_sector; 

    rc = nv_merged_device_read(nv_device,
                                     sgl, sgl_nents,
                                     block_lba, cmd, wait_req);
    if(rc) {
        pr_crit("merged read is failed\n");
        goto end;
    }

end:

    pr_crit("exiting merged block read\n");
    return rc;       
}

int
nv_merged_block_write(struct scatterlist *sgl,
                            u32 sgl_nents,
                            sector_t start_sector,
                            nv_cmd_t *cmd,
                            int wait_req) {
    int rc = 0;
    sector_t block_lba = 0;

    if(!nv_device) {
        rc = -EINVAL;
        pr_crit("nv device is NULL in write\n");
        goto end;
    }
    
    pr_crit("entering merged block write\n");    
    block_lba = start_sector;

    rc = nv_merged_device_write(nv_device,
                                      sgl, sgl_nents,
                                      block_lba, cmd, wait_req);
    if(rc) {
        pr_crit("merged write is failed\n");
        goto end;
    }
       
end:

    pr_crit("exiting merged block write\n");    
    return rc;       
}

int
nv_block_read(nv_cmd_t *cmd,
                    int wait_req) {
    int rc = 0;
    sector_t block_lba = 0;

    if(!nv_device) {
        pr_crit("no nv device present\n");
        rc = -EINVAL;
        goto end;
    }

    pr_crit("entering merged block read\n");
    block_lba = cmd->rq->bio->bi_iter.bi_sector; 

    rc = nv_device_read(nv_device,
                              block_lba, cmd, wait_req);
    if(rc) {
        pr_crit("merged read is failed\n");
        goto end;
    }

end:

    pr_crit("exiting merged block read\n");
    return rc;       
}

int
nv_block_write(nv_cmd_t *cmd,
                     int wait_req) {
    int rc = 0;
    sector_t block_lba = 0;

    if(!nv_device) {
        rc = -EINVAL;
        pr_crit("nv device is NULL in write\n");
        goto end;
    }
    
    pr_crit("entering merged block write\n");    
    block_lba = cmd->rq->bio->bi_iter.bi_sector;

    rc = nv_device_write(nv_device,
                               block_lba, cmd, wait_req);
    if(rc) {
        pr_crit("merged write is failed\n");
        goto end;
    }
       
end:

    pr_crit("exiting merged block write\n");    
    return rc;       
}

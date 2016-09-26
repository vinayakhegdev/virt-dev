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

void 
convert_nv_dev_err(nv_device_req_status_t *pstatus,
                         int *err) {
    switch((*pstatus)) {
        case NV_DEV_ERR:
            (*err) = -1;
            break;
    
        case NV_DEV_SUCCESS:
            (*err) = 0;
            break;
        
        default:
            (*err) = -1;
            break;
    }

    return;
}          

nv_device_t *
nv_device_register(char *name) {
    nv_device_t *nv_dev = NULL;
    fmode_t mode; 
    struct block_device *bd = NULL;
    struct request_queue *q = NULL;

    nv_dev = kmalloc(sizeof(nv_device_t), GFP_KERNEL);

    if(!nv_dev) {
        pr_crit("failed to register nv device %s\n", name);
        goto end;
    }

    memset(nv_dev->device_path, 0, sizeof(nv_dev->device_path));

    memcpy(nv_dev->device_path, name, strlen(name));

    nv_dev->bio_set = bioset_create(NV_BIO_POOL_SIZE, 
                                                   0); 

    if(!nv_dev->bio_set) {
        pr_crit("failed to allocate bio set\n");
        goto end;
    }

    mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;

    pr_crit("device path %s\n", nv_dev->device_path);

    bd = blkdev_get_by_path(nv_dev->device_path, mode, 
                            nv_dev);


    if(!bd) {
        pr_crit("failed to get the block device path %s\n", name);
        goto out_bioset_free;
    }

    nv_dev->bd = bd;

    /*q = bdev_get_queue(bd);

    nv_dev->dev_attrib.hw_block_size = bdev_logical_block_size(bd);
    nv_dev->dev_attrib.hw_max_sectors = queue_max_hw_sectors(q);
    nv_dev->dev_attrib.hw_queue_depth = q->nr_requests;*/

    goto ret;

    blkdev_put(nv_dev->bd, 
               mode);

out_bioset_free:    
    bioset_free(nv_dev->bio_set);
    nv_dev->bio_set = NULL;
end:
    if(nv_dev) {
        kfree(nv_dev);
        nv_dev = NULL;
    }

ret:
    return nv_dev;
}

int 
nv_device_unregister(nv_device_t *nv_dev) {
    fmode_t mode = 0;
    int rc = 0;

    if(nv_dev) {
        if(nv_dev->bd) {
            blkdev_put(nv_dev->bd,  
                       mode);
            nv_dev->bd = NULL;
        }
        if(nv_dev->bio_set) {
            bioset_free(nv_dev->bio_set);
            nv_dev->bio_set = NULL;
        }
    
        kfree(nv_dev);
        nv_dev = NULL;
    }
    
    return rc;
}

static void 
nv_complete_req(nv_device_req_t *nv_req) {
    
    if(!atomic_dec_and_test(&nv_req->pending)) {
        goto end;
    }

    if(atomic_read(&nv_req->bio_err_cnt)) {
       nv_req->status = NV_DEV_ERR;
    } else {
       nv_req->status = NV_DEV_SUCCESS;
    }

    pr_crit("calling end nv bio\n");
    nv_req->state = NV_DEV_FINISHED;
    if(nv_req->cmd) {
        nv_req->cmd->status = nv_req->status;
        nv_req->cmd->state = NV_DEV_FINISHED;
        if(nv_req->cmd->virtual_io_end) {
            nv_req->cmd->virtual_io_end(nv_req->cmd);
        }
    }

    if(nv_req->waiting) {    
        wake_up(&nv_req->waitq);
    } else {
        if(nv_req) {
            kfree(nv_req);
        }
        nv_req = NULL;
    }       
end:

    pr_crit("returning end nv bio\n");
    return;
}

static void 
nv_bio_done(struct bio *bio, int err) {
    nv_device_req_t *nv_req = bio->bi_private;

    pr_crit("calling nv bio done\n");
    if(!test_bit(BIO_UPTODATE, &bio->bi_flags) && (!err)) {
        err = -EIO;
    }

    if (err != 0) {
        pr_crit("test_bit(BIO_UPTODATE) failed for bio: %p,"
            " err: %d\n", bio, err);
        //smp_mb__after_atomic();
    }

    bio_put(bio);

    nv_complete_req(nv_req);
}

static struct bio *
nv_get_bio(nv_device_t *nv_dev, 
                 nv_device_req_t *nv_req,
                 sector_t lba, u32 sg_num) {

    struct bio *bio = NULL;

    if(sg_num > BIO_MAX_PAGES) {
        sg_num = BIO_MAX_PAGES;
    }

    bio = bio_alloc_bioset(GFP_NOIO, sg_num, 
                           nv_dev->bio_set);
    if(!bio) {
        pr_crit("Unable to allocate memory for bio\n");
        goto end;
    }

    bio->bi_bdev = nv_dev->bd;
    bio->bi_private = nv_req;
    bio->bi_end_io = &nv_bio_done;
    bio->bi_iter.bi_sector = lba;

end:
    return bio;
}

static void 
nv_submit_bios(struct bio_list *list, 
                     int rw) {
    struct blk_plug plug;
    struct bio *bio = NULL;

    blk_start_plug(&plug);
    while((bio = bio_list_pop(list))) {
        pr_crit("submitting the bio\n");
        submit_bio(rw, bio);
    }
    blk_finish_plug(&plug);
}

int
nv_merged_device_read(nv_device_t *nv_device,
                            struct scatterlist *sgl, u32 sgl_nents,
                            sector_t block_lba, nv_cmd_t *cmd,
                            int wait_req) {
    struct bio *bio = NULL; 
    unsigned bio_cnt;
    nv_device_req_t *nv_req = NULL;
    struct bio_list list;
    struct scatterlist *sg;
    u32 sg_num = sgl_nents;
    int i = 0;
    int rw = READ | REQ_SYNC | REQ_FUA;    
    int rc = 0;

    pr_crit("entering merged device read\n");
    nv_req = kmalloc(sizeof(nv_device_req_t), GFP_KERNEL);
    
    if(!nv_req) {
        pr_crit("failed to allcoat nv req structure\n");
        goto end; 
    }

    memset(nv_req, 0, sizeof(nv_device_req_t));

    bio = nv_get_bio(nv_device, nv_req,
                           block_lba, sgl_nents);
     
    if(!bio) {
        pr_crit("bio allcoation failed\n");
        goto free_req;
    }

    bio_list_init(&list);
    bio_list_add(&list, bio);
    bio_cnt = 1;
    atomic_set(&nv_req->pending, 2);
    
    init_waitqueue_head(&nv_req->waitq);
    nv_req->state = NV_DEV_PENDING;
    nv_req->cmd = cmd;
    nv_req->waiting = wait_req;

    struct page *pg1 = NULL;
    pg1 = alloc_page(GFP_KERNEL);
   
    bio_add_page(bio, pg1, 4096, 0);
   /* for_each_sg(sgl, sg, sgl_nents, i) {       
        pr_crit("adding bio \n %d %d", sg->length, sg->offset);
        while(bio_add_page(bio, pg1, sg->length, sg->offset)
                    != sg->length) {
            pr_crit("new bio start\n %d %d", sg->length, sg->offset);
            if(bio_cnt >= NV_MAX_BIO_PER_TASK) {
                nv_submit_bios(&list, rw);
                bio_cnt = 0;
            }

            bio = nv_get_bio(nv_device, 
                                   nv_req,
                                   block_lba, sg_num);
            if(!bio) {
                pr_crit("fail to get the bio\n");       
                goto put_bios;
            }                
            bio_list_add(&list, bio);
            bio_cnt++;

            pr_crit("new bio end\n");
            atomic_inc(&nv_req->pending);
        }

        block_lba += sg->length >> NV_LBA_SHIFT;
        sg_num = sg_num - 1;
    }*/

    nv_submit_bios(&list, rw);
    nv_complete_req(nv_req);

    if(wait_req) {
        wait_event(nv_req->waitq,
                   (nv_req->state == NV_DEV_FINISHED));

        convert_nv_dev_err(&nv_req->status,
                                 &rc);
     
        goto free_req;
    } else {
        goto end;
    }
    
put_bios:
    while((bio = bio_list_pop(&list))) {
        bio_put(bio);
    }
free_req:
    if(nv_req) { 
        kfree(nv_req);
    }
end:

    pr_crit("exiting merged device read\n");
    return rc;
}    

int
nv_merged_device_write(nv_device_t *nv_device,
                            struct scatterlist *sgl, u32 sgl_nents,
                            sector_t block_lba,
                            nv_cmd_t *cmd,
                            int wait_req) {
    struct bio *bio = NULL; 
    struct bio *bio_start = NULL;
    unsigned bio_cnt;
    nv_device_req_t *nv_req = NULL;
    struct bio_list list;
    struct scatterlist *sg;
    u32 sg_num = sgl_nents;
    int i = 0;
    int rw = WRITE_FLUSH_FUA;    
    int rc = 0;

    pr_crit("entering merged device write, sector no %llu\n", block_lba);

    nv_req = kmalloc(sizeof(nv_device_req_t), GFP_KERNEL);
    
    if(!nv_req) {
        pr_crit("failed to allcoat nv req structure\n");
        goto end; 
    }

    bio = nv_get_bio(nv_device, nv_req,
                           block_lba, sgl_nents);
     
    if(!bio) {
        pr_crit("bio allcoation failed\n");
        goto free_req;
    }

    bio_start = bio;
    bio_list_init(&list);
    bio_list_add(&list, bio);
    bio_cnt = 1;
    atomic_set(&nv_req->pending, 2);
    
    init_waitqueue_head(&nv_req->waitq);
    nv_req->state = NV_DEV_PENDING;
    nv_req->cmd = cmd;
    nv_req->waiting = wait_req;

    for_each_sg(sgl, sg, sgl_nents, i) {       
        while(bio_add_page(bio, sg_page(sg), sg->length, sg->offset)
                    != sg->length) {
            if(bio_cnt >= NV_MAX_BIO_PER_TASK) {
                nv_submit_bios(&list, rw);
                bio_cnt = 0;
            }

            bio = nv_get_bio(nv_device, 
                                   nv_req,
                                   block_lba, sg_num);
            if(!bio) {
                pr_crit("fail to get the bio\n");       
                goto put_bios;
            }                
            bio_list_add(&list, bio);
            bio_cnt++;
            atomic_inc(&nv_req->pending);
        }

        block_lba += sg->length >> NV_LBA_SHIFT;
        sg_num = sg_num - 1;
    }

    nv_submit_bios(&list, rw);
    nv_complete_req(nv_req);

    if(wait_req) {
        wait_event(nv_req->waitq,
                   (nv_req->state == NV_DEV_FINISHED));
        convert_nv_dev_err(&nv_req->status,
                                 &rc);
        goto free_req;
    } else {
        goto end;
    }

put_bios:
    while((bio = bio_list_pop(&list))) {
        bio_put(bio);
    }
free_req:
    if(nv_req) { 
        kfree(nv_req);
    }
end:

    pr_crit("exiting merged device write, sector no %llu\n", block_lba);
    return rc;
}    

int
nv_device_read(nv_device_t *nv_device,
                     sector_t block_lba, nv_cmd_t *cmd,
                     int wait_req) {
    struct bio *bio = NULL; 
    unsigned bio_cnt;
    nv_device_req_t *nv_req = NULL;
    struct bio_list list;
    int i = 0;
    int rw = READ | REQ_SYNC | REQ_FUA;    
    int rc = 0;
    struct bio *virt_bio = NULL;
    struct request *virt_rq = NULL;
    struct bio_vec bvec;
    struct req_iterator iter;

    pr_crit("entering device read\n");
    
    virt_rq = cmd->rq;
    virt_bio = virt_rq->bio;
    
    nv_req = kmalloc(sizeof(nv_device_req_t), GFP_KERNEL);
    
    if(!nv_req) {
        pr_crit("failed to allcoat nv req structure\n");
        goto end; 
    }

    memset(nv_req, 0, sizeof(nv_device_req_t));

    bio = nv_get_bio(nv_device, nv_req,
                           block_lba, virt_bio->bi_vcnt);
     
    if(!bio) {
        pr_crit("bio allcoation failed\n");
        goto free_req;
    }

    bio_list_init(&list);
    bio_list_add(&list, bio);
    bio_cnt = 1;
    atomic_set(&nv_req->pending, 2);
    
    init_waitqueue_head(&nv_req->waitq);
    nv_req->state = NV_DEV_PENDING;
    nv_req->cmd = cmd;
    nv_req->waiting = wait_req;

    rq_for_each_segment(bvec, virt_rq, iter) { 
        /* handle error */
        bio_add_page(bio, bvec.bv_page, bvec.bv_len,
                     bvec.bv_offset);
    }

    nv_submit_bios(&list, rw);
    nv_complete_req(nv_req);

    if(wait_req) {
        wait_event(nv_req->waitq,
                   (nv_req->state == NV_DEV_FINISHED));

        convert_nv_dev_err(&nv_req->status,
                                 &rc);
     
        goto free_req;
    } else {
        goto end;
    }
    
put_bios:
    while((bio = bio_list_pop(&list))) {
        bio_put(bio);
    }
free_req:
    if(nv_req) { 
        kfree(nv_req);
    }
end:

    pr_crit("exiting merged device read\n");
    return rc;
}    

int
nv_device_write(nv_device_t *nv_device,
                      sector_t block_lba,
                      nv_cmd_t *cmd,
                      int wait_req) {
    struct bio *bio = NULL; 
    struct bio *bio_start = NULL;
    unsigned bio_cnt;
    nv_device_req_t *nv_req = NULL;
    struct bio_list list;
    int rw = WRITE_FLUSH_FUA;    
    int rc = 0;
    struct bio *virt_bio = NULL;
    struct request *virt_rq = NULL;
    struct bio_vec bvec;
    struct req_iterator iter;
    pr_crit("entering merged device write, sector no %llu\n", block_lba);

    virt_rq = cmd->rq;
    virt_bio = virt_rq->bio;
    
    nv_req = kmalloc(sizeof(nv_device_req_t), GFP_KERNEL);
    
    if(!nv_req) {
        pr_crit("failed to allcoat nv req structure\n");
        goto end; 
    }

    bio = nv_get_bio(nv_device, nv_req,
                           block_lba, virt_bio->bi_vcnt);
     
    if(!bio) {
        pr_crit("bio allcoation failed\n");
        goto free_req;
    }

    bio_start = bio;
    bio_list_init(&list);
    bio_list_add(&list, bio);
    bio_cnt = 1;
    atomic_set(&nv_req->pending, 2);
    
    init_waitqueue_head(&nv_req->waitq);
    nv_req->state = NV_DEV_PENDING;
    nv_req->cmd = cmd;
    nv_req->waiting = wait_req;

    rq_for_each_segment(bvec, virt_rq, iter) { 
        /* handle error */
        bio_add_page(bio, bvec.bv_page, bvec.bv_len,
                     bvec.bv_offset);
    }

    nv_submit_bios(&list, rw);
    nv_complete_req(nv_req);

    if(wait_req) {
        wait_event(nv_req->waitq,
                   (nv_req->state == NV_DEV_FINISHED));
        convert_nv_dev_err(&nv_req->status,
                                 &rc);
        goto free_req;
    } else {
        goto end;
    }

put_bios:
    while((bio = bio_list_pop(&list))) {
        bio_put(bio);
    }
free_req:
    if(nv_req) { 
        kfree(nv_req);
    }
end:

    pr_crit("exiting merged device write, sector no %llu\n", block_lba);
    return rc;
}    










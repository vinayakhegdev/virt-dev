#ifndef _FS_NV_DEVICE_H
#define _FS_NV_DEVICE_H

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/poll.h>
#include <linux/splice.h>
#include <linux/workqueue.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/scatterlist.h>

#define MAX_NV_DEVICE_NAME 256
#define NV_MAX_BIO_PER_TASK	 32	/* max # of bios to submit at a time */
#define NV_BIO_POOL_SIZE	128
#define NV_LBA_SHIFT 9
#define NV_PR_DEV_NAME "/dev/sdb"
#define NV_PRBACK_DEV_NAME "/dev/drbd9"
#define SG_MAX          32
#define NV_CTL_ADD 1
#define NV_CTL_REMOVE 2
#define NV_CTL_GET_FREE 3 
#define CONFIG_VD_DEV_NV_MIN_COUNT 16

#define NV_CTRL_MINOR MISC_DYNAMIC_MINOR

enum {
    vd_unbound,
    vd_bound,
};

typedef struct nv_virtual_device {
	int vd_number;
	int vd_refcnt;
	struct file *vd_backing_file;
	struct block_device *vd_device;
	unsigned vd_blocksize;
	void *key_data; 
	gfp_t old_gfp_mask;
	spinlock_t vd_lock;
	int	vd_state;
	struct mutex vd_ctl_mutex;
	struct request_queue *vd_queue;
	struct blk_mq_tag_set tag_set;
	struct gendisk *vd_disk;
} nv_virtual_device_t;

typedef struct nv_device_attr__ {
    int block_size;
    int hw_block_size;
    int hw_max_sectors;
    int hw_queue_depth;
    int is_nonrot;
} nv_device_attr_t;

typedef struct nv_device__ {
    char device_path[MAX_NV_DEVICE_NAME];
    nv_device_attr_t dev_attrib;
    struct bio_set  *bio_set;
    struct block_device *bd;
} nv_device_t;

typedef enum nv_device_req_state__ {
    NV_DEV_PENDING,
    NV_DEV_FINISHED,
} nv_device_req_state_t;

typedef enum nv_device_req_status__ {
    NV_DEV_SUCCESS,
    NV_DEV_ERR,
} nv_device_req_status_t;

typedef struct nv_cmd__ {
	struct request *rq;
    void (*virtual_io_end)(void *cmd);
    nv_device_req_status_t status; 
    nv_device_req_state_t state;
} nv_cmd_t;

typedef struct nv_device_req__ {
    atomic_t pending;
    atomic_t bio_err_cnt;
    wait_queue_head_t waitq;
    nv_device_req_state_t state;
    nv_device_req_status_t status;
    nv_cmd_t *cmd;
    int waiting;
} nv_device_req_t;

int
nv_merged_block_read(struct scatterlist *sgl,
                           u32 sgl_nents,
                           sector_t start_sector,
                           nv_cmd_t *cmd,
                           int wait_req);

int
nv_merged_block_write(struct scatterlist *sgl,
                            u32 sgl_nents,
                            sector_t start_sector,
                            nv_cmd_t *cmd,
                            int wait_req);
nv_device_t *
nv_device_register(char *name);

int 
nv_device_unregister(nv_device_t *nv_dev);

int
nv_merged_device_read(nv_device_t *nv_device,
                            struct scatterlist *sgl, u32 sgl_nents,
                            sector_t block_lba, nv_cmd_t *cmd,
                            int wait_req);

int
nv_merged_device_write(nv_device_t *nv_device,
                            struct scatterlist *sgl, u32 sgl_nents,
                            sector_t block_lba,
                            nv_cmd_t *cmd,
                            int wait_req);
int nv_block_init(void);
void nv_block_finish(void);

int
nv_block_read(nv_cmd_t *cmd,
                    int wait_req);
int
nv_block_write(nv_cmd_t *cmd,
                     int wait_req);

int
nv_device_read(nv_device_t *nv_device,
                     sector_t block_lba, nv_cmd_t *cmd,
                     int wait_req);
int
nv_device_write(nv_device_t *nv_device,
                      sector_t block_lba,
                      nv_cmd_t *cmd,
                      int wait_req);
#endif

#ifndef _FS_NV_INTERNAL_H
#define _FS_NV_INTERNAL_H

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
#include "nv_i.h"

#define NV_DEFAULT_BLKSIZE 512

#define NV_COMM_MINOR MISC_DYNAMIC_MINOR
#define NV_DM_COMM_MINOR MISC_DYNAMIC_MINOR
#define NV_MEM_BUFF_MINOR MISC_DYNAMIC_MINOR


typedef struct nv_mem_buff__ {
    char name[NV_MEM_BUFF_NAME_LEN + 1];
    struct vm_area_struct *(vm_area[NV_MEM_BUFF_MAX_MMAPS]);
    struct file *file;
    unsigned char *buf;
    unsigned long size;
    int unit_size;
    int total_chunks;
    rwlock_t entry_lock;
    nv_mem_chunk_buff_t *pending_list;
    nv_mem_chunk_buff_t *free_list;
    nv_mem_chunk_buff_t *processing_list;
    struct nv_mem_buff__ *next;
    struct nv_mem_buff__ *prev;
} nv_mem_buff_t;

typedef struct nv_conn__ {
    spinlock_t lock;
    int req_present;
    wait_queue_head_t waitq;
} nv_conn_t;

int
nv_dev_init(void);

void
nv_dev_cleanup(void);

#endif

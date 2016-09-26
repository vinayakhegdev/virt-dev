#ifndef _FS_NV_MEM_H
#define _FS_NV_MEM_H

#include "nv_i.h"
#include "nv_internal.h"
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
#include <linux/workqueue.h>

void * 
nv_vmalloc(unsigned long size);

void 
nv_vfree(void *mem, 
               unsigned long size);

int 
nv_vmmap(nv_mem_buff_t *mem_buff,
               struct vm_area_struct *vma);

void
nv_print_vma(struct vm_area_struct *area);

void 
nv_mem_buff_list_add(nv_mem_buff_t *mem_buff);

void 
nv_mem_buff_list_remove(nv_mem_buff_t *mem_buff);

int 
nv_mem_buff_allocate(const char *name, 
                           nv_mem_buff_t **mem_buff);

void 
nv_mem_buff_deallocate(nv_mem_buff_t *mem_buff);

nv_mem_buff_t * 
nv_mem_buff_list_lookup_name(const char *name,
                                   int priority);

nv_mem_buff_t * 
nv_mem_buff_list_lookup_buf(void *buf);

int 
nv_shared_mem_allocate(nv_mem_buff_request_t *req,
                             nv_mem_buff_t **addr); 

void
nv_mem_buff_release_all(void);

int 
nv_shared_mem_deallocate(void *addrm, int force);

nv_mem_buff_t * 
nv_mem_buff_list_lookup_vma(struct vm_area_struct *area);

nv_mem_buff_t * 
nv_mem_buff_list_remove_vma(struct vm_area_struct *area);

int 
nv_mem_buff_list_add_vma(nv_mem_buff_t *mem_buff, 
                               struct vm_area_struct *area);

nv_mem_buff_t * 
nv_mem_buff_lookup_file(struct file *file);

int 
nv_dev_mem_buff_mmap(struct file *file, 
                   struct vm_area_struct *vma);

loff_t  
nv_dev_mem_buff_llseek(struct file *file,
                     loff_t offset, int origin);

long 
nv_dev_mem_buff_ioctl(struct file *file, 
                    unsigned int cmd, unsigned long arg);

int
nv_dev_mem_buff_open(struct inode *inode, 
                           struct file *file);

int 
nv_dev_mem_buff_close(struct inode *inode, 
                            struct file *file);

void 
nv_mem_buff_open(struct vm_area_struct * area);

void 
nv_mem_buff_close(struct vm_area_struct * area);

void 
nv_mem_buff_unmap(struct vm_area_struct *area, 
                                unsigned long a1, 
                                size_t a2);

nv_mem_chunk_buff_t *
nv_dequeue(nv_mem_buff_t *mem_buff,
                 nv_mem_chunk_buff_t **head);

void
nv_enqueue(nv_mem_buff_t *mem_buff,
                 nv_mem_chunk_buff_t **head,
                 nv_mem_chunk_buff_t *elem);

void 
nv_chunk_list_add(nv_mem_buff_t *mem_buff,
                        nv_mem_chunk_buff_t **head,
                        unsigned long page_number,
                        unsigned long index, int lock);

void 
nv_chunk_list_remove(nv_mem_buff_t *mem_buff,
                           nv_mem_chunk_buff_t *elem,
                           nv_mem_chunk_buff_t **head,
                           int lock);

nv_mem_chunk_buff_t *
nv_chunk_mem_get(nv_mem_buff_t *mem_buff,
                       nv_mem_chunk_buff_t **head);

void
nv_chunk_mem_put(nv_mem_buff_t *mem_buff,
                       nv_mem_chunk_buff_t *elem,
                       nv_mem_chunk_buff_t **head);

void
nv_chunk_mem_remove(nv_mem_buff_t *mem_buff,
                           nv_mem_chunk_buff_t *elem,
                           nv_mem_chunk_buff_t **head);

void 
nv_get_req(nv_conn_t *nv_conn,
                 nv_req_t **req,
                 nv_mem_chunk_buff_t **req_chunk_buff);

void 
nv_get_resp(nv_conn_t *nv_conn,
                  nv_resp_t **resp,
                  nv_mem_chunk_buff_t **resp_chunk_buff);

void 
nv_get_data(nv_conn_t *nv_conn,
                  char **data,
                  nv_mem_chunk_buff_t **data_chunk_buff);

#endif       

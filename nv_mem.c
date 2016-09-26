#include "nv_i.h"
#include "nv_internal.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/uio.h>
#include <linux/miscdevice.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/pipe_fs_i.h>
#include <linux/swap.h>
#include <linux/splice.h>
#include <linux/aio.h>

rwlock_t nv_mem_buff_list_rwlock;
nv_mem_buff_t *nv_mem_buff_list = NULL;
/* 0 - request
 * 1 - response
 * 2 - data
 */

nv_mem_buff_t *mem_buff[3];
nv_conn_t *nv_conn;
extern int triggered_signal;

void * 
nv_vmalloc(unsigned long size) {
	void * mem;
	unsigned long adr;
    struct page *page = NULL;

	mem = vmalloc(size);
	if(mem) {
        memset(mem, 0, size); 
	    adr = (unsigned long) mem;
		while(size > 0) {
	        page = vmalloc_to_page((void *) adr);
			//mem_map_reserve(page);
            set_bit(PG_reserved, &((page)->flags));
			adr += PAGE_SIZE;
			size -= PAGE_SIZE;
		}
	}

	return mem;
}

void 
nv_vfree(void *mem, 
           unsigned long size) {
    unsigned long adr;
    struct page *page = NULL;

	if(mem) {
	    adr = (unsigned long) mem;
		while(size > 0) {
            page = vmalloc_to_page((void *) adr);
            //mem_map_unreserve(virt_to_page(adr));
            clear_bit(PG_reserved, &((page)->flags));
			adr += PAGE_SIZE;
			size -= PAGE_SIZE;
		}
		vfree(mem);
	}
}

/* this function will map (fragment of) 
 * vmalloc'ed memory area to user space 
 */

int 
nv_vmmap(nv_mem_buff_t *mem_buff,
               struct vm_area_struct *vma) {
   	unsigned long pos, size, start = vma->vm_start;
	//unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
    unsigned long offset = 0;
    int ret = 0;	
    void *mem = (void *) mem_buff->buf;
    unsigned int memsize = mem_buff->size;

    if(offset < 0) {
        ret = -EFAULT;
        goto end;
    }     
	
    size = vma->vm_end - vma->vm_start;
	
    if(size + offset > memsize) {
        ret = -EFAULT;
        goto end;
	}

    pos = (unsigned long) mem + offset;
	
    if(pos % PAGE_SIZE || start % PAGE_SIZE || size % PAGE_SIZE) {
        ret = -EFAULT;
	    goto end;
    }        
	
    while(size > 0) {
		if(remap_pfn_range(vma, start, 
                           vmalloc_to_pfn((void *)pos), PAGE_SIZE, 
		    	           vma->vm_page_prot)) {
	        /* fixme: do cleanup of previous mapped page 
             */
            pr_crit("nv_vmmap failed: vm_start=0x%lx, vm_end=0x%lx, "
                      "size=0x%lx, pos=0x%lx; \n",
                      vma->vm_start, vma->vm_end, size,
                      pos);
			ret = -EFAULT;
            goto end;
		}
		pos += PAGE_SIZE;
		start += PAGE_SIZE;
		size -= PAGE_SIZE;
    }

end:
	return ret;
}

void
nv_print_vma(struct vm_area_struct *area) {
    pr_crit("area = %p ", area);
    if(!area) {
        pr_crit("vm area is NULL");
        return;
    }

    pr_crit("start=%lx end=%lx", 
              area->vm_start, area->vm_end);
    return;
}

void 
nv_mem_buff_list_add(nv_mem_buff_t *mem_buff) {
    mem_buff->prev = NULL;

    write_lock(&nv_mem_buff_list_rwlock);

    mem_buff->next = nv_mem_buff_list;
    
    if(mem_buff->next) {
        (mem_buff->next)->prev = mem_buff;
    }

    nv_mem_buff_list = mem_buff;

    write_unlock(&nv_mem_buff_list_rwlock);

    return;
}

void 
nv_mem_buff_list_remove(nv_mem_buff_t *mem_buff, int lock) {
    nv_mem_buff_t *next; 
    nv_mem_buff_t *prev;

    if(lock) {
        write_lock(&nv_mem_buff_list_rwlock);
    }

    next = mem_buff->next;
    prev = mem_buff->prev;

    if(next) {
        next->prev = prev;
    }

    if(prev) {
        prev->next = next;
    } else {
        nv_mem_buff_list = next;
    }

    if(lock) {
        write_unlock(&nv_mem_buff_list_rwlock);
    }

    mem_buff->next = NULL;
    mem_buff->prev = NULL;

    return;
}

int 
nv_mem_buff_allocate(const char *name, 
                           nv_mem_buff_t **mem_buff) {
    int ret = 0;
    (*mem_buff) = kmalloc(sizeof(nv_mem_buff_t), GFP_KERNEL);
    if(!(*mem_buff)) {
        pr_crit("memory alloacation failed in nv memory "
                  "buffer creation");    
        ret = -ENOMEM;
        goto end;
    }

    memset(*mem_buff, 0, sizeof(nv_mem_buff_t));

    rwlock_init(&(*mem_buff)->entry_lock);
    strncpy((*mem_buff)->name, name, NV_MEM_BUFF_NAME_LEN);
    (*mem_buff)->name[NV_MEM_BUFF_NAME_LEN - 1] = 0;
    
    nv_mem_buff_list_add(*mem_buff);

end:    
    return ret;
}

void 
nv_mem_buff_deallocate(nv_mem_buff_t *mem_buff, int lock) {
    nv_mem_buff_list_remove(mem_buff, 0);
    if(mem_buff) {    
        kfree(mem_buff);
        mem_buff = NULL;
    }
}

nv_mem_buff_t * 
nv_mem_buff_list_lookup_name(const char *name,
                               int priority) {
    nv_mem_buff_t *mem_buff;

    read_lock(&nv_mem_buff_list_rwlock);

    mem_buff = nv_mem_buff_list;

    while(mem_buff != NULL) {
        if(!strncmp(mem_buff->name, name, 
                    NV_MEM_BUFF_NAME_LEN)) {
            break;
        }
        mem_buff = mem_buff->next;
    }

    read_unlock(&nv_mem_buff_list_rwlock);

    return mem_buff;
}

nv_mem_buff_t * 
nv_mem_buff_list_lookup_buf(void *buf) {
    nv_mem_buff_t *mem_buff;

    read_lock(&nv_mem_buff_list_rwlock);

    mem_buff = nv_mem_buff_list;
    
    while(mem_buff != NULL) {
        if(mem_buff->buf == buf) {
            break;
        }
        mem_buff = mem_buff->next;
    }

    read_unlock(&nv_mem_buff_list_rwlock);

    return mem_buff;
}

nv_mem_chunk_buff_t *
nv_dequeue(nv_mem_buff_t *mem_buff,
                 nv_mem_chunk_buff_t **head) {
    nv_mem_chunk_buff_t *entry = NULL;

    entry = (*head);

    if((*head) != NULL) {
        (*head) = (*head)->next;
        if((*head)) {
            (*head)->prev = NULL;
        }
    } else {
        (*head) = NULL;
    }      

    if(entry) {
        entry->next = NULL;
        entry->prev = NULL;
    }

    return entry;
}

void
nv_enqueue(nv_mem_buff_t *mem_buff,
                 nv_mem_chunk_buff_t **head,
                 nv_mem_chunk_buff_t *elem) {
    elem->prev = NULL;
    elem->next = NULL;

    elem->next = (*head);
    (*head) = elem;
    return;
}

void 
nv_chunk_list_add(nv_mem_buff_t *mem_buff,
                        nv_mem_chunk_buff_t **head,
                        unsigned long offset, 
                        int lock) {
    int ret = 0;
    nv_mem_chunk_buff_t *elem = NULL;

    elem = kmalloc(sizeof(nv_mem_chunk_buff_t), GFP_KERNEL);
    if(!elem) {
        pr_crit("memory alloacation failed in nv memory "
                  "chunk list creation");    
        ret = -ENOMEM;
        goto end;
    }

    if(lock) {
        write_lock(&mem_buff->entry_lock);
    }

    elem->chunk_size = mem_buff->unit_size;
    elem->offset = offset;
    elem->page_size = PAGE_SIZE;

    pr_crit("enqueuing the elem name %s chunk_size %d offset %lu\n",
             mem_buff->name, elem->chunk_size, elem->offset);
    nv_enqueue(mem_buff, &mem_buff->free_list, elem);

    if(lock) {
        write_unlock(&mem_buff->entry_lock);
    }
end:
    return;
}

void 
nv_chunk_list_remove(nv_mem_buff_t *mem_buff,
                           nv_mem_chunk_buff_t *elem,
                           nv_mem_chunk_buff_t **head,
                           int lock) {
    nv_mem_chunk_buff_t *next; 
    nv_mem_chunk_buff_t *prev;

    if(lock) {
        write_lock(&mem_buff->entry_lock);
    }

    next = elem->next;
    prev = elem->prev;

    if(next) {
        next->prev = prev;
    }

    if(prev) {
        prev->next = next;
    } 
   
    if((*head) == elem) {
        (*head) = next;
    }

    if(lock) { 
        write_unlock(&mem_buff->entry_lock);
    }
    elem->next = NULL;
    elem->prev = NULL;

    return;
}

nv_mem_chunk_buff_t *
nv_chunk_mem_get(nv_mem_buff_t *mem_buff,
                       nv_mem_chunk_buff_t **head) {
    nv_mem_chunk_buff_t *chunk_mem = NULL;
    write_lock(&mem_buff->entry_lock);
    
    chunk_mem = nv_dequeue(mem_buff, head);

    if(!chunk_mem) {
        //pr_crit("dequeuing from the free list failed");
    }

    write_unlock(&mem_buff->entry_lock);

    return chunk_mem;
}

void
nv_chunk_mem_put(nv_mem_buff_t *mem_buff,
                       nv_mem_chunk_buff_t *elem,
                       nv_mem_chunk_buff_t **head) {
    write_lock(&mem_buff->entry_lock);
    nv_enqueue(mem_buff, head, elem);
    write_unlock(&mem_buff->entry_lock);
}

void
nv_chunk_mem_remove(nv_mem_buff_t *mem_buff,
                           nv_mem_chunk_buff_t *elem,
                           nv_mem_chunk_buff_t **head) {
    write_lock(&mem_buff->entry_lock);
    nv_chunk_list_remove(mem_buff, elem, head, 0);
    write_unlock(&mem_buff->entry_lock);
}

void 
nv_get_req(nv_conn_t *nv_conn,
                 nv_req_t **req,
                 nv_mem_chunk_buff_t **req_chunk_buff) {
    (*req_chunk_buff) = nv_chunk_mem_get(mem_buff[0],
                                               &mem_buff[0]->free_list);
    
    if(!(*req_chunk_buff)) {
        pr_crit("nv request memory get is failed");
        goto end;
    }

    (*req) = (nv_req_t *)
                        (mem_buff[0]->buf + 
                            (*req_chunk_buff)->offset);
end:
    return;
}

void 
nv_get_resp(nv_conn_t *nv_conn,
                  nv_resp_t **resp,
                  nv_mem_chunk_buff_t **resp_chunk_buff) {
    (*resp_chunk_buff) = nv_chunk_mem_get(mem_buff[1],
                                                &mem_buff[1]->free_list);
    
    if(!(*resp_chunk_buff)) {
        pr_crit("nv request memory get is failed");
        goto end;
    }

    (*resp) = (nv_resp_t *)
                        (mem_buff[1]->buf + 
                           (*resp_chunk_buff)->offset);
end:
    return;
}

void 
nv_get_data(nv_conn_t *nv_conn,
                  char **data,
                  nv_mem_chunk_buff_t **data_chunk_buff) {
    (*data_chunk_buff) = nv_chunk_mem_get(mem_buff[2],
                                                &mem_buff[2]->free_list);
    
    if(!(*data_chunk_buff)) {
        pr_crit("nv request data memory get is failed");
        goto end;
    }

    (*data) = (char *) (mem_buff[2]->buf + 
                            (*data_chunk_buff)->offset);
end:
    return;
}

int 
nv_shared_mem_allocate(nv_mem_buff_request_t *req,
                             nv_mem_buff_t **addr) { 
    nv_mem_buff_t *mem_buf = NULL;
    int priority = 0;
    int ret = 0;
    char *name = NULL;
    unsigned int size = 0;
    unsigned int unit_size = 0;
    int total_chunks = 0;
    unsigned long offset = 0;

    name = req->name;
    size = req->size;
    unit_size = req->unit_size;

    mem_buf = nv_mem_buff_list_lookup_name(name, priority);
    
    if(mem_buf) {
        if(size > mem_buf->size) {
            ret = -EIO; 
            goto end;
        }
    } else {
        if(size == 0) {
            ret = -EIO;
            goto end;
        }

        ret = nv_mem_buff_allocate(name, &mem_buf);
        if(ret) {
            goto end;
        }

        size = ((size - 1) & PAGE_MASK) + PAGE_SIZE;
        mem_buf->buf = (char *) nv_vmalloc(size); 
        /*this might sleep */
        
        /* vmalloc might schedule other processes -
         * preemption point */

        if(!mem_buf->buf){
            nv_mem_buff_deallocate(mem_buf, 1);
            ret = -ENOMEM;
            goto end;
        }
        
        pr_crit("allocated %d bytes at %p for %p(%.32s)\n", size,
                   mem_buf->buf, mem_buf, mem_buf->name);
        mem_buf->size = size;
        mem_buf->unit_size = unit_size;
        
        /* now construct the chunks */

        total_chunks = 0;
        offset = 0;
        total_chunks = size / unit_size;
        mem_buf->total_chunks = total_chunks;

        while(total_chunks > 0) {
            nv_chunk_list_add(mem_buf, &mem_buf->free_list,
                                    offset, 1);            

            total_chunks = total_chunks - 1;
            offset = offset + unit_size;
        }
        
        pr_crit("tatal chunks %d\n", mem_buf->total_chunks);
        
        if(!strncmp(mem_buf->name, REQUEST_BUFF_NAME,
                    NV_MEM_BUFF_NAME_LEN)) {
            mem_buff[0] = mem_buf;
        }
        if(!strncmp(mem_buf->name, RESPONSE_BUFF_NAME,
                    NV_MEM_BUFF_NAME_LEN)) {
            mem_buff[1] = mem_buf;
        }
        if(!strncmp(mem_buf->name, DATA_BUFF_NAME,
                    NV_MEM_BUFF_NAME_LEN)) {
            mem_buff[2] = mem_buf;
        }     
    }

    if(*addr) {
        (*addr) = mem_buf;
    }

end:    
    return ret;
}

int 
nv_shared_mem_deallocate(void *addr, int force) {  
    nv_mem_buff_t *mem_buff;
    int ret = 0;

	mem_buff = nv_mem_buff_list_lookup_buf(addr);
	
    if(!mem_buff) {
        ret = -EINVAL;
        goto end;
    }	
    
    if(force) {
        nv_vfree(mem_buff->buf, mem_buff->size);
        nv_mem_buff_deallocate(mem_buff, 1);
    }

end:	
    return ret;
}

void
nv_mem_buff_release_all(void) {
    nv_mem_buff_t *mem_buff = NULL;
    nv_mem_buff_t *tmp_buff = NULL;

    write_lock(&nv_mem_buff_list_rwlock);

    mem_buff = nv_mem_buff_list;


    while(mem_buff != NULL) {
        pr_crit("freeing");
        tmp_buff = mem_buff;
        mem_buff = mem_buff->next;
        nv_vfree(tmp_buff->buf, tmp_buff->size);
        nv_mem_buff_deallocate(tmp_buff, 0);
    }

    write_unlock(&nv_mem_buff_list_rwlock);

    return;
}

nv_mem_buff_t * 
nv_mem_buff_list_lookup_vma(struct vm_area_struct *area) {
	nv_mem_buff_t *mem_buff = (nv_mem_buff_t *) (area->vm_private_data);
    return mem_buff;
}

nv_mem_buff_t * 
nv_mem_buff_list_remove_vma(struct vm_area_struct *area) {
	int i;
	nv_mem_buff_t *mem_buff;

	read_lock(&nv_mem_buff_list_rwlock);

	mem_buff = nv_mem_buff_list_lookup_vma(area);

	for(i = 0; i < NV_MEM_BUFF_MAX_MMAPS; i++) {
		if(mem_buff->vm_area[i] == area) {
			goto found;
        }
    }

	read_unlock(&nv_mem_buff_list_rwlock);
	return NULL;

found:
	mem_buff->vm_area[i] = NULL;
	read_unlock(&nv_mem_buff_list_rwlock);
	return mem_buff;
}

int 
nv_mem_buff_list_add_vma(nv_mem_buff_t *mem_buff, 
                           struct vm_area_struct *area) {
	int i;
	for(i = 0; i < NV_MEM_BUFF_MAX_MMAPS; i++) {
		if(mem_buff->vm_area[i] == NULL) {
			area->vm_private_data = (void *) mem_buff;
			mem_buff->vm_area[i] = area;
			break;
		}
    }

	if(i == NV_MEM_BUFF_MAX_MMAPS) { 
		return -ENOMEM;
    } else {
	    return 0;
    }
}
		
nv_mem_buff_t * 
nv_mem_buff_lookup_file(struct file *file) {
    nv_mem_buff_t *mem_buff = NULL;

	mem_buff = (nv_mem_buff_t *) (file->private_data);
	if(mem_buff == NULL) {
        pr_crit("mem_buff_list_lookup_file: NULL private on %p\n",
                  file);
    } else {
        mem_buff = nv_mem_buff_list_lookup_buf(mem_buff->buf); 
    }
    return mem_buff;
}

loff_t  
nv_dev_mem_buff_llseek(struct file *file,
                     loff_t offset, int origin) {
    nv_mem_buff_t *mem_buff;
    int ret = 0;

	mem_buff = nv_mem_buff_lookup_file(file);
	
    switch(origin) {
	    case 0:	
		    break;
	    case 1:
	    	offset += file->f_pos;
		    break;
	    case 2:
		    offset += mem_buff->size;
		    break;
	    default:
            ret = -EINVAL;
            goto end;
	}
	
    if(offset >= 0 && offset < mem_buff->size){
		file->f_pos = offset;   
        goto end;
	} else {
		ret = -EINVAL;
	}
end:
    return ret;
}

void 
handle_process_restart(void) {
    nv_mem_chunk_buff_t *req_proc_list = NULL;
    nv_mem_chunk_buff_t *req_chunk_buff = NULL;        
    nv_req_t *shared_req = NULL;

    req_proc_list = mem_buff[0]->processing_list;
    triggered_signal = 0;
    pr_crit("calling restart \n");
    while(req_proc_list != NULL) {
        write_lock(&mem_buff[0]->entry_lock); 
        req_chunk_buff = req_proc_list;
        req_proc_list = req_proc_list->next;

        shared_req = (nv_req_t *)
                        (mem_buff[0]->buf +
                               req_chunk_buff->offset);
        
        shared_req->state = NV_REQ_ABORT;
        pr_crit("waking up %p\n", (wait_queue_head_t *) shared_req->waitq); 
        if(req_chunk_buff->wake_up_done == 0) {
            req_chunk_buff->wake_up_done = 1;
            wake_up((wait_queue_head_t *) shared_req->waitq);
        }
        write_unlock(&mem_buff[0]->entry_lock);
    }

    return;
}

long 
nv_dev_mem_buff_ioctl(struct file *file, 
                            unsigned int cmd, 
                            unsigned long arg) {
	nv_mem_buff_request_t req;
    nv_mem_buff_t *mem_buff;
	long ret = 0;

    if(cmd > IOCTL_NV_MEM_BUFF_LAST) {
        ret = -EINVAL;
        goto end;
    }

	if(copy_from_user(&req, (void*) arg, sizeof(req))) {
        ret = -EFAULT;
        goto end; 
    }	

    switch(cmd) {
	    case IOCTL_NV_MEM_BUFF_ALLOCATE:
		    ret = nv_shared_mem_allocate(&req, 
                                               &mem_buff);
		    if(ret < 0) {
                goto end;
            }
		    
            file->private_data = (void*) mem_buff;
		    ret = mem_buff->size;
            goto end;
        case IOCTL_NV_MEM_BUFF_DEALLOCATE:
		    mem_buff = nv_mem_buff_list_lookup_name(req.name, 0);
		    if(!mem_buff) {
                ret = -EINVAL;
                goto end;
            }		
            
            nv_shared_mem_deallocate(mem_buff, 1);	
            goto end;	
	    case IOCTL_NV_MEM_BUFF_START:
            /* process restart case */
            if(req.flags & NV_START) {
                handle_process_restart();
            } else if(req.flags & NV_KILL) {
                pr_crit("got killing signal\n");
                triggered_signal = 1;
            }

            goto end; 

        default:
		    ret = -EINVAL;
            goto end;
	}
end:
	return ret;
}

int
nv_dev_mem_buff_open(struct inode *inode, 
                           struct file *file) {
    int ret = 0;
    return ret;
}

int 
nv_dev_mem_buff_close(struct inode *inode, 
                            struct file *file) {
    int ret = 0;
    return ret;
}

void 
nv_mem_buff_open(struct vm_area_struct * area) {
	pr_crit("nv open vma");
	nv_print_vma(area);
	nv_mem_buff_list_add_vma(nv_mem_buff_list_lookup_vma(area), 
                                   area);
	return;
}

void 
nv_mem_buff_close(struct vm_area_struct * area) {
	nv_mem_buff_t *mem_buff = NULL;

	pr_crit("nv closing vma");
	nv_print_vma(area);
	
    if(area) {
		mem_buff = nv_mem_buff_list_remove_vma(area);
	}

	if(!mem_buff){
		pr_crit("closing unknown mem_buff %p\n", area);
		return;
	}
}

const struct vm_operations_struct nv_mem_buff_vm_op = {
    .open       = nv_mem_buff_open,
    .close      = nv_mem_buff_close,
//  .unmap      = nv_mem_buff_unmap,
//  .sync: mb_sync,
//  .advise: mb_advise,
//  .nopage: mb_nopage,
//  .wppage: mb_wppage,
//  .swapout: mb_swapout,
//  .swapin: mb_swapin
};

int 
nv_dev_mem_buff_mmap(struct file *file, 
                   struct vm_area_struct *vma) {
	int ret = 0; 
	char *mem_buff_0;
    nv_mem_buff_t *mem_buff;

	mem_buff = nv_mem_buff_lookup_file(file);

	if(!mem_buff){
		pr_crit("mem_buff_mmap:no buffer selected for this file:%p\n",
                   file);
		ret = -EINVAL;
        goto end;
	}
	
    mem_buff_0 = mem_buff->buf;

	if(!mem_buff->buf) {
        pr_crit("Shared memory buffer has to be allocated before mmap\n");
		ret = -EAGAIN;
        goto end;
	}
	
    if((ret = nv_vmmap(mem_buff, vma)) < 0) {
		if(mem_buff_0 == NULL) {
			nv_vfree(mem_buff->buf, mem_buff->size);
			mem_buff->buf = NULL; 
            mem_buff->size = 0; 
		}
        goto end;
	}

	if(!vma->vm_ops) {
		vma->vm_ops = &nv_mem_buff_vm_op;
	}
	
    ret = nv_mem_buff_list_add_vma(mem_buff, vma);
	if(ret) {
	    pr_crit("failed to add vma to mem buff");
    }

end:    
    return ret;
}




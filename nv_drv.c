#include "nv_i.h"
#include "nv_mem.h"
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
#include <linux/wait.h>

extern nv_mem_buff_t *mem_buff[3];
extern nv_conn_t *nv_conn;
extern rwlock_t nv_mem_buff_list_rwlock;

int triggered_signal = 0;

int 
nv_dev_open(struct inode *inode,
                         struct file *file) {
    return 0;
}

ssize_t 
nv_dev_read(struct file *filp,
                  char __user *buf,
                  size_t len,
                  loff_t *ppos) {
    nv_mem_chunk_buff_t *req_chunk_buff = NULL;
    nv_mem_chunk_buff_t *resp_chunk_buff = NULL;
    nv_control_req_header_t control_req_header;   
    nv_req_t *req = NULL;
    loff_t offset = 0;
    size_t ret = 0;

    ret = len;
    while(!req_chunk_buff) {
        req = NULL;
        spin_lock(&nv_conn->lock);
        req_chunk_buff = nv_chunk_mem_get(mem_buff[0],
                                        &mem_buff[0]->pending_list);
        if(!req_chunk_buff) {
            spin_unlock(&nv_conn->lock);
            wait_event_timeout(nv_conn->waitq,
                       (nv_conn->req_present == 1), HZ);
            if(signal_pending(current) ||
                (triggered_signal)) {
                ret = 0;
                triggered_signal = 0;
                goto end;
            }       
        } else {
            spin_unlock(&nv_conn->lock);
            break;
        }

        spin_lock(&nv_conn->lock);
        req_chunk_buff = nv_chunk_mem_get(mem_buff[0],
                                        &mem_buff[0]->pending_list);
        if(!req_chunk_buff) {
            nv_conn->req_present = 0;
        }      
    
        spin_unlock(&nv_conn->lock);
    }

    req = (nv_req_t *)
                     (mem_buff[0]->buf +
                           req_chunk_buff->offset); 

    resp_chunk_buff = req->req_msg.resp_mem;

    nv_chunk_mem_remove(mem_buff[1], resp_chunk_buff, 
                              &mem_buff[1]->pending_list);
    
    /* fixme: not needed will be removed after
     * code is stabilized
     */

    memcpy(&control_req_header.req_chunk_buff,
           req_chunk_buff, sizeof(nv_mem_chunk_buff_t));
    
    memcpy(&control_req_header.resp_chunk_buff,
           resp_chunk_buff, sizeof(nv_mem_chunk_buff_t));


    simple_read_from_buffer(buf, 
                            sizeof(nv_control_req_header_t),
                            &offset, (char *) &control_req_header,
                            len);
   
    nv_chunk_mem_put(mem_buff[0], req_chunk_buff, 
                           &mem_buff[0]->processing_list);
    
    nv_chunk_mem_put(mem_buff[1], resp_chunk_buff, 
                           &mem_buff[1]->processing_list);
    
    req_chunk_buff->queue_status = NV_PROCESSING_LIST;
    resp_chunk_buff->queue_status = NV_PROCESSING_LIST;

end:
    return ret;
}

ssize_t 
nv_dev_write(struct file *file, 
                   const char __user *buf,
                   size_t len, 
                   loff_t *ppos) {
    nv_mem_chunk_buff_t *req_chunk_buff = NULL;
    nv_mem_chunk_buff_t *resp_chunk_buff = NULL;
    nv_req_t *shared_req = NULL;
    nv_control_resp_header_t ctrl_resp_data; 
    loff_t offset = 0;
    wait_queue_head_t *waitq_ptr = NULL;

    simple_write_to_buffer((char *) &ctrl_resp_data,
                            sizeof(ctrl_resp_data),
                            &offset, buf, len);
 
    req_chunk_buff = &ctrl_resp_data.req_chunk_buff;
    resp_chunk_buff = &ctrl_resp_data.resp_chunk_buff;

    if(!req_chunk_buff || !resp_chunk_buff) {
        pr_crit("req/resp buffers are null");
        goto end;
    }

    shared_req = (nv_req_t *)
                        (mem_buff[0]->buf +
                               req_chunk_buff->offset); 

    shared_req->state = NV_REQ_FINISHED;

    /* dont do much processing here 
     * do it this in vfs context
     */

    waitq_ptr = (wait_queue_head_t *) shared_req->waitq;

    req_chunk_buff->wake_up_done = 1;
    
    wake_up(waitq_ptr);

end: 
    return len;
}

unsigned 
nv_dev_poll(struct file *file, poll_table *wait) {
    return 0;
}

int 
nv_dev_release(struct inode *inode, struct file *file) {
	return 0;
}

const struct file_operations nv_dev_operations = {
	.owner		= THIS_MODULE,
    .open       = nv_dev_open,
	.read		= nv_dev_read,
	.write		= nv_dev_write,
	.poll		= nv_dev_poll,
	.release	= nv_dev_release,
};

static struct miscdevice nv_comm_miscdevice = {
	.minor = NV_COMM_MINOR,
	.name  = "nv_comm",
	.fops = &nv_dev_operations,
};

const struct file_operations nv_mem_buff_operations = {
	.owner		= THIS_MODULE,
    .open       = nv_dev_mem_buff_open,
	.release	= nv_dev_mem_buff_close,
    .unlocked_ioctl = nv_dev_mem_buff_ioctl,
    .mmap       = nv_dev_mem_buff_mmap,
    .llseek      = nv_dev_mem_buff_llseek, 
};

static struct miscdevice nv_mem_buff_miscdevice = {
	.minor = NV_MEM_BUFF_MINOR,
	.name  = "nv_mem",
	.fops = &nv_mem_buff_operations,
};

int 
nv_dev_init(void) {
	int err = -ENOMEM;

    /* allocate the global connection */
    nv_conn = kmalloc(sizeof(*nv_conn), GFP_KERNEL);
    if(!nv_conn) {
        pr_crit("failed to allcoate memory for nv connection");
        goto clean;
    }

    rwlock_init(&nv_mem_buff_list_rwlock);

    spin_lock_init(&nv_conn->lock);
    init_waitqueue_head(&nv_conn->waitq);

	err = misc_register(&nv_mem_buff_miscdevice);
	if(err) {
        if(nv_conn) {
            kfree(nv_conn);
        }     
        goto clean;
    }
	
    err = misc_register(&nv_comm_miscdevice);
	if(err) {
		if(nv_conn) {
            kfree(nv_conn);
        }     
        goto clean;
    }

clean:
	return err;
}

void 
nv_dev_cleanup(void) {
	misc_deregister(&nv_comm_miscdevice);
    misc_deregister(&nv_mem_buff_miscdevice);
    if(nv_conn) {
        kfree(nv_conn);
        nv_conn = NULL;
    }      
    /* need to destroy the memory pools */
    nv_mem_buff_release_all();
}

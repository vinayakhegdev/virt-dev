#ifndef _FS_NV_I_H
#define _FS_NV_I_H


/* res mask */
#define LOCAL_OWNER 0x1
#define REMOTE_OWNER 0x2
#define NVFS_MAX_NAME 256
#define REQUEST_BUFF_NAME "nv_req_buff"
#define RESPONSE_BUFF_NAME "nv_resp_buff"
#define DATA_BUFF_NAME "nv_data_buff"

#define NV_MEM_BUFF_NAME_LEN 32
#define NV_MEM_BUFF_MAX_MMAPS 16
#define NV_KERN_OID_BYTE 12
#define NV_INODE_LEN 8 
#define NV_MAX_FILE_KEY_SIZE (2 * (sizeof(u64) + sizeof(int))) 
#define IOCTL_NV_MEM_BUFF_ALLOCATE 0
#define IOCTL_NV_MEM_BUFF_DEALLOCATE 2
#define IOCTL_NV_MEM_BUFF_START 1
#define IOCTL_NV_MEM_BUFF_LAST IOCTL_NV_MEM_BUFF_DEALLOCATE

#define IOCTL_NV_SNAP_INFO 0
#define IOCTL_NV_SNAP_LAST 1

#define NV_SNAP_START 0x1
#define NV_SNAP_END 0x2

#define NV_START 0x1
#define NV_KILL 0x2

typedef struct nv_mem_buff_request__ {
    unsigned int flags;
    char name[NV_MEM_BUFF_NAME_LEN + 1];
    unsigned long long size;
    int unit_size;
} nv_mem_buff_request_t;

typedef enum nv_queue_status__ {
    NV_PENDING_LIST,
    NV_PROCESSING_LIST,
    NV_FREE_LIST,
} nv_queue_status_t;

typedef struct nv_mem_chunk_buff__ {
    unsigned long offset;
    unsigned long page_size;
    int chunk_size;
    nv_queue_status_t queue_status;
    int wake_up_done;
    struct nv_mem_chunk_buff__ *next;
    struct nv_mem_chunk_buff__ *prev;
} nv_mem_chunk_buff_t;

typedef enum nv_type__ {
    NV_IFSOCK,
    NV_IFLNK,
    NV_IFREG,
    NV_IFBLK,
    NV_IFDIR,
    NV_IFCHR,
    NV_IFIFO 
} nv_type_t;

typedef enum nv_attr_mask__ { 
    NVFS_ATTR_MODE = (1 << 0),
    NVFS_ATTR_UID  = (1 << 1),
    NVFS_ATTR_GID  = (1 << 2),
    NVFS_ATTR_SIZE = (1 << 3),
    NVFS_ATTR_ATIME = (1 << 4),
    NVFS_ATTR_MTIME = (1 << 5),
    NVFS_ATTR_FH    = (1 << 6),
    NVFS_ATTR_CTIME = (1 << 7),
    NVFS_ATTR_ALL = 
            (NVFS_ATTR_MODE | NVFS_ATTR_UID |
                    NVFS_ATTR_GID | NVFS_ATTR_SIZE
                    | NVFS_ATTR_ATIME |
                    NVFS_ATTR_MTIME |
                    NVFS_ATTR_CTIME)
} nv_attr_mask_t;

typedef enum nv_access_mask__ {
    NV_MAY_EXEC = 0x00000001,
    NV_MAY_WRITE = 0x00000002,
    NV_MAY_READ  = 0x00000004,
    NV_MAY_APPEND = 0x00000008,
    NV_MAY_ACCESS = 0x00000010,
    NV_MAY_OPEN  = 0x00000020,
    NV_MAY_CHDIR = 0x00000040
} nv_access_mask_t;   

typedef enum nv_mode__ {
    NV_READ_ONLY = 0x00000001,
    NV_WRITE_ONLY = 0x00000002,
    NV_READ_WRITE = 0x00000004,
    NV_CREATE  = 0x00000008,
    NV_EXCL = 0x00000010,
    NV_APPEND = 0x00000020,
    NV_TRUNC = 0x00000040,
} nv_mode_t;   

typedef struct nv_attr__ {
    unsigned long long ino;
    unsigned long long size;
    unsigned long long blocks;
    unsigned long long atime;
    unsigned long long mtime;
    unsigned long long ctime;
    unsigned long atimensec;
    unsigned long mtimensec;
    unsigned long ctimensec;
    unsigned long mode;
    unsigned long nlink;
    unsigned long uid;
    unsigned long gid;
    unsigned long rdev;
    unsigned long blksize;
    unsigned long padding;
} nv_attr_t;

typedef struct nv_kstatfs__ {
    unsigned long long blocks;
    unsigned long long bfree;
    unsigned long long bavail;
    unsigned long long files;
    unsigned long long ffree;
    unsigned long bsize;
    unsigned long namelen;
    unsigned long frsize;
    unsigned long padding;
    unsigned long spare[6];
} nv_kstatfs_t;

typedef enum nv_req_state__ {
    NV_REQ_INIT = 0,
    NV_REQ_PENDING,
    NV_REQ_SENT,
    NV_REQ_FINISHED,
    NV_REQ_ABORT
} nv_req_state_t;

typedef enum nv_req_op_code__ {
    NV_OP_REQ_READ = 1,
    NV_OP_REQ_WRITE,
    NV_OP_REQ_GET_PATH,
    NV_OP_REQ_GET_OWNER,
    NV_OP_REQ_GETATTR,
    NV_OP_REQ_SETATTR,
    NV_OP_REQ_REMOTE_GETATTR,
    NV_OP_REQ_REMOTE_READ,
    NV_OP_REQ_REMOTE_WRITE,
    NV_OP_REQ_CREATE,
    NV_OP_REQ_LOOKUP,
    NV_OP_REQ_RENAME,
    NV_OP_REQ_SYMLINK,
    NV_OP_REQ_READLINK,
    NV_OP_REQ_LINK,
    NV_OP_REQ_UNLINK,
    NV_OP_REQ_RMDIR,
    NV_OP_REQ_MKDIR,
    NV_OP_REQ_MKNOD,
    NV_OP_REQ_READIDR,
    NV_OP_REQ_ACCESS,
    NV_OP_REQ_READDIR,
    NV_OP_REQ_MOUNT,
    NV_OP_REQ_UMOUNT,
    NV_OP_REQ_STATFS,
    NV_OP_REQ_FALLOCATE,
} nv_req_op_code_t;

typedef struct nv_req_msg__ {
    nv_mem_chunk_buff_t *req_mem;
    nv_mem_chunk_buff_t *resp_mem;
    nv_req_op_code_t op_code;
    union nv_req_data_t {
        struct nv_read_req {
            int vol_id;
            unsigned long long file_id;
            unsigned long long offset;
            unsigned long long len;
        } nv_read_req_data;
        struct nv_write_req {
            int vol_id;
            unsigned long long file_id;
            unsigned long long offset;
            unsigned long long len;
        } nv_write_req_data;
        struct nv_get_path_req {
            int vol_id;
            unsigned long long file_id;
            unsigned long long offset;
            unsigned long long len;
        } nv_get_path_req_data;
        struct nv_getattr_req {
            int vol_id;
            unsigned long long  file_id;
        } nv_getattr_req_data;      
        struct nv_setattr_req {
            int vol_id;
            unsigned long long  file_id;
            nv_attr_mask_t attr_mask;
            nv_attr_t attr;
            nv_attr_mask_t mask;
        } nv_setattr_req_data;      
        struct nv_readlink_req {
            int vol_id;
            unsigned long long  file_id;
        } nv_readlink_req_data;      
        struct nv_readdir_req {
            int vol_id;
            unsigned long long  file_id;
            unsigned long long cookie;
        } nv_readdir_req_data;   
        struct nv_lookup_req {
            int vol_id;
            unsigned long long  dir_id;
            char name[NVFS_MAX_NAME];
            int len;
        } nv_lookup_req_data;   
        struct nv_link_req {
            int vol_id;
            unsigned long long  file_id;
            unsigned long long  dir_id;
            char name[NVFS_MAX_NAME];
            int len;
        } nv_link_req_data;      
        struct nv_access_req {
            int vol_id;
            unsigned long long  file_id;
            nv_access_mask_t mask;
        } nv_access_req_data;      
        struct nv_create_req {
            int vol_id;
            nv_mode_t mode;             
            int excl;
            unsigned long long  dir_id;
            char name[NVFS_MAX_NAME];
            int len;
        } nv_create_req_data;    
        struct nv_mkdir_req {
            int vol_id;
            nv_mode_t mode;        
            unsigned long long  dir_id;
            char name[NVFS_MAX_NAME];
            int len;
        } nv_mkdir_req_data;  
        struct nv_mknod_req {
            int vol_id;
            unsigned long long  file_id;
            unsigned long long  dir_id;
            char name[NVFS_MAX_NAME];
            int len;
        } nv_mknod_req_data;     
        struct nv_rename_req {
            int vol_id;
            unsigned long long  old_dir_id;
            char old_name[NVFS_MAX_NAME];
            int old_len;
            unsigned long long  new_dir_id;
            char new_name[NVFS_MAX_NAME];
            int new_len;
        } nv_rename_req_data;   
        struct nv_symlink_req {
            int vol_id;
            unsigned long long  dir_id;
            char name[NVFS_MAX_NAME];
            int len;
            char link_content[NVFS_MAX_NAME];
        } nv_symlink_req_data;     
        struct nv_unlink_req {
            int vol_id;
            unsigned long long  dir_id;
            char name[NVFS_MAX_NAME];
            int len;
        } nv_unlink_req_data;     
        struct nv_rmdir_req {
            int vol_id;
            unsigned long long  dir_id;
            char name[NVFS_MAX_NAME];
            int len;
        } nv_rmdir_req_data;      
        struct nv_remote_read_req {
            int vol_id;
            unsigned long long  file_id;
            unsigned long long offset;
            unsigned long long len;
        } nv_remote_read_req_data;      
        struct nv_remote_write_req {
            int vol_id;
            unsigned long long  file_id;
            unsigned long long offset;
            unsigned long long len;
            nv_mem_chunk_buff_t chunk_data_buff;                    
        } nv_remote_write_req_data;
        struct nv_mount_req {
            char path[NVFS_MAX_NAME];
        } nv_mount_req_data;
        struct nv_umount_req {
            char path[NVFS_MAX_NAME];
        } nv_umount_req_data;
        struct nv_statfs_req {
            int vol_id;
        } nv_statfs_req_data;
        struct nv_fallocate_req {
            int vol_id;
            unsigned long long  file_id;
            unsigned long long offset;
            unsigned long long len;
            int mode;
        } nv_fallocate_req_data;
    } nv_req_data;
} nv_req_msg_t;
 
typedef enum nv_resp_op_code__ {
    NV_OP_REQRESP_READ,
    NV_OP_REQRESP_WRITE,
    NV_OP_REQRESP_GET_PATH,
    NV_OP_REQRESP_GET_OWNER,
    NV_OP_REQRESP_GET_ATTR,
    NV_OP_REQRESP_INVALIDATE_CACHE,
    NV_OP_REQRESP_REMOTE_GETATTR,
    NV_OP_REQRESP_REMOTE_READ,
    NV_OP_REQRESP_REMOTE_WRITE,
    NV_OP_REQRESP_CREATE,
    NV_OP_REQRESP_LOOKUP,
    NV_OP_REQRESP_LINK,
    NV_OP_REQRESP_READLINK,
    NV_OP_REQRESP_SYMLINK,
    NV_OP_REQRESP_UNLINK,
    NV_OP_REQRESP_RMDIR,
    NV_OP_REQRESP_MKDIR,
    NV_OP_REQRESP_MKNOD,
    NV_OP_REQRESP_ACCESS,
    NV_OP_REQRESP_READDIR,
} nv_resp_op_code_t;

typedef enum nv_resp_status__ {
    NV_ERR_SUCCESS,
    NV_ERR_NOENT,
    NV_ERR_BUSY,
    NV_ERR_EXISTS,
    NV_ERR_INVAL,
    NV_ERR_NOSPC,
    NV_ERR_EACCESS,
    NV_ERR_EPERM,
    NV_ERR_READ_ONLY,
    NV_ERR_NOMEM,
    NV_ERR_DELAY
} nv_resp_status_t;

typedef struct nv_dirent__ { 
    unsigned long long    ino;
    unsigned long long    off;
    unsigned long         namelen;
    nv_type_t       type;
    char name[NVFS_MAX_NAME];
} nv_dirent_t;

typedef struct nv_direntplus__ {
    int dir_count;
    int eof;
    nv_attr_t dir_attr;                 
    nv_dirent_t dirent[3];
} nv_direntplus_t;

typedef struct nv_read_info__ {
    int res_mask;
    unsigned long long offset;
    unsigned long long count;
    char path[NVFS_MAX_NAME];
} nv_read_info_t;

typedef struct nv_write_info__ {
    int res_mask;
    unsigned long long offset;
    unsigned long long count;
    char path[NVFS_MAX_NAME];
} nv_write_info_t;

typedef struct nv_resp_msg__ {
    nv_mem_chunk_buff_t *req_mem;
    nv_mem_chunk_buff_t *resp_mem;    
    nv_resp_op_code_t op_code;
    
    union nv_resp_data_t {
        struct nv_read_resp {
            nv_resp_status_t resp_status;
            int total_entry;
            nv_read_info_t read_info[2];
        } nv_read_resp_data;
        struct nv_write_resp {
            nv_resp_status_t resp_status;
            int total_entry;
            nv_write_info_t write_info[2];
        } nv_write_resp_data;
        struct nv_getattr_resp {
            nv_resp_status_t resp_status;
            nv_attr_t attr;
        } nv_getattr_resp_data;
        struct nv_setattr_resp {
            nv_resp_status_t resp_status;
            int res_mask;
            nv_attr_t attr;
        } nv_setattr_resp_data;
        struct nv_readlink_resp {
            nv_resp_status_t resp_status;       
            char link[NVFS_MAX_NAME];
        } nv_readlink_resp_data;      
        struct nv_readdir_resp {
            nv_resp_status_t resp_status;
            nv_direntplus_t dirent_data;
        } nv_readdir_resp_data;      
        struct nv_remote_read_resp {
            nv_resp_status_t resp_status;
            int res_mask;
            unsigned long long bytes_read;
            unsigned long long offset;
            char path[NVFS_MAX_NAME];
            nv_mem_chunk_buff_t chunk_data_buff;
        } nv_remote_read_resp_data;
        struct nv_remote_write_resp {
            nv_resp_status_t resp_status;
            int res_mask;
            unsigned long long bytes_written;
            unsigned long long offset;
            char path[NVFS_MAX_NAME];
        } nv_remote_write_resp_data;
        struct nv_link_resp {
            nv_resp_status_t resp_status;
            nv_attr_t dir_attr;
            nv_attr_t file_attr;
        } nv_link_resp_data;      
        struct nv_create_resp {
            nv_resp_status_t resp_status;
            unsigned long long  file_id;
            nv_attr_t dir_attr;
            nv_attr_t file_attr;
        } nv_create_resp_data;    
        struct nv_access_resp {
            nv_resp_status_t resp_status;
        } nv_access_resp_data;
        struct nv_mkdir_resp {
            nv_resp_status_t resp_status;
            unsigned long long  file_id;
            nv_attr_t dir_attr;
            nv_attr_t file_attr;
        } nv_mkdir_resp_data;  
        struct nv_mknod_resp {
            nv_resp_status_t resp_status;
            unsigned long long  file_id;
            nv_attr_t dir_attr;
            nv_attr_t file_attr;
        } nv_mknod_resp_data;     
        struct nv_rename_resp {
            nv_resp_status_t resp_status;
            nv_attr_t old_dir_attr;
            nv_attr_t new_dir_attr;
            nv_attr_t file_attr;
        } nv_rename_resp_data;   
        struct nv_lookup_resp {
            nv_resp_status_t resp_status;
            unsigned long long  file_id;
            nv_attr_t file_attr;
        } nv_lookup_resp_data;  
        struct nv_symlink_resp {
            nv_resp_status_t resp_status;
            unsigned long long  file_id;
            nv_attr_t file_attr;
            nv_attr_t symlink_attr;
        } nv_symlink_resp_data;          
        struct nv_unlink_resp {
            nv_resp_status_t resp_status;
            unsigned long long  file_id;
            nv_attr_t file_attr;
            nv_attr_t dir_attr;
        } nv_unlink_resp_data;          
        struct nv_rmdir_resp {
            nv_resp_status_t resp_status;
            nv_attr_t dir_attr;
        } nv_rmdir_resp_data;          
        struct nv_mount_resp {
            nv_resp_status_t resp_status;
            nv_kstatfs_t kstatfs;
            nv_attr_t root_attr;
            int vol_id;
            unsigned long long  file_id;
        } nv_mount_resp_data;
        struct nv_umount_resp {
            nv_resp_status_t resp_status;
        } nv_umount_resp_data;
        struct nv_statfs_resp {
            nv_resp_status_t resp_status;
            nv_kstatfs_t kstatfs;
        } nv_statfs_resp_data;
        struct nv_invalidate_cache {
            nv_resp_status_t resp_status;
            int vol_id;
            char path[NVFS_MAX_NAME];
        } nv_invalidate_cache_data;
        struct nv_fallocate_resp {
            nv_resp_status_t resp_status;
        } nv_fallocate_resp_data;
    } nv_resp_data;
} nv_resp_msg_t;

typedef struct nv_control_req_header__ {
    nv_mem_chunk_buff_t req_chunk_buff;
    nv_mem_chunk_buff_t resp_chunk_buff; 
} nv_control_req_header_t;

typedef struct nv_control_resp_header__ {
    nv_mem_chunk_buff_t req_chunk_buff;
    nv_mem_chunk_buff_t resp_chunk_buff;
} nv_control_resp_header_t;

typedef struct nv_req__ {
    nv_req_state_t state;
    nv_req_msg_t req_msg; 
    char *waitq;
} nv_req_t;

typedef struct nv_resp__ {
    nv_resp_msg_t resp_msg; 
} nv_resp_t;


/* shared between datamanger for snapshot 
 * for ioctl 
 */

typedef struct nv_snap_request__ {
    unsigned int flags;
    unsigned long long file_id;
    int vol_id;
} nv_snap_request_t;

#endif   

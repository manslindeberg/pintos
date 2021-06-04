#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/exception.h"
#include "vm/sup_page.h"
#include "vm/frame.h"

/* system call implementations */
static void halt(void);
static void exit(struct intr_frame *f);
static uint32_t exec(struct intr_frame *f);
static uint32_t wait(struct intr_frame *f);
static uint32_t create(struct intr_frame *);
static uint32_t remove(struct intr_frame *);
static uint32_t open(struct intr_frame *);
static uint32_t filesize(struct intr_frame *);
static uint32_t read(struct intr_frame *);
static uint32_t write(struct intr_frame *);
static void seek(struct intr_frame *);
static void close(struct intr_frame *);
static uint32_t mmap(struct intr_frame *f);

/* helper functions for file descriptor list in thread struct */
static struct file_descriptor *get_file_from_fd(int fd);
static uint32_t add_file_to_fd(struct file *);
static void remove_file_from_fd(int fd);
static void close_all_fds(struct thread *);
static void syscall_handler(struct intr_frame *);

/* Mutex locks for system call synchronization on files and descriptors */
struct lock syscall_lock;


void
syscall_init(void)
{ 
    memset(&syscall_lock, 0, sizeof syscall_lock);
    lock_init(&syscall_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    // -> is it needed in this?? since no g is allowed yet??multiprocessin
}

/* Returns true if the user address sequence is in valid range or false otherwise.
   If exact is true, the whole range is checked, otherwise this can be used to
   check for validity of strings - it only looks up to end of string \0.
 */
bool validate_user_addr_range(uint8_t *va, size_t bcnt, uint32_t *esp, bool exact);

/* Uses the second technique mentioned in pintos doc. 3.1.5 
   to cause page faults and check addresses (returns -1 on fault) */

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user(const uint8_t *uaddr)
{
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
/*
static bool
put_user (uint8_t *udst, uint8_t byte) {
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}
*/

/* Used to validate pointers, buffers and strings. 
   With exact false, it validates until 0 (end of string). */
bool validate_user_addr_range(uint8_t *va, size_t bcnt, uint32_t *esp, bool exact)
{
    if (va == NULL) {  /* NULL is not allowed */
        return false;
    }

    for (size_t i = 0; (i < bcnt) || !exact; i++) {
        if (!is_user_vaddr(va + i)) { /* outside user space! wrong */
            return false;
        }
        int w = get_user(va + i);
        if (!exact && w == 0) { /* end of string */
            return true;
        }
        if (w == -1) { /* outside mapped pages */
#ifdef VM
            uint8_t* uaddr = PFNO_TO_ADDR(ADDR_TO_PFNO(va+i));
            struct sup_page* spg = lookup_page(uaddr);
            if(spg != NULL && load_page(spg, uaddr)) /* page must be loaded */
              continue; /* check next address */
            if(va+i > (uint8_t*)esp && grow_stack(uaddr)) /* 1st stack access in syscall */
              continue; /* check next address*/
            /* none of these situations! */
#endif
            return false;
        }
    }
    return true;
}

/* File system primitive synchronization. Sequentialize file system accesses. */
#define FS_ATOMIC(code) \
  {  fs_take(); \
     {code} \
     fs_give(); }

static void
syscall_handler(struct intr_frame *f)
{

 /* making sure that part user arguments on stack < PHYS_BASE*/
 bool is_validated = validate_user_addr_range(f->esp,
	    16, f->esp, true);

 /* exists with status code -1 */
    if (!is_validated || f->esp == NULL) {
        thread_exit();
    }

    uint32_t *syscall_no = (f->esp);
    uint32_t ret = 0;

    switch (*syscall_no) {

        case SYS_HALT: {
            halt();
            NOT_REACHED();
        }
            break;

        case SYS_EXIT: {
            exit(f);
            NOT_REACHED();
        }
            break;

        case SYS_EXEC: {
            ret = exec(f);
            f->eax = (uint32_t) ret;
        }
            break;

        case SYS_WAIT: {
            ret = wait(f);
            f->eax = (int32_t) ret;
        }
            break;

        case SYS_CREATE: {
            ret = create(f);
            f->eax = (uint32_t) ret;
        }
            break;

        case SYS_REMOVE: {
            ret = remove(f);
            f->eax = (uint32_t) ret;
        }
            break;

        case SYS_OPEN: {
            ret = open(f);
            f->eax = (uint32_t) ret;
        }
            break;

        case SYS_FILESIZE: {
            ret = filesize(f);
            f->eax = (int32_t) ret;
        }
            break;

        case SYS_READ: {
            ret = read(f);
            f->eax = (uint32_t) ret;
        }
            break;

        case SYS_WRITE: {
            ret = write(f);
            f->eax = (uint32_t) ret;
        }
            break;

        case SYS_SEEK: {
            seek(f);
        }
            break;

        case SYS_TELL: {
            //TODO
        }
            break;

        case SYS_CLOSE: {
            close(f);
        }
            break;

        case SYS_MMAP: {
            ret = mmap(f);
            f->eax = (int32_t) ret;
        }
            break;

        case SYS_MUNMAP: {
            size_t id = (f->esp + 4);
            munmap(id);
        }
            break;
    }
}

static void exit(struct intr_frame *f)
{
    struct fd_args *args = (struct fd_args *) f->esp;
    int status = args->fd;
    struct thread *t = thread_current();

    if ( t->parent !=  NULL ) {
        if (status < 0) {
            //TODO: Unnecessary? What does this do?
            t->exit_status = 1;
        } 
        t->exit_status = status;
    }
  
    close_all_fds(t);
   
    thread_exit(); //Also exits process if userprog
}

/* */
static uint32_t exec(struct intr_frame *f)
{
    struct file_args *args = (struct file_args *) f->esp;
    bool is_validated = validate_user_addr_range(args->file,
	    MAX_FILENAME_SIZE, f->esp, true);
    
    if(!is_validated) {
        thread_exit();
    }

    //fs_take();
    uint32_t ret  = process_execute((const char *) args->file);
    //fs_give();
    return ret;
}

static uint32_t wait(struct intr_frame *f)
{
   struct fd_args *args = (struct fd_args *) f->esp;
   if (args->fd < 0) {
        return -1;
   }
   return process_wait(args->fd);
}

/* Shuts down the machine if running on qemu or bosh */
static void halt(void)
{
    shutdown_power_off();
}

/* Creates new file from filename into filesystem */
static uint32_t create(struct intr_frame *f)
{

    struct create_args *args = (struct create_args *) f->esp;
    bool is_validated = validate_user_addr_range((uint8_t*) args->file,
	    4, f->esp, false);
    
    if(!is_validated) {
        thread_exit();
        return -1;
    }

    if (*args->file == 0) {
        return -1;
    }

    fs_take();
    bool success = filesys_create((const char *) args->file,
	    args->length);
    fs_give();
    return success;
}

/* Removes file from filesystem */
static uint32_t remove(struct intr_frame *f)
{
    struct file_args *args = (struct file_args *) f->esp;
    bool is_validated = validate_user_addr_range((uint8_t*)args->file, 
	    MAX_FILENAME_SIZE, f->esp, true);
    if(!is_validated) {
        return -1;
    }
    fs_take();
    bool ret = filesys_remove((const char *) args->file);
    fs_give();
    return ret;
}

/* Opens file in filesystem and adds it to file descriptor list */
static uint32_t open(struct intr_frame *f)
{
    struct file_args *args = (struct file_args *) f->esp;
    bool is_validated = validate_user_addr_range((uint8_t*)args->file, 
	    4, f->esp, false);
    
    if(!is_validated) {
        thread_exit();
        return -1;
    }

    if (args->file == NULL) {
        return -1;
    }

    fs_take();
    struct file *file = filesys_open((const char *) args->file);
    fs_give();
    if (file == NULL) {
        return -1;
    }
    return add_file_to_fd(file);
}

/* Finds the file given by file descriptor and returns its size in bytes */
static uint32_t filesize(struct intr_frame *f)
{
    struct fd_args *args = (struct fd_args *) f->esp;
    struct file_descriptor *file_descr = get_file_from_fd(args->fd);

    if (file_descr == NULL) {
        return -1;
    }

    fs_take();
    uint32_t size = file_length(file_descr->file);
    fs_give();
    return (uint32_t) size;
}

/* Reads size bytes file descriptor fd index. Returns the number of bytes that
 * was read  or -1 if encountering errors. STDIN_FILENO reads from keyboard. */
static uint32_t read(struct intr_frame *f)
{
    struct io_args *args = (struct io_args *) f->esp;
    bool is_validated = validate_user_addr_range((uint8_t*)args->buffer,
	    args->length, f->esp, true);
    
    if(!is_validated)
        thread_exit();

    if (args->fd < 0 || args->fd > 128)
        return -1;

    uint32_t read_length;
   
	if (args->fd == STDIN_FILENO) {
		
		uint32_t i;
		for (i = 0; i < args->length; i++) {
            char c = input_getc();
            memcpy(args->buffer, &c, sizeof(c));
        }
        return i;

    } else {
		struct file_descriptor *descriptor = get_file_from_fd(args->fd);

        if (descriptor == NULL) {
            return -1;
		}
        fs_take();
		read_length = file_read(descriptor->file, args->buffer,
		args->length);
        fs_give();
    }
    return read_length;
}

/* Writes to file given the file descriptor index and returns the number of
 * bytes that was written to that file and -1 if error */
static uint32_t write(struct intr_frame *f)
{
    struct io_args *args = (struct io_args *) f->esp;
    bool is_validated = validate_user_addr_range((uint8_t*)args->buffer, args->length,
	    f->esp, true);
    
    if(!is_validated) {
        thread_exit();
    }

    uint32_t written_length;



	if (args->fd < 0 || args->fd > MAX_FD_SIZE || args->fd == STDIN_FILENO)
		return -1;

    
    if (args->fd == STDOUT_FILENO) {
        putbuf((const char *) (args->buffer), args->length);
        written_length = args->length;
    } else {
        struct file_descriptor *descriptor = get_file_from_fd(args->fd);
       
        if (descriptor == NULL) {
            return -1;
		}

        fs_take();
        written_length = file_write(descriptor->file, args->buffer, 
		args->length);
        fs_give();
    }
    return written_length;
}

/* Finds file given by file descirpter and moves it's cursor to position */
static void 
seek(struct intr_frame *f)
{
    struct seek_args *args = (struct seek_args *) f->esp;
    struct file_descriptor *file_descr = get_file_from_fd(args->fd);
 
    if (file_descr != NULL) {
        fs_take();
        file_seek(file_descr->file, args->pos);
        fs_give();
    }
}

/* Closes file in process file-descripter list with index fd */
static void 
close(struct intr_frame *f)
{
    struct fd_args *args = (struct fd_args *) f->esp;
    struct file_descriptor *file_descr = get_file_from_fd(args->fd);

    if (file_descr != NULL) {
        fs_take();
        file_close(file_descr->file);
        fs_give();
        remove_file_from_fd(file_descr->fd);
    }
    return;
}

static uint32_t
mmap(struct intr_frame *f)
{
    struct thread *t = thread_current();
    struct mmapping *m = (struct mmapping*) malloc(sizeof(struct mmapping));
    struct mmap_args *args = (struct mmap_args *) f->esp;
    struct file_descriptor *file_descr = get_file_from_fd(args->fd);

    /* error in input arguments or failed to allocate memory for mapping descriptor */
    if (file_descr == NULL || m == NULL || args->va == NULL)
    { 
        return -1;
    }
    
    /* cannot map stdin/stdout fds*/
    if (args->fd == 0 || args->fd == 1 || args->fd > MAX_FD_SIZE) 
        return -1;
    
    /*TODO: check if the number of pages fits or not */
    fs_take();
    int length_bytes = file_length(file_descr->file);
    fs_give();

    if(length_bytes < 0)
        return -1;
  
    uint8_t *addr = args->va;
    if (args->va != pg_round_down(addr) || args->va != pg_round_up(addr))
        return -1;

    fs_take();
    struct file *file = file_reopen(file_descr->file);
    fs_give();

    if (file == NULL)
        return -1;
   
    m->mapid = t->mappings_size++;
    struct list_elem *e;
    for (e = list_begin(&t->mappings);
         e != list_end(&t->mappings); e = list_next(e)) {
        
        struct mmapping *m = list_entry(e, struct mmapping, elem);
        unsigned mm_addr = ADDR_TO_PFNO(args->va);
        unsigned itr_addr = ADDR_TO_PFNO(m->page);
        if ((mm_addr > itr_addr) && (mm_addr < (itr_addr + PGSIZE))){
            return -1;
        }
    }


    m->page = args->va;

    // check how many pages the file is
    int offset = 0;
    int page_length = 0;

    while (length_bytes > 0)
    { 
        size_t read_bytes = length_bytes;
        if (read_bytes > PGSIZE)
            read_bytes = PGSIZE;

        if (pagedir_get_page(t->pagedir, args->va) != NULL) {
            return -1;
        }

        uint8_t *addr = (uint8_t*) args->va + page_length*PGSIZE;

        struct sup_page *spg = new_mmf_sup_page(offset, read_bytes,(uint8_t*) addr, true);
        spg->mmf_file = file;

        if (spg == NULL)
            return -1;
       
        offset += PGSIZE;
        length_bytes -= PGSIZE;
        page_length++;
    }


    m->length = page_length;
    list_push_back(&t->mappings, &m->elem);
    return m->mapid;
}


void  
munmap(size_t mapid)
{

    if (mapid < 0)
    {
        thread_exit();
    }

    /* remove mapid from mappings*/
    struct thread *t = thread_current();
    struct mmapping *m;
    struct list_elem *e;
    
    for (e = list_begin(&t->mappings);
         e != list_end(&t->mappings); e = list_next(e)) {
        
        m = list_entry(e, struct mmapping, elem);
       
        /* remove from list */
        if (m->mapid == mapid) {
            list_remove(e);
            break;
        }
    }

    if (m == NULL) {
        thread_exit();
    }

    int i = 0;
    /* remove entries from sup_page_table */
    for (size_t page = 0; page < m->length; page++)
    {
        struct sup_page* spg = lookup_page((uint8_t*) m->page + page*PGSIZE);
        struct file *file = spg->mmf_file;

        /* if we have changed it's content, we need to write changes back to disk */
        if (pagedir_is_dirty(t->pagedir, PFNO_TO_ADDR(spg->page_no))) {
            if (i == 0) {
                i++;
            }
            fs_take();
            file_seek(file, spg->offset); // set correct pointer if offset
            file_write(file, PFNO_TO_ADDR(spg->page_no), spg->read_bytes);
            fs_give();
        }

        //pagedir_clear_page(t->pagedir, PFNO_TO_ADDR(spg->page_no));
        list_remove(&spg->elem);
    }
}

/* Retrieves file descriptor from file descriptor list given the file-
 * descriptor index.
 * Returns NULL if there's no descriptor with corresponding index */
static struct file_descriptor *get_file_from_fd(int fd)
{
    struct thread *t = thread_current();
    struct list_elem *e;
    for (e = list_begin(&t->file_descriptors);
         e != list_end(&t->file_descriptors); e = list_next(e)) {
        struct file_descriptor *descriptor = list_entry(e,
        struct file_descriptor, elem);
        if (descriptor->fd == fd)
            return descriptor;
    }
    return NULL;
}

/* Adds opened files to list of file descriptors */
static uint32_t add_file_to_fd(struct file *file)
{
    struct thread *t = thread_current();
    struct file_descriptor *file_descr = (struct file_descriptor *)
        malloc(sizeof(struct file_descriptor));
    file_descr->file = file;
    t->file_descriptors_size++;
    file_descr->fd = t->file_descriptors_size;
    list_push_back(&t->file_descriptors, &file_descr->elem);
    return (uint32_t) file_descr->fd;
}


/* Removes files from list of file descriptors */
static void remove_file_from_fd(int fd)
{
    struct thread *t = thread_current();
    struct list_elem *e;
    for (e = list_begin(&t->file_descriptors);
         e != list_end(&t->file_descriptors); e = list_next(e)) {
        struct file_descriptor *descriptor = list_entry(e,
        struct file_descriptor, elem);
        if (descriptor->fd == fd) {
            list_remove(e);
            free(descriptor);
            break;
        }
    }
}

static void close_all_fds(struct thread *t)
{
    /* Need to implicitly close all open file descriptors */
    struct list_elem *e;
    for (e = list_begin(&t->file_descriptors);
         e != list_end(&t->file_descriptors); e = list_next(e)) {
        struct file_descriptor *descriptor = list_entry(e,
        struct file_descriptor, elem);
        fs_take();
        file_close(descriptor->file);
        fs_give();
        list_remove(e);
        free(descriptor);
        break;
    }
}

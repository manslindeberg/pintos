#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct thread* get_child(tid_t);

struct aux_struct {
    struct semaphore sema;
    const char *file_name;
};

/* exception.c uses this */
bool install_page (void *upage, void *kpage, bool writable);
#endif /* userprog/process.h */

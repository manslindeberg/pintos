#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdint.h>

#define MAX_FD_SIZE     (256)
void syscall_init(void);

void  munmap(size_t);

struct file_args
{
    uint32_t id;
    uint8_t *file;
};

struct create_args
{
    uint32_t id;
    uint32_t *file;
    uint32_t length;
};

struct fd_args
{
    uint32_t id;
    int fd;
};

struct seek_args
{
    uint32_t id;
    uint32_t fd;
    uint32_t pos;
};

struct io_args
{
    uint32_t id;
    int fd;
    uint32_t *buffer;
    uint32_t length;
};

struct mmap_args
{
    uint32_t id;
    uint32_t fd;
    uint32_t *va;
};

#endif /* userprog/syscall.h */

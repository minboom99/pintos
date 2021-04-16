#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "list.h"


#define STDIN (struct file *)0xffffffffffffffff
#define STDOUT (struct file *)0xfffffffffffffffe

void syscall_init (void);
void exit (int status);

bool less_with_fd(const struct list_elem * a, const struct list_elem * b , void * aux);

struct lock filesys_lock;

#endif /* userprog/syscall.h */

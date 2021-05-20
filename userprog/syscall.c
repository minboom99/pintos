#include "userprog/syscall.h"

#include <devices/input.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include <stdbool.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "lib/kernel/stdio.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "list.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void syscall_halt_handler(void);
void syscall_exit_handler(struct intr_frame *);
void syscall_fork_handler(struct intr_frame *);
void syscall_exec_handler(struct intr_frame *);
void syscall_wait_handler(struct intr_frame *);
void syscall_create_handler(struct intr_frame *);
void syscall_remove_handler(struct intr_frame *);
void syscall_open_handler(struct intr_frame *);
void syscall_filesize_handler(struct intr_frame *);
void syscall_read_handler(struct intr_frame *);
void syscall_write_handler(struct intr_frame *);
void syscall_seek_handler(struct intr_frame *);
void syscall_tell_handler(struct intr_frame *);
void syscall_close_handler(struct intr_frame *);

void syscall_dup2_handler(struct intr_frame *);
bool less_with_fd(const struct list_elem *, const struct list_elem *, void *);


/*
 * System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual.
 */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void check_address(const void *addr) {
  /*
   * A user can pass a null pointer, a pointer to unmapped virtual memory,
   * or a pointer to kernel virtual address space (above KERN_BASE).
   * All of these types of invalid pointers must be rejected
   * without harm to the kernel or other running processes,
   * by terminating the offending process and freeing its resources.
   * For example, suppose that your system call has acquired a lock or allocated
   * memory with malloc(). If you encounter an invalid user pointer afterward,
   * you must still be sure to release the lock or free the page of
   * memory(thread_exit에서 해줌).
   */
  
  // TODO : addr에 해당하는 struct page가 존재하는지 찾기

  uint64_t *pml4 = thread_current()->pml4;
  if (addr)
    if (is_user_vaddr(addr))
      if (pml4_get_page(pml4, addr)) return;
  exit(-1);
}

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG)
                                                               << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

  lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *if_ UNUSED) {
  int syscall_num = if_->R.rax;
  switch (syscall_num) {
    case SYS_HALT: {
      syscall_halt_handler();
      break;
    }
    case SYS_EXIT: {
      syscall_exit_handler(if_);
      break;
    }
    case SYS_FORK: {
      syscall_fork_handler(if_);
      break;
    }
    case SYS_EXEC: {
      syscall_exec_handler(if_);
      break;
    }
    case SYS_WAIT: {
      syscall_wait_handler(if_);
      break;
    }
    case SYS_CREATE: {
      syscall_create_handler(if_);
      break;
    }
    case SYS_REMOVE: {
      syscall_remove_handler(if_);
      break;
    }
    case SYS_OPEN: {
      syscall_open_handler(if_);
      break;
    }
    case SYS_FILESIZE: {
      syscall_filesize_handler(if_);
      break;
    }
    case SYS_READ: {
      syscall_read_handler(if_);
      break;
    }
    case SYS_WRITE: {
      syscall_write_handler(if_);
      break;
    }
    case SYS_SEEK: {
      syscall_seek_handler(if_);
      break;
    }
    case SYS_TELL: {
      syscall_tell_handler(if_);
      break;
    }
    case SYS_CLOSE: {
      syscall_close_handler(if_);
      break;
    }
    case SYS_DUP2: {
      syscall_dup2_handler(if_);
      break;
    }
  }
}

void syscall_halt_handler() {
  // void halt (void);
  // Terminates Pintos by calling power_off()
  power_off();
}

void syscall_exit_handler(struct intr_frame *if_) {
  // void exit (int status);
  /*
   * Terminates the current user program, returning status to the kernel.
   * If the process's parent waits for it (see below), this is the status that
   * will be returned. Conventionally, a status of 0 indicates success and
   * nonzero values indicate errors. Whenever a user process terminates, because
   * it called exit or for any other reason, print the process's name and exit
   * code
   */

  int status = (int)if_->R.rdi;
  exit(status);
}

void exit(int status) {
  struct thread *t = thread_current();
  t->exit_status = status;

  printf("%s: exit(%d)\n", t->name, t->exit_status);

  thread_exit();
}

void syscall_fork_handler(struct intr_frame *if_) {
  // pid_t fork (const char *thread_name);
  /*
   * Create new process which is the clone of current process with the name
   * THREAD_NAME.
   *
   * You don't need to clone the value of the registers except %RBX, %RSP, %RBP,
   * and %R12 - %R15, which are callee-saved registers.
   *
   * Must return pid of the child process, otherwise shouldn't be a valid pid.
   *
   * In child process, the return value should be 0. The child should have
   * DUPLICATED resources including file descriptor and virtual memory space.
   *
   * Parent process should never return from the fork until it knows whether the
   * child process successfully cloned.
   *
   * That is, if the child process fail to duplicate the resource, the fork ()
   * call of parent should return the TID_ERROR.
   *
   * The template utilizes the pml4_for_each() in threads/mmu.c to copy entire
   * user memory space, including corresponding pagetable structures, but you
   * need to fill missing parts of passed pte_for_each_func (See virtual
   * address).
   */

  // Check validity of the pointer argument
  const char *thr_name = if_->R.rdi;
  int tid;
  check_address((void *)thr_name);
  // Create new process which is the clone of current process with the name
  // THREAD_NAME.
  struct thread *thr_current = thread_current();
  struct thread *child_thread;
  if_->R.rax = 0;
  thr_current->if_ = if_;
  tid = process_fork(thr_name, if_);

  child_thread = find_child_with_pid(thr_current, tid);

  if (child_thread && child_thread->exit_status == -1) {
    tid = TID_ERROR;
    list_remove(&child_thread->child_e);
    child_thread->parent = NULL;
  }

  thr_current->if_ = NULL;
  if_->R.rax = tid;
}

void syscall_exec_handler(struct intr_frame *if_) {
  // int exec (const char *cmd_line);

  /*
   * Change current process to the executable whose name is given in cmd_line,
   * passing any given arguments. This never returns if successful. Otherwise
   * the process terminates with exit state -1, if the program cannot load or
   * run for any reason. This function does not change the name of the thread
   * that called exec. Please note that file descriptors remain open across an
   * exec call.
   */

  char *cmd_line = if_->R.rdi;
  check_address((void *)cmd_line);

  char *name = palloc_get_page(0);
  if (!name) {
    if_->R.rax = -1;
    exit(-1);
  }
  strlcpy(name, cmd_line, PGSIZE);
  int ret = process_exec(name);
  ASSERT(ret == -1);
  if_->R.rax = ret;
  exit(-1);  // Not reached on success.
}

void syscall_wait_handler(struct intr_frame *if_) {
  tid_t pid = (tid_t)if_->R.rdi;
  if_->R.rax = process_wait(pid);
}
// ================================ FILE SYSTEM ================================
void syscall_create_handler(struct intr_frame *if_) {
  const char *filename = if_->R.rdi;
  check_address((void *)filename);
  unsigned initial_size = (unsigned)if_->R.rsi;

  lock_acquire(&filesys_lock);
  if_->R.rax = filesys_create(filename, initial_size);
  lock_release(&filesys_lock);
}

void syscall_remove_handler(struct intr_frame *if_) {
  const char *filename = if_->R.rdi;
  check_address((void *)filename);

  lock_acquire(&filesys_lock);
  if_->R.rax = filesys_remove(filename);
  lock_release(&filesys_lock);
}

void syscall_open_handler(struct intr_frame *if_) {
  const char *filename = if_->R.rdi;
  check_address((void *)filename);

  lock_acquire(&filesys_lock);
  struct file *fp = filesys_open(filename); 
  if (fp == NULL) {
    if_->R.rax = -1;
  } else {
    if (strcmp(thread_name(), filename) == 0)
      file_deny_write(fp);

    if_->R.rax = process_add_file(fp);

    if ((int)if_->R.rax < 0) {
      file_close(fp);
    }
  }
  lock_release(&filesys_lock);
}

void syscall_filesize_handler(struct intr_frame *if_) {
  // int filesize (int fd);
  /* Returns the size, in bytes, of the file open as fd. */
  int fd = (int)if_->R.rdi;
  int ret = -1;

  struct file *fp = process_get_file(fd);
  if (fp != NULL)
  {
    lock_acquire(&filesys_lock);
    ret = file_length(fp);
    lock_release(&filesys_lock);
  }

  if_->R.rax = ret;
}

void syscall_read_handler(struct intr_frame *if_) {
  // ====================== check validity of arguments ======================
  int fd = (int)if_->R.rdi;
  if (fd < 0) {
    if_->R.rax = -1;
    return;
  }
  void *buffer = if_->R.rsi;
  check_address(buffer);
  unsigned size = (unsigned)if_->R.rdx;
  // =========================================================================
  lock_acquire(&filesys_lock);

  int ret = -1;

  struct file *fp = process_get_file(fd);
  if (fp != NULL)
  {
    if (fp == STDIN) {
      int num_of_bytes_read = 0;
      char key = input_getc();
      while (num_of_bytes_read <= size) {
        *((char *)buffer + (num_of_bytes_read++)) = key;
        key = input_getc();
      }
      ret = num_of_bytes_read;
    }
    else if (fp == STDOUT) {
      ret = -1;
    }
    else {
      ret = (int)file_read(fp, buffer, (off_t)size);
    }
  }

  if_->R.rax = ret;
  lock_release(&filesys_lock);
}

void syscall_write_handler(struct intr_frame *if_) {
  // ===================== check validity of arguments =====================
  struct thread *t = thread_current();
  int fd = (int)if_->R.rdi;
  if (fd < 0) {
    if_->R.rax = -1;
    return;
  }
  const void *buffer = if_->R.rsi;
  check_address(buffer);
  unsigned size = (unsigned)if_->R.rdx;
  // =======================================================================================
  lock_acquire(&filesys_lock);

  int ret = -1;

  struct file *fp = process_get_file(fd);
  if (fp != NULL)
  {
    if (fp == STDOUT) {
      putbuf(buffer, size);
      ret = size;
    }
    else if (fp == STDIN) {
      ret = -1;
    }
    else {
      ret = (int)file_write(fp, buffer, (off_t)size);
    }
  }

  if_->R.rax = ret;
  lock_release(&filesys_lock);
}

void syscall_seek_handler(struct intr_frame *if_) {
  int fd = (int)if_->R.rdi;
  unsigned poistion = (unsigned)if_->R.rsi;

  struct file *fp = process_get_file(fd);

  lock_acquire(&filesys_lock);
  if (fp && fp != STDIN && fp != STDOUT) {
    file_seek(
        fp,
        (off_t)poistion);
  }
  lock_release(&filesys_lock);
}

void syscall_tell_handler(struct intr_frame *if_) {
  int fd = (int)if_->R.rdi;

  struct file *fp = process_get_file(fd);
  lock_acquire(&filesys_lock);
  if_->R.rax = file_tell(fp);
  lock_release(&filesys_lock);
}

void syscall_close_handler(struct intr_frame *if_) {
  int fd = (int)if_->R.rdi;

  lock_acquire(&filesys_lock);
  process_close_file(fd);
  lock_release(&filesys_lock);
}


void syscall_dup2_handler(struct intr_frame *if_) {
  struct thread * curr = thread_current();
  int oldfd = (int)if_->R.rdi;
  int newfd = (int)if_->R.rsi;
  struct file * fp;
  struct fd_entry * entry;

  if (oldfd < 0 || newfd < 0) {
    if_->R.rax = -1;
    return;
  }

  if (oldfd == newfd) {
    if_->R.rax = newfd;
    return;
  }

  lock_acquire(&filesys_lock);

  fp = process_get_file(oldfd);
  if (!fp) {
    if_->R.rax = -1;
    lock_release(&filesys_lock);
    return;
  }

  entry = malloc(sizeof(struct fd_entry));
  if (!entry) {
    if_->R.rax = -1;
    lock_release(&filesys_lock);
    return;
  }
  entry->fd = newfd;
  entry->fp = fp;
  process_close_file(newfd);
  list_push_back(&curr->fd_list, &entry->file_elem);
  curr->file_num++;

  lock_release(&filesys_lock); 
}

// ==============================================================================
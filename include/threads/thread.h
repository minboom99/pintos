#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>

#include "threads/interrupt.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif

/* States in a thread's life cycle. */
enum thread_status {
  THREAD_RUNNING, /* Running thread. */
  THREAD_READY,   /* Not running but ready to run. */
  THREAD_BLOCKED, /* Waiting for an event to trigger. */
  THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */

#define STDIN_CLOSED 0x01 /* a flag indicating stdin closed (no input_getc) */
#define STDOUT_CLOSED 0x02 /* a flag indicating stdout closed (no putbuf) */

#define FILE_DESCRIPTORS_TABLE_SIZE 128

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
  /* Owned by thread.c. */
  tid_t tid;                 /* Thread identifier. */
  enum thread_status status; /* Thread state. */
  char name[16];             /* Name (for debugging purposes). */
  int priority;              /* Priority. */
  int p_donation;            /* Priority received by donation. */

  struct list lock_waiting_thread_ls; /* List of threads that trying to aquire
                                         it's lock */
  struct list_elem
      lock_waiting_thread_ls_e; /* list_elem for lock_waiting_thread_ls */

  struct lock *lock_waiting; /* The lock it tryies to aquire */

  /* Shared between thread.c and synch.c. */
  struct list_elem elem; /* List element. */

  int nice;
  int recent_cpu; /* Shoulde be fp value */
  struct list_elem all_th_ls_e;

  /* ========================== About Process Control ==========================
   */
  struct list child_ls;     /* list of child processes */
  struct list_elem child_e; /* element for child_ls */

  struct thread *parent; /* parent thread */
  struct thread
      *waiting_child; /* current waiting child (set by wait() syscall) */

  struct semaphore wait_sema; /* semaphore for wait() system call */
  // struct semaphore load_sema; 		/* semaphore for calling load()
  // */
  int exit_status; /* exit status */
  bool is_terminated;
  /* ===========================================================================
   */

  /* ========================== About File system ========================== */
  struct file
      *fd_table[FILE_DESCRIPTORS_TABLE_SIZE]; /* 파일 객체 포인터의 배열 */
#ifdef EXTRA2
  uint8_t
      std_flags; /* flags indicates whether stdin, stdout are closed or not */
#endif
  /*======================================================================== */

#ifdef USERPROG
  /* Owned by userprog/process.c. */
  uint64_t *pml4; /* Page map level 4 */
#endif
#ifdef VM
  /* Table for whole virtual memory owned by thread. */
  struct supplemental_page_table spt;
#endif

  /* Owned by thread.c. */
  struct intr_frame tf; /* Information for switching */
  unsigned magic;       /* Detects stack overflow. */
  int64_t wakeup_tick;

  struct intr_frame *if_ /* used for _do_fork() */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void do_iret(struct intr_frame *tf);

void thread_sleep(struct thread *);
void thread_wake(int64_t);

void give_donate(struct thread *);
void refresh_donation(void);
void remove_from_lock_ls(struct lock *);

void mlfqs_priority(struct thread *);
void mlfqs_recent_cpu(struct thread *);
void mlfqs_load_avg(void);
void mlfqs_increment(void);
void mlfqs_priority_all(void);
void mlfqs_recent_cpu_all(void);

#endif /* threads/thread.h */

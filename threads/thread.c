#include "threads/thread.h"

#include <debug.h>
#include <random.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "threads/malloc.h"
#include "intrinsic.h"
#include "threads/fixed_point.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#include "userprog/syscall.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

#define NICE_DEFAULT 0       /* Default nice value*/
#define RECENT_CPU_DEFAULT 0 /* Default recent_cpu value*/
#define LOAD_AVG_DEFAULT 0   /* Default load_avg value*/

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* List of processes in 'sleeping' state. Should wake up after
sleep() time. */
static struct list sleep_list;

/* List of all threads after creation and before destruction */
static struct list all_thread_list;

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4          /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

int load_avg;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *)(pg_round_down(rrsp())))

/* Returns larger integer between a and b */
int max(a, b) { return a > b ? a : b; }

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void) {
  ASSERT(intr_get_level() == INTR_OFF);

  /* Reload the temporal gdt for the kernel
   * This gdt does not include the user context.
   * The kernel will rebuild the gdt with user context, in gdt_init (). */
  struct desc_ptr gdt_ds = {.size = sizeof(gdt) - 1, .address = (uint64_t)gdt};
  lgdt(&gdt_ds);

  /* Init the globla thread context */
  lock_init(&tid_lock);
  list_init(&ready_list);
  list_init(&destruction_req);
  list_init(&sleep_list);
  list_init(&all_thread_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread();
  init_thread(initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid();
  list_push_back(&all_thread_list, &initial_thread->all_th_ls_e);
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void) {
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init(&idle_started, 0);
  thread_create("idle", PRI_MIN, idle, &idle_started);
  load_avg = LOAD_AVG_DEFAULT;

  /* Start preemptive thread scheduling. */
  intr_enable();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void) {
  struct thread *t = thread_current();

  /* Update statistics. */
  if (t == idle_thread) idle_ticks++;
#ifdef USERPROG
  else if (t->pml4 != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE) intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void) {
  printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
         idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority, thread_func *function,
                    void *aux) {
  struct thread *t;
  tid_t tid;

  ASSERT(function != NULL);

  /* Allocate thread. */
  t = palloc_get_page(PAL_ZERO);
  if (t == NULL) return TID_ERROR;

  /* Initialize thread. */
  init_thread(t, name, priority);
  tid = t->tid = allocate_tid();
  #ifdef USERPROG
  struct fd_entry * stdio;
  stdio = malloc(sizeof(struct fd_entry));
  if (!stdio)
    exit(-1); 
  stdio->fd = 0;
  stdio->fp = (struct file *)0xffffffffffffffff;
  list_push_back(&t->fd_list, &stdio->file_elem);
  stdio = malloc(sizeof(struct fd_entry));
  if (!stdio)
    exit(-1); 
  stdio->fd = 1;
  stdio->fp = (struct file *)0xfffffffffffffffe;
  list_push_back(&t->fd_list, &stdio->file_elem);
  #endif

  /* Call the kernel_thread if it scheduled.
   * Note) rdi is 1st argument, and rsi is 2nd argument. */
  t->tf.rip = (uintptr_t)kernel_thread;
  t->tf.R.rdi = (uint64_t)function;
  t->tf.R.rsi = (uint64_t)aux;
  t->tf.ds = SEL_KDSEG;
  t->tf.es = SEL_KDSEG;
  t->tf.ss = SEL_KDSEG;
  t->tf.cs = SEL_KCSEG;
  t->tf.eflags = FLAG_IF;

  list_push_back(&all_thread_list, &t->all_th_ls_e);

  /* Add to run queue. */
  thread_unblock(t);

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void) {
  ASSERT(!intr_context());
  ASSERT(intr_get_level() == INTR_OFF);
  thread_current()->status = THREAD_BLOCKED;
  schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread *t) {
  enum intr_level old_level;

  ASSERT(is_thread(t));

  old_level = intr_disable();
  ASSERT(t->status == THREAD_BLOCKED);
  list_push_back(&ready_list, &t->elem);
  t->status = THREAD_READY;
  intr_set_level(old_level);
  if (!intr_context()) thread_yield();
}

/* Returns the name of the running thread. */
const char *thread_name(void) { return thread_current()->name; }

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *thread_current(void) {
  struct thread *t = running_thread();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT(is_thread(t));
  ASSERT(t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void) { return thread_current()->tid; }

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void) {
  ASSERT(!intr_context());

#ifdef USERPROG
  process_exit();
#endif

  /* Just set our status to dying and schedule another process.
     We will be destroyed during the call to schedule_tail(). */
  intr_disable();
  do_schedule(THREAD_DYING);
  NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void) {
  struct thread *curr = thread_current();
  enum intr_level old_level;

  ASSERT(!intr_context());

  if (curr->is_terminated) return;

  old_level = intr_disable();
  if (curr != idle_thread) list_push_back(&ready_list, &curr->elem);
  do_schedule(THREAD_READY);
  intr_set_level(old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority) {
  if (thread_mlfqs) return;
  int old_priority = thread_current()->priority;
  thread_current()->priority = new_priority;
  if (old_priority > new_priority) thread_yield();
}

/* Returns the current thread's priority. */
int thread_get_priority(void) {
  return max(thread_current()->priority, thread_current()->p_donation);
}

/*
 * Sets the current thread's nice value to new nice and recalculates the
 * thread's priority based on the new value (see Calculating Priority). If the
 * running thread no longer has the highest priority, yields.
 */
/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED) {
  enum intr_level old_level;
  int old_priority;
  old_level = intr_disable();
  thread_current()->nice = nice;
  // recalculates the thread's priority, and if the running thread no longer has
  // the highest priority, yields
  old_priority = thread_current()->priority;
  mlfqs_priority(thread_current());
  if (thread_current()->priority < old_priority) thread_yield();
  intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int thread_get_nice(void) {
  int nice;
  enum intr_level old_level;
  old_level = intr_disable();
  nice = thread_current()->nice;
  intr_set_level(old_level);
  return nice;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void) {
  int returnVal;
  enum intr_level old_level;
  old_level = intr_disable();
  returnVal = fp_to_int(mult_mixed(load_avg, 100));
  intr_set_level(old_level);
  return returnVal;
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void) {
  int returnVal;
  int recent_cpu;
  enum intr_level old_level;
  old_level = intr_disable();
  recent_cpu = thread_current()->recent_cpu;
  returnVal = fp_to_int(mult_mixed(recent_cpu, 100));
  intr_set_level(old_level);
  return returnVal;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void idle(void *idle_started_ UNUSED) {
  struct semaphore *idle_started = idle_started_;

  idle_thread = thread_current();
  sema_up(idle_started);

  for (;;) {
    /* Let someone else run. */
    intr_disable();
    thread_block();

    /* Re-enable interrupts and wait for the next one.

       The `sti' instruction disables interrupts until the
       completion of the next instruction, so these two
       instructions are executed atomically.  This atomicity is
       important; otherwise, an interrupt could be handled
       between re-enabling interrupts and waiting for the next
       one to occur, wasting as much as one clock tick worth of
       time.

       See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
       7.11.1 "HLT Instruction". */
    asm volatile("sti; hlt" : : : "memory");
  }
}

/* Function used as the basis for a kernel thread. */
static void kernel_thread(thread_func *function, void *aux) {
  ASSERT(function != NULL);

  intr_enable(); /* The scheduler runs with interrupts off. */
  function(aux); /* Execute the thread function. */
  thread_exit(); /* If function() returns, kill the thread. */
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void init_thread(struct thread *t, const char *name, int priority) {
  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);

  memset(t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy(t->name, name, sizeof t->name);
  t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);
  t->priority = priority;
  t->p_donation = 0;
  t->nice = NICE_DEFAULT;
  t->recent_cpu = RECENT_CPU_DEFAULT;
  t->magic = THREAD_MAGIC;
  list_init(&t->lock_waiting_thread_ls);
  list_init(&t->child_ls);
  t->lock_waiting = NULL;
  t->parent = NULL;
  if (t != initial_thread) {
    t->parent = initial_thread;
    list_push_back(&initial_thread->child_ls, &t->child_e);
  }
  t->if_ = NULL;
  #ifdef USERPROG
  list_init(&t->fd_list);
  t->file_num = 2;
  #endif
 
  sema_init(&t->wait_sema, 0);

  t->waiting_child = NULL;
  t->is_terminated = false;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *next_thread_to_run(void) {
  struct thread *t;
  struct list_elem *e;
  struct thread *t_with_highest_p;
  struct list_elem *e_with_highest_p;
  int highest_p = 0;
  if (list_empty(&ready_list))
    return idle_thread;
  else {
    e = list_front(&ready_list);
    t = list_entry(e, struct thread, elem);
    e_with_highest_p = e;
    t_with_highest_p = t;
    while (e != &(ready_list.tail)) {
      t = list_entry(e, struct thread, elem);
      if (max(t->priority, t->p_donation) > highest_p) {
        highest_p = max(t->priority, t->p_donation);
        e_with_highest_p = e;
        t_with_highest_p = t;
      }
      e = e->next;
    }
    list_remove(e_with_highest_p);
    return t_with_highest_p;
  }
}

/* Use iretq to launch the thread */
void do_iret(struct intr_frame *tf) {
  __asm __volatile(
      "movq %0, %%rsp\n"
      "movq 0(%%rsp),%%r15\n"
      "movq 8(%%rsp),%%r14\n"
      "movq 16(%%rsp),%%r13\n"
      "movq 24(%%rsp),%%r12\n"
      "movq 32(%%rsp),%%r11\n"
      "movq 40(%%rsp),%%r10\n"
      "movq 48(%%rsp),%%r9\n"
      "movq 56(%%rsp),%%r8\n"
      "movq 64(%%rsp),%%rsi\n"
      "movq 72(%%rsp),%%rdi\n"
      "movq 80(%%rsp),%%rbp\n"
      "movq 88(%%rsp),%%rdx\n"
      "movq 96(%%rsp),%%rcx\n"
      "movq 104(%%rsp),%%rbx\n"
      "movq 112(%%rsp),%%rax\n"
      "addq $120,%%rsp\n"
      "movw 8(%%rsp),%%ds\n"
      "movw (%%rsp),%%es\n"
      "addq $32, %%rsp\n"
      "iretq"
      :
      : "g"((uint64_t)tf)
      : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void thread_launch(struct thread *th) {
  uint64_t tf_cur = (uint64_t)&running_thread()->tf;
  uint64_t tf = (uint64_t)&th->tf;
  ASSERT(intr_get_level() == INTR_OFF);

  /* The main switching logic.
   * We first restore the whole execution context into the intr_frame
   * and then switching to the next thread by calling do_iret.
   * Note that, we SHOULD NOT use any stack from here
   * until switching is done. */
  __asm __volatile(
      /* Store registers that will be used. */
      "push %%rax\n"
      "push %%rbx\n"
      "push %%rcx\n"
      /* Fetch input once */
      "movq %0, %%rax\n"
      "movq %1, %%rcx\n"
      "movq %%r15, 0(%%rax)\n"
      "movq %%r14, 8(%%rax)\n"
      "movq %%r13, 16(%%rax)\n"
      "movq %%r12, 24(%%rax)\n"
      "movq %%r11, 32(%%rax)\n"
      "movq %%r10, 40(%%rax)\n"
      "movq %%r9, 48(%%rax)\n"
      "movq %%r8, 56(%%rax)\n"
      "movq %%rsi, 64(%%rax)\n"
      "movq %%rdi, 72(%%rax)\n"
      "movq %%rbp, 80(%%rax)\n"
      "movq %%rdx, 88(%%rax)\n"
      "pop %%rbx\n"  // Saved rcx
      "movq %%rbx, 96(%%rax)\n"
      "pop %%rbx\n"  // Saved rbx
      "movq %%rbx, 104(%%rax)\n"
      "pop %%rbx\n"  // Saved rax
      "movq %%rbx, 112(%%rax)\n"
      "addq $120, %%rax\n"
      "movw %%es, (%%rax)\n"
      "movw %%ds, 8(%%rax)\n"
      "addq $32, %%rax\n"
      "call __next\n"  // read the current rip.
      "__next:\n"
      "pop %%rbx\n"
      "addq $(out_iret -  __next), %%rbx\n"
      "movq %%rbx, 0(%%rax)\n"  // rip
      "movw %%cs, 8(%%rax)\n"   // cs
      "pushfq\n"
      "popq %%rbx\n"
      "mov %%rbx, 16(%%rax)\n"  // eflags
      "mov %%rsp, 24(%%rax)\n"  // rsp
      "movw %%ss, 32(%%rax)\n"
      "mov %%rcx, %%rdi\n"
      "call do_iret\n"
      "out_iret:\n"
      :
      : "g"(tf_cur), "g"(tf)
      : "memory");
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void do_schedule(int status) {
  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(thread_current()->status == THREAD_RUNNING);
  while (!list_empty(&destruction_req)) {
    struct thread *victim =
        list_entry(list_pop_front(&destruction_req), struct thread, elem);
    if (!victim->parent) {
      palloc_free_page(victim);
    }
  }
  thread_current()->status = status;
  schedule();
}

static void schedule(void) {
  struct thread *curr = running_thread();
  struct thread *next = next_thread_to_run();

  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(curr->status != THREAD_RUNNING);
  ASSERT(is_thread(next));
  /* Mark us as running. */
  next->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate(next);
#endif

  if (curr != next) {
    /* If the thread we switched from is dying, destroy its struct
 thread. This must happen late so that thread_exit() doesn't
 pull out the rug under itself.
 We just queuing the page free reqeust here because the page is
 currently used bye the stack.
 The real destruction logic will be called at the beginning of the
 schedule(). */
    if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
      ASSERT(curr != next);
      list_push_back(&destruction_req, &curr->elem);
      list_remove(&curr->all_th_ls_e);
    }

    /* Before switching the thread, we first save the information
     * of current running. */
    thread_launch(next);
  }
}

/* Returns a tid to use for a new thread. */
static tid_t allocate_tid(void) {
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire(&tid_lock);
  tid = next_tid++;
  lock_release(&tid_lock);

  return tid;
}

/* Puts a thread into the thread_sleep list. */
void thread_sleep(struct thread *thread) {
  enum intr_level old_level;
  old_level = intr_disable();
  list_push_back(&sleep_list, &thread->elem);
  thread_block();
  intr_set_level(old_level);
}

/* Wakes threads from sleeping */
void thread_wake(int64_t ticks) {
  struct thread *wake_thread;
  struct list_elem *wake_elem;
  struct list_elem *next;
  if (!list_empty(&sleep_list)) {
    wake_elem = list_front(&sleep_list);
    next = wake_elem->next;
    while (wake_elem != &(sleep_list.tail)) {
      if ((wake_thread = list_entry(wake_elem, struct thread, elem))
              ->wakeup_tick <= ticks) {
        list_remove(wake_elem);
        thread_unblock(wake_thread);
      }
      wake_elem = next;
      next = wake_elem->next;
    }
  }
}

/* Donates priority to threads holding lock. */
void give_donate(struct thread *t_donate_from) {
  struct thread *t_donate_to;
  if (t_donate_from->lock_waiting != NULL) {
    t_donate_to = t_donate_from->lock_waiting->holder;
    if (t_donate_to == NULL) return;
    if (max(t_donate_from->priority, t_donate_from->p_donation) >
        max(t_donate_to->priority, t_donate_to->p_donation)) {
      t_donate_to->p_donation =
          max(t_donate_from->priority, t_donate_from->p_donation);
    }
    give_donate(t_donate_to);
  }
}

/* Re-calculate the priority of current thread considering multiple/nested
 * donation after releasing a lock. */
void refresh_donation(void) {
  struct thread *curr = thread_current();
  struct thread *t;
  int p_donation_update = 0;
  if (!list_empty(&curr->lock_waiting_thread_ls)) {
    struct list_elem *e = list_front(&curr->lock_waiting_thread_ls);
    while (e != &curr->lock_waiting_thread_ls.tail) {
      t = list_entry(e, struct thread, lock_waiting_thread_ls_e);
      p_donation_update =
          max(p_donation_update, max(t->priority, t->p_donation));
      e = e->next;
    }
  }
  curr->p_donation = p_donation_update;
}

/* After releasing a lock, remove threads which tried to aquire the lock from
 * lock_waiting_thread_ls. */
void remove_from_lock_ls(struct lock *lock) {
  struct thread *curr = thread_current();
  struct thread *t;
  struct list_elem *e;
  if (!list_empty(&curr->lock_waiting_thread_ls)) {
    e = list_front(&curr->lock_waiting_thread_ls);
    while (e != &curr->lock_waiting_thread_ls.tail) {
      t = list_entry(e, struct thread, lock_waiting_thread_ls_e);
      if (t->lock_waiting == lock) {
        e = list_remove(e);
      } else {
        e = e->next;
      }
    }
  }
}

/* Calculates priority of given thread with mlfqs scheduler */
void mlfqs_priority(struct thread *t) {
  int nice = t->nice;
  int recent_cpu = t->recent_cpu;
  int priority;
  if (t == idle_thread) return;
  // priority = PRI_MAX - (recent_cpu / 4) - (nice * 2)
  priority = fp_to_int_round(sub_mixed(
      sub_fp(int_to_fp(PRI_MAX), div_mixed(recent_cpu, 4)), nice * 2));
  if (priority > PRI_MAX) priority = PRI_MAX;
  if (priority < PRI_MIN) priority = PRI_MIN;
  t->priority = priority;
}

/* Calculates recent_cpu of given thread with mlfqs scheduler */
void mlfqs_recent_cpu(struct thread *t) {
  int new_recent_cpu;                         // should be fp value
  int add_left;                               // should be fp value
  int mult_left, mult_right, twice_load_avg;  // should be fp value
  if (t == idle_thread) return;
  // Calculate  and assign recent_cpu = (2 * load_avg)/(2 * load_avg + 1) *
  // recent_cpu + nice;
  twice_load_avg = mult_mixed(load_avg, 2);
  mult_left = div_fp(
      twice_load_avg,
      add_mixed(twice_load_avg, 1));  // (2 * load_avg)/(2 * load_avg + 1)
  mult_right = t->recent_cpu;         // recent_cpu
  add_left = mult_fp(
      mult_left, mult_right);  // (2 * load_avg)/(2 * load_avg + 1) * recent_cpu
  new_recent_cpu = add_mixed(add_left, t->nice);  // nice is int
  t->recent_cpu = new_recent_cpu;
}

/* Calculates load_avg with mlfqs scheduler */
void mlfqs_load_avg(void) {
  int ready_threads;
  int new_load_avg;
  ready_threads = list_size(&ready_list);
  if (thread_current() != idle_thread) ready_threads++;
  // load_avg = (59/60) * load_avg + (1/60) * ready_threads
  new_load_avg = add_fp(mult_fp(div_mixed(int_to_fp(59), 60), load_avg),
                        mult_mixed(div_mixed(int_to_fp(1), 60), ready_threads));
  load_avg = new_load_avg;
}

/* Increases recent_cpu by 1 */
void mlfqs_increment(void) {
  int recent_cpu;
  struct thread *curr = thread_current();
  if (thread_current() == idle_thread) return;
  recent_cpu = thread_current()->recent_cpu;
  thread_current()->recent_cpu = add_mixed(recent_cpu, 1);
}

/* Calculates priority of all threads in all_thread_list with mlfqs scheduler */
void mlfqs_priority_all(void) {
  struct list_elem *temp_thread_el;
  struct thread *temp_thread;
  for (temp_thread_el = list_begin(&all_thread_list);
       temp_thread_el != list_tail(&all_thread_list);
       temp_thread_el = list_next(temp_thread_el)) {
    temp_thread = list_entry(temp_thread_el, struct thread, all_th_ls_e);
    mlfqs_priority(temp_thread);
  }
}

/* Calculates recent_cpu of all threads in all_thread_list with mlfqs scheduler
 */
void mlfqs_recent_cpu_all(void) {
  struct list_elem *temp_thread_el;
  struct thread *temp_thread;
  for (temp_thread_el = list_begin(&all_thread_list);
       temp_thread_el != list_tail(&all_thread_list);
       temp_thread_el = list_next(temp_thread_el)) {
    temp_thread = list_entry(temp_thread_el, struct thread, all_th_ls_e);
    mlfqs_recent_cpu(temp_thread);
  }
}
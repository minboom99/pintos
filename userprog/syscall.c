#include "userprog/syscall.h"
#include "userprog/process.h"
#include "lib/kernel/stdio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/palloc.h"
#include <syscall-nr.h>
#include <devices/input.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

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

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

// #define STATUS_ARR_SIZE 100
// #define SEMAPHORE_ARR_SIZE 100

// struct lock syscall_lock;

// int status_arr[STATUS_ARR_SIZE] = {
// 	0,
// };

// struct semaphore *semaphore_arr[SEMAPHORE_ARR_SIZE];

void check_address(const void *addr)
{
	/*  
		* A user can pass a null pointer, a pointer to unmapped virtual memory, 
		* or a pointer to kernel virtual address space (above KERN_BASE). 
		* All of these types of invalid pointers must be rejected 
		* without harm to the kernel or other running processes, 
		* by terminating the offending process and freeing its resources. 
		* For example, suppose that your system call has acquired a lock or allocated memory with malloc().
		* If you encounter an invalid user pointer afterward, 
		* you must still be sure to release the lock or free the page of memory(thread_exit에서 해줌). 
	*/

	uint64_t *pml4 = thread_current()->pml4;
	if (addr)
		if (is_user_vaddr(addr))
			if (pml4_get_page(pml4, addr))
				return;
	exit(-1);
}

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	// lock_init(&syscall_lock);
	lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *if_ UNUSED)
{
	// lock_acquire(&syscall_lock);
	int syscall_num = if_->R.rax;
	switch (syscall_num)
	{
	case SYS_HALT:
	{
		syscall_halt_handler();
		break;
	}
	case SYS_EXIT:
	{
		syscall_exit_handler(if_);
		break;
	}
	case SYS_FORK:
	{
		syscall_fork_handler(if_);
		break;
	}
	case SYS_EXEC:
	{
		syscall_exec_handler(if_);
		break;
	}
	case SYS_WAIT:
	{
		syscall_wait_handler(if_);
		break;
	}
	case SYS_CREATE:
	{
		syscall_create_handler(if_);
		break;
	}
	case SYS_REMOVE:
	{
		syscall_remove_handler(if_);
		break;
	}
	case SYS_OPEN:
	{
		syscall_open_handler(if_);
		break;
	}
	case SYS_FILESIZE:
	{
		syscall_filesize_handler(if_);
		break;
	}
	case SYS_READ:
	{
		syscall_read_handler(if_);
		break;
	}
	case SYS_WRITE:
	{
		syscall_write_handler(if_);
		break;
	}
	case SYS_SEEK:
	{
		syscall_seek_handler(if_);
		break;
	}
	case SYS_TELL:
	{
		syscall_tell_handler(if_);
		break;
	}
	case SYS_CLOSE:
	{
		syscall_close_handler(if_);
		break;
	}
	}
	// lock_release(&syscall_lock);
}

void syscall_halt_handler()
{
	// void halt (void);
	// Terminates Pintos by calling power_off()
	power_off();
}

void syscall_exit_handler(struct intr_frame *if_)
{
	// void exit (int status);
	/* 
	 * Terminates the current user program, returning status to the kernel. 
	 * If the process's parent waits for it (see below), this is the status that will be returned. 
	 * Conventionally, a status of 0 indicates success and nonzero values indicate errors. 
	 * Whenever a user process terminates, because it called exit or for any other reason,
	 * print the process's name and exit code
	 */

	int status = (int)if_->R.rdi;
	exit(status);
}

void exit(int status)
{
	struct thread *t = thread_current();
	t->exit_status = status;
	/*
	 * 1. t에 child가 존재하는지 판단.
	 * 2. 존재한다면, 각각의 child에 대하여(loop) child가 terminated 상태라면 free를 해준다. 
	 * 아니라면, child의 parent를 NULL로 할당해준다.
	 */
	while (!list_empty(&t->child_ls))
	{
		struct thread *child =
			list_entry(list_pop_front(&t->child_ls), struct thread, child_e);
		if (child->is_terminated)
		{
			palloc_free_page(child);
		}
		else
		{
			child->parent = NULL;
		}
	}
	printf("%s: exit(%d)\n", t->name, t->exit_status);
	
	// if (lock_held_by_current_thread(&syscall_lock))
	// 	lock_release(&syscall_lock);
	thread_exit();
}

void syscall_fork_handler(struct intr_frame *if_)
{
	// pid_t fork (const char *thread_name);
	/*
	 * Create new process which is the clone of current process with the name THREAD_NAME. 
	 *
	 * You don't need to clone the value of the registers except %RBX, %RSP, %RBP, and %R12 - %R15, 
	 * which are callee-saved registers. 
	 * 
	 * Must return pid of the child process, otherwise shouldn't be a valid pid. 
	 * 
	 * In child process, the return value should be 0. The child should have DUPLICATED resources 
	 * including file descriptor and virtual memory space. 
	 * 
	 * Parent process should never return from the fork until it knows whether the child process successfully cloned. 
	 * 
	 * That is, if the child process fail to duplicate the resource, the fork () call of parent
	 * should return the TID_ERROR. 
	 * 
	 * The template utilizes the pml4_for_each() in threads/mmu.c to copy entire user memory space,
	 * including corresponding pagetable structures, but you need to fill missing parts of 
	 * passed pte_for_each_func (See virtual address).
	 */

	// Check validity of the pointer argument
	const char *thr_name = if_->R.rdi;
	int tid;
	check_address((void *)thr_name);
	// Create new process which is the clone of current process with the name THREAD_NAME.
	struct thread *thr_current = thread_current();
	if_->R.rax = 0;
	thr_current->if_ = if_;
	tid = process_fork(thr_name, if_);
	thr_current->if_ = NULL;
	if_->R.rax = tid;
}

void syscall_exec_handler(struct intr_frame *if_)
{
	// int exec (const char *cmd_line);
	char *cmd_line = if_->R.rdi;
	char *name = palloc_get_page(0);
	if (!name)
	{
		if_->R.rax = -1;
		return;
	}
	strlcpy(name, cmd_line, PGSIZE);
	int ret = process_exec(name);
	if_->R.rax = ret; // Not reached on success.
}

void syscall_wait_handler(struct intr_frame *if_)
{
	// int wait (pid_t pid);
	/* ========================== <PLAN> ==========================
		0. pid에 해당하는 child가 존재하는지 검색 => 없으면 -1 return (V)
		1. pid에 해당하는 child가 terminated 상태인지 확인 (V)
		2-1. (terminated) Child를 free해주기 + child를 list에서 제거 + child의 exit status를 return (V)
		2-2. (not terminated) pid에 해당하는 child를 waiting_child로 할당하기 + sema_down (V)
		(sema down 밑부분)
		3. child가 terminated 되었는지 다시 확인 (ASSERT) (V)
		4. child를 free해주기 + child를 list에서 제거 (V)
		5. child의 exit status를 return(V)
	*/
	tid_t pid = (tid_t)if_->R.rdi;
	if_->R.rax = process_wait(pid);
}
// ================================ FILE SYSTEM ================================
void syscall_create_handler(struct intr_frame *if_)
{
	// bool create (const char *file, unsigned initial_size);
	/* 
	 * Creates a new file called file initially initial_size bytes in size. 
	 * Returns true if successful, false otherwise. 
	 * Creating a new file does not open it: 
	 * opening the new file is a separate operation which would require a open system call.
	 */
	const char *filename = if_->R.rdi;
	check_address((void *)filename);
	unsigned initial_size = (unsigned)if_->R.rsi;

	lock_acquire(&filesys_lock);
	if_->R.rax = filesys_create(filename, initial_size);
	lock_release(&filesys_lock);
}

void syscall_remove_handler(struct intr_frame *if_)
{
	// bool remove (const char *file);
	/*
	 * Deletes the file called file. Returns true if successful, false otherwise. 
	 * A file may be removed regardless of whether it is open or closed,
	 * and removing an open file does not close it. See Removing an Open File in FAQ for details.
	 * 
	 * You should implement the standard Unix semantics for files. 
	 * That is, when a file is removed, any process which has a file descriptor 
	 * for that file may continue to use that descriptor. 
	 * This means that they can read and write from the file. The file will not have a name, 
	 * and no other processes will be able to open it, but it will continue to exist 
	 * until all file descriptors referring to the file are closed or the machine shuts down.
	 */
	const char *filename = if_->R.rdi;
	check_address((void *)filename);

	lock_acquire(&filesys_lock);
	if_->R.rax = filesys_remove(filename);
	lock_release(&filesys_lock);
}

void syscall_open_handler(struct intr_frame *if_)
{
	// int open (const char *file);
	/*
	 * Opens the file called file.
	 *
	 * Returns a nonnegative integer handle called a "file descriptor" (fd),
	 * or -1 if the file could not be opened. 
	 * 
	 * File descriptors numbered 0 and 1 are reserved for the console: 
	 * fd 0 (STDIN_FILENO) is standard input,
	 * fd 1 (STDOUT_FILENO) is standard output. 
	 * The open system call will never return either of these file descriptors,
	 * which are valid as system call arguments only as explicitly described below.
	 *  
	 * Each process has an independent set of file descriptors. 
	 * File descriptors are inherited by child processes. 
	 * 
	 * When a single file is opened more than once, whether by a single process or different processes, 
	 * each open returns a new file descriptor. 
	 * Different file descriptors for a single file are closed independently in separate calls to close
	 * and they do not share a file position. 
	 * 
	 * You should follow the linux scheme, which returns integer starting from zero, to do the extra.
	 */
	const char *filename = if_->R.rdi;
	check_address((void *)filename);

	lock_acquire(&filesys_lock);
	struct file *fp = filesys_open(filename); // 파일을 open
	if (fp == NULL)
	{
		if_->R.rax = -1; // 해당 파일이 존재하지 않으면 -1 리턴
	}
	else
	{
		if_->R.rax = process_add_file(fp); // 해당 파일 객체에 fd부여, fd리턴
	}
	lock_release(&filesys_lock);
}

void syscall_filesize_handler(struct intr_frame *if_)
{
	// int filesize (int fd);
	/* Returns the size, in bytes, of the file open as fd. */
	int fd = (int)if_->R.rdi;
	int ret = -1;

	struct file *fp = process_get_file(fd); // fd를 이용하여 파일 객체 검색
	if (fp != NULL)							// 해당 파일이 존재하지 않으면 -1 리턴
	{
		lock_acquire(&filesys_lock);
		ret = file_length(fp); // 해당 파일의 길이를 리턴
		lock_release(&filesys_lock);
	}

	if_->R.rax = ret;
}

void syscall_read_handler(struct intr_frame *if_)
{
	// int read (int fd, void *buffer, unsigned size);
	/*
	 * Reads size bytes from the file open as fd into buffer. 
	 *
	 * Returns the number of bytes actually read (0 at end of file), 
	 * or -1 if the file could not be read (due to a condition other than end of file).
	 * fd 0 reads from the keyboard using input_getc().
	 */
	// ============================= check validity of arguments =============================
	int fd = (int)if_->R.rdi;
	if (fd < 0)
	{
		if_->R.rax = -1;
		return;
	}
	void *buffer = if_->R.rsi;
	check_address(buffer);
	unsigned size = (unsigned)if_->R.rdx;
	// =======================================================================================
	lock_acquire(&filesys_lock);

	int ret = -1;
	if (fd == 0)
	{
		// reads from the keyboard using input_getc().
		int num_of_bytes_read = 0;
		char key = input_getc();
		while (num_of_bytes_read <= size)
		{
			*((char *)buffer + (num_of_bytes_read++)) = key;
			key = input_getc();
		}
		ret = num_of_bytes_read;
	}
	else if (fd >= 2)
	{
		struct file *fp = process_get_file(fd);
		if (fp != NULL) // 해당 파일이 존재하지 않으면 -1 리턴
		{
			ret = (int)file_read(fp, buffer, (off_t)size);
		}
		else 
		{
			ret = -1;
		}
	}
	if_->R.rax = ret;

	lock_release(&filesys_lock);
}

void syscall_write_handler(struct intr_frame *if_)
{
	// int write (int fd, const void *buffer, unsigned size);
	/*
	 * Writes size bytes from buffer to the open file fd.
	 *
	 * Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
	 * 
	 * Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. 
	 * The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, 
	 * or 0 if no bytes could be written at all. 
	 * 
	 * fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(), 
	 * at least as long as size is not bigger than a few hundred bytes (It is reasonable to break up larger buffers). 
	 * Otherwise, lines of text output by different processes may end up interleaved on the console, 
	 * confusing both human readers and our grading scripts.
	 */
	// ============================= check validity of arguments =============================
	int fd = (int)if_->R.rdi;
	if (fd < 0)
	{
		if_->R.rax = -1;
		return;
	}
	const void *buffer = if_->R.rsi;
	check_address(buffer);
	unsigned size = (unsigned)if_->R.rdx;
	// =======================================================================================
	lock_acquire(&filesys_lock);

	int ret = -1;
	if (fd == 1)
	{
		// writes to the console using putbuf().
		putbuf(buffer, size);
		ret = size;
	}
	else if (fd >= 2)
	{
		struct file *fp = process_get_file(fd);
		if (fp != NULL) // 해당 파일이 존재하지 않으면 -1 리턴
		{
			ret = (int)file_write(fp, buffer, (off_t)size);
		}
	}
	if_->R.rax = ret;

	lock_release(&filesys_lock);
}

void syscall_seek_handler(struct intr_frame *if_)
{
	// void seek (int fd, unsigned position);
	/*
	 * Changes the next byte to be read or written in open file fd to position, 
	 * expressed in bytes from the beginning of the file (Thus, a position of 0 is the file's start). 
	 * 
	 * A seek past the current end of a file is not an error. 
	 * A later read obtains 0 bytes, indicating end of file. 
	 * A later write extends the file, filling any unwritten gap with zeros. 
	 * (However, in Pintos files have a fixed length until project 4 is complete, 
	 * so writes past end of file will return an error.) 
	 * 
	 * These semantics are implemented in the file system and do not require any special effort in system call implementation.
	 */
	int fd = (int)if_->R.rdi;
	unsigned poistion = (unsigned)if_->R.rsi;

	struct file *fp = process_get_file(fd); // fd를 이용하여 파일 객체 검색

	lock_acquire(&filesys_lock);
	file_seek(fp, (off_t)poistion); // 해당 열린 파일의 위치(offset)를 position만큼 이동
	lock_release(&filesys_lock);
}

void syscall_tell_handler(struct intr_frame *if_)
{
	// unsigned tell (int fd);
	/*
	 * Returns the position of the next byte to be read or written in open file fd, 
	 * expressed in bytes from the beginning of the file.
	 */
	int fd = (int)if_->R.rdi;

	struct file *fp = process_get_file(fd); // fd를 이용하여 파일 객체 검색
	lock_acquire(&filesys_lock);
	if_->R.rax = file_tell(fp); // 해당 파일의 위치(offset)를 반환
	lock_release(&filesys_lock);
}

void syscall_close_handler(struct intr_frame *if_)
{
	// void close (int fd);
	/*
	 * Closes file descriptor fd.
	 * Exiting or terminating a process implicitly closes all its open file descriptors, 
	 * as if by calling this function for each one.
	 */
	int fd = (int)if_->R.rdi;

	struct file *fp = process_get_file(fd); // fd를 이용하여 파일 객체 검색
	lock_acquire(&filesys_lock);
	process_close_file(fd);
	lock_release(&filesys_lock);
}
// ==============================================================================
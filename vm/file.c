/* file.c: Implementation of memory backed file object (mmaped object). */
#include <string.h>
#include <round.h>

#include "vm/vm.h"
#include "threads/mmu.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "threads/malloc.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

static bool lazy_mmap_segment(struct page *page, void *aux);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
  void *va = page->va;

	struct file_page *file_page UNUSED = &page->file;
  struct file *fp = file_page->fp;
  off_t ofs = file_page->ofs;
  size_t page_read_bytes = file_page->page_read_bytes;
  bool is_holder = lock_held_by_current_thread(&filesys_lock);

  if (!is_holder)
    lock_acquire(&filesys_lock);
  file_read_at(fp, kva, page_read_bytes, ofs);
  if (!is_holder)
    lock_release(&filesys_lock);

  pml4_set_accessed(thread_current()->pml4, va, file_page->accessed);
  pml4_set_dirty(thread_current()->pml4, va, false);
  return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
  void *va = page->va;
  struct frame *frame = page->frame;
  void *kva = frame->kva;

	struct file_page *file_page = &page->file;
  struct file *fp = file_page->fp;
  off_t ofs = file_page->ofs;
  size_t page_read_bytes = file_page->page_read_bytes;
  bool is_dirty = pml4_is_dirty(thread_current()->pml4, va);
  bool is_holder = lock_held_by_current_thread(&filesys_lock);

  if (is_dirty) {
    if (!is_holder)
      lock_acquire(&filesys_lock);
    file_write_at(fp, kva, page_read_bytes, ofs);
    if (!is_holder)
      lock_release(&filesys_lock);
  }

  file_page->accessed = pml4_is_accessed(thread_current()->pml4, va);
  pml4_clear_page(thread_current()->pml4, va);

  page->frame = NULL;
  return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
  // write back => vm_entry 가리키는 가상 주소에 대한 물리 페이지가 존재하고,
  // dirty하면 디스크에 메모리 내용을 기록
  void *va = page->va;
  struct frame *frame = page->frame;
  void *kva;

  struct file_page *file_page = &page->file;
  struct file *fp = file_page->fp;
  off_t ofs = file_page->ofs;
  size_t page_read_bytes = file_page->page_read_bytes;
  bool is_dirty;

  if (frame) {
    kva = frame->kva;
    is_dirty = pml4_is_dirty(thread_current()->pml4, va);
    if (is_dirty) {
      lock_acquire(&filesys_lock);
      file_write_at(fp, kva, page_read_bytes, ofs);
      lock_release(&filesys_lock);
    }

    list_remove(&frame->frame_list_elem);
    palloc_free_page(kva);
    free(frame);
    pml4_clear_page(thread_current()->pml4, va);
  }
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
  size_t file_len = file_length(file) - offset;
  size_t read_bytes = file_len > length ? length : file_len;
  size_t zero_bytes = (ROUND_UP(length, PGSIZE) - read_bytes);
  void *upage = addr;
  
  struct file *file_cpy = file_reopen(file);
    
  if (!file_cpy) 
    return NULL;
  
	struct mmap_file *mmap_file = malloc(sizeof(struct mmap_file));
	if (!mmap_file) {
		file_close(file_cpy);
		return NULL;
	}

	struct page *prev_page = NULL;
	struct page *cur_page = NULL;

	mmap_file->fp = file_cpy;

  while (read_bytes > 0 || zero_bytes > 0) {
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* TODO: Set up aux to pass information to the lazy_mmap_segment. */
    struct mmap_aux *aux = NULL;
    aux = malloc(sizeof(struct mmap_aux)); /* mmap_aux 생성 (malloc 사용) */
    if (aux == NULL) {
			file_close(file_cpy);
			free(mmap_file);
      return NULL;
    }

    /* struct page 멤버들 설정, 가상페이지가 요구될 때 읽어야 할 파일의 오프셋과
      사이즈, 마지막에 패딩할 제로 바이트 등등 */
    aux->fp = file_cpy;
    aux->page_read_bytes = page_read_bytes;
    aux->page_zero_bytes = page_zero_bytes;
    aux->ofs = offset;

    if (!vm_alloc_page_with_initializer(VM_FILE, upage, writable, lazy_mmap_segment, aux)) {
			while (addr < upage) {
				struct page *page_destroy = spt_find_page(&thread_current()->spt, addr);
				spt_remove_page(&thread_current()->spt, page_destroy); // TODO : file_backed destroy 내부 구현
				addr += PGSIZE;
			}
			file_close(file_cpy);
      free(mmap_file);
      free(aux);
      return NULL;
    }

		cur_page = spt_find_page(&thread_current()->spt, upage);
		if (prev_page) {
			prev_page->next_page = cur_page;
		}
		prev_page = cur_page;

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
    offset += page_read_bytes;
  }

	cur_page = spt_find_page(&thread_current()->spt, addr);
	mmap_file->file_page_head = cur_page;
	list_push_back(&thread_current()->mmap_list, &mmap_file->mmap_list_elem);

  return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
  // Unmaps the mapping for the specified address range addr, which must be the
  // virtual address returned by a previous call to mmap by the same process
  // that has not yet been unmapped.

  /* ================= <PLAN> =================
   * 1. addr에 해당하는 page를 찾는다. => 없으면? 그냥 끝
   * 2. page의 type이 file이거나, file이 될 예정인 uninit인지 확인 => 아니면
   * 그냥 끝
   * 3. page에 있는 file포인터 fp 겟또다제
   * 4. fp를 이용해 thread에 있는 mmap_file_list로부터 제거
   * 5. page_head부터 시작해서 next_page 포인터를 따라서 쭉 spt_remove_page() 호출
   * (spt에서 제거되고 page도 destroy됨)
   * 6. file_close(fp)
   * 번외: file page destroyer 만들기 (file write back 등 넣어야 됨)
   * 
   */

  struct thread *t = thread_current();
  struct supplemental_page_table *spt = &t->spt;
  struct page *page = spt_find_page(spt, addr);
  struct page *next_page;
  enum vm_type type;
  struct file *fp;
  struct mmap_aux *aux;
  struct list_elem * e;
  struct mmap_file *mmap_file;
  
  // ================= STEP 1 =================
  if (!page)
    return;
  // ================= STEP 2 =================
  type = page_get_type(page);
  if (type != VM_FILE)
    return;
  // ================= STEP 3 =================
  type = VM_TYPE(page->operations->type);
  if (type == VM_FILE) {
    fp = page->file.fp;
  } else {
    // VM_UNINIT
    aux = page->uninit.aux;
    fp = aux->fp;
  }
  // ================= STEP 4 =================
  for (e = list_begin(&t->mmap_list); e != list_end(&t->mmap_list); e = list_next(e)) {
    mmap_file = list_entry(e, struct mmap_file, mmap_list_elem);
    if (mmap_file->fp == fp) {
      list_remove(e);
      break;
    }
  }
  // ================= STEP 5 =================
  page = mmap_file->file_page_head;
  while (page) {
    next_page = page->next_page;
    spt_remove_page(spt, page);
    page = next_page;
  }
  // ================= STEP 6 =================
  file_close(fp);
}

/* page fault가 났을 때, mmap_file이랑 관련된 page였으면 불리는 함수 (lazy loading) */
static bool lazy_mmap_segment(struct page *page, void *aux) {
  ASSERT(aux);
  ASSERT(page);

  // mmap_aux 해체
  struct mmap_aux *mmap_aux = (struct mmap_aux *)aux;
  struct file *file = mmap_aux->fp;
  size_t page_read_bytes = mmap_aux->page_read_bytes;
  size_t page_zero_bytes = mmap_aux->page_zero_bytes;
  off_t ofs = mmap_aux->ofs;

  void *kva = page->frame->kva;
  // =====================================================================
  bool is_holder = lock_held_by_current_thread(&filesys_lock);
  free(aux); // 넌 더 이상 쓸모가 없다. 이제, 죽어라.

  if (!is_holder) lock_acquire(&filesys_lock);
  /* Load this page. */
  file_seek(file, ofs);
  int bytes = file_read(file, kva, page_read_bytes);
  if (!is_holder) lock_release(&filesys_lock);

  if (bytes != (int)page_read_bytes) return false;

  memset(kva + page_read_bytes, 0, page_zero_bytes);
  pml4_set_dirty(thread_current()->pml4, page->va, false);
  pml4_set_accessed(thread_current()->pml4, page->va, false);

  // 이걸 initializer에서 할 수가 없어서 여기서 함
  page->file.fp = file;
  page->file.page_read_bytes = page_read_bytes;
  page->file.page_zero_bytes = page_zero_bytes;
  page->file.ofs = ofs;

  return true;
}

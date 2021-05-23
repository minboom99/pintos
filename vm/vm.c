/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

#include <hash.h>
#include <string.h>
#include "threads/mmu.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
  list_init(&frame_list);
  lock_init(&frame_list_lock);
  frame_list_cursor = NULL;
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux) {
  ASSERT(VM_TYPE(type) != VM_UNINIT);

  struct supplemental_page_table *spt = &thread_current()->spt;

  /* Check wheter the upage is already occupied or not. */
  if (spt_find_page(spt, upage) == NULL) {
    /* TODO: Create the page, fetch the initialier according to the VM type,
     * TODO: and then create "uninit" page struct by calling uninit_new. You
     * TODO: should modify the field after calling the uninit_new. */

    struct page *newpage = malloc(sizeof(struct page));
    if (newpage == NULL) {
      return false;
    }

    vm_initializer *initiazlier;
    switch (VM_TYPE(type)) {
      case VM_ANON: {
        initiazlier = anon_initializer;
      } break;
      case VM_FILE: {
        initiazlier = file_backed_initializer;
      } break;
        // case VM_PAGE_CACHE:
        // break;
      default: {
        free(newpage);
        goto err;
      } break;
    }
    uninit_new(newpage, upage, init, type, aux, initiazlier);
    newpage->writable = writable;
    newpage->next_page = NULL;
    newpage->owner_spt = spt;

    /* TODO: Insert the page into the spt. */
    if (!spt_insert_page(spt, newpage)) {
      free(newpage);
      goto err;
    }
    return true;
  }
err:
  return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	struct page p;
	struct hash_elem *e;

	va = pg_round_down(va); // vaddr의 페이지 번호 얻기
	p.va = va;

	e = hash_find(&spt->pages, &p.h_elem);
	if (e != NULL) {
		page = hash_entry(e, struct page, h_elem);
	}

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	int succ = false;
	/* TODO: Fill this function. */
	struct page *p = spt_find_page(spt, page->va);
	if (p == NULL) {
		hash_insert (&spt->pages, &page->h_elem);
		succ = true;
	} 

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	hash_delete(&spt->pages, &page->h_elem);
	vm_dealloc_page (page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
  ASSERT(!list_empty(&frame_list));

	struct frame *victim = NULL;
  struct list_elem *e;
	/* TODO: The policy for eviction is up to you. */

  // list 내에 file_page가 존재하는지 찾기
  for (e = list_begin(&frame_list); e != list_end(&frame_list); e = list_next(e)) {
    struct frame *cur_frame = list_entry(e, struct frame, frame_list_elem);
    if (page_get_type(cur_frame->page) == VM_FILE) {
      victim = cur_frame;
      return victim;
    }
  }
  e = list_front(&frame_list);
  victim = list_entry(e, struct frame, frame_list_elem);
  ASSERT(victim);
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
  // Choose a frame to evict, using your page replacement algorithm. The
  // "accessed" and "dirty" bits in the page table, described below, will come
  // in handy.

  // Remove references to the frame from any page table that refers to it.
  // Unless you have implemented sharing, only a single page should refer to a
  // frame at any given time.

  // If necessary, write the page to the file system or to swap. The evicted
  // frame may then be used to store a different page

  /* =================== PLAN ===================
   * 1. file_page가 frame_list에 존재하는지 찾기
   * 2-1. 존재하면? swap_out() 성공할때까지 get_victim(), swap_out() loop 돌린다
   * 2-2. 존재안하면? get_victim() 후 swap_out() 실패하면 바로 PANIC
   * 3. frame_list 내에서 frame 제거하고 physical frame을 memset해준다.
   */
  struct frame *victim = vm_get_victim();

  if (page_get_type(victim->page) == VM_FILE) {
    swap_out(victim->page);
  } else {
    if (!swap_out(victim->page)) 
      PANIC('The Swap disk is full!');
  }

  lock_acquire(&frame_list_lock);
  list_remove(&victim->frame_list_elem);
  lock_release(&frame_list_lock);
  victim->page = NULL;
  memset(victim->kva, 0, PGSIZE);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

	frame = malloc(sizeof(struct frame));
	if (frame == NULL) {
    frame = vm_evict_frame();
	}

	void *phy_addr = palloc_get_page(PAL_USER);
	frame->kva = phy_addr;
	if (phy_addr == NULL) {
    free(frame);
    frame = vm_evict_frame();
	}

	frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr) {
  /*
   * Increases the stack size by allocating one or more anonymous pages so
   * that addr is no longer a faulted address. Make sure you round down
   * the addr to PGSIZE when handling the allocation.
   */
  addr = pg_round_down(addr);  // page 시작 부분으로 round_down
  if (!vm_alloc_page(VM_ANON | VM_STACK, addr, true)) {
    exit(-1);
  }
  if (!vm_claim_page(addr)) {
    exit(-1);
  }
  pml4_set_dirty(thread_current()->pml4, addr, false);
  pml4_set_accessed(thread_current()->pml4, addr, false);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present) {
  /* not_present 	-> True: not-present page, false: writing r/o page. */
  /* write 		-> True: access was write, false: access was read. */
  /* user 		-> True: access by user, false: access by kernel. */

  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *page = NULL;
  /* TODO: Validate the fault */
  /* TODO: Your code goes here */

  if (addr == NULL) exit(-1);

  if (user) thread_current()->user_rsp = f->rsp;

  page = spt_find_page(spt, addr);
  if (page == NULL) {
    // USER_STACK에 대한 접근인지 확인하고, 스택 확장을 해야하는 경우인지
    // 판단해서 vm_stack_growth() 호출 stack에 write하려고 하는 데 공간이 모자른
    // 경우에만 vm_stack_growth() 호출
    if (write) {
      void *rsp = user ? f->rsp : thread_current()->user_rsp;
      if ((addr >= rsp - 8) && is_user_stack_vaddr(addr)) {
        // stack 확장
        vm_stack_growth(addr);
        return true;
      }
    }
    exit(-1);
  }
  if (!page->writable && write && !not_present) exit(-1);

  return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = spt_find_page(&thread_current()->spt, va);
	/* TODO: Fill this function */
	if (page == NULL) 
		return false;
	
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame (); // frame이 NULL이 아닌 건 vm_get_frame()이 체크함

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	bool success = pml4_set_page (thread_current()->pml4, page->va, frame->kva, page->writable);
	if (success == false) {
		vm_dealloc_page(page);
		return false;
	}
  lock_acquire(&frame_list_lock);
  list_push_back(&frame_list, &frame->frame_list_elem);
  lock_release(&frame_list_lock);

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
  hash_init (&spt->pages, page_hash, page_less, NULL);
  lock_init (&spt->hash_lock);
  spt->owner_th = thread_current();
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src) {
  /*
   * Copies the supplemental page table from src to dst. This is used when a
   * child needs to inherit the execution context of its parent (i.e. fork()).
   *
   * Iterate through each page in the src's supplemental page table and make a
   * exact copy of the entry in the dst's supplemental page table. You will need
   * to allocate uninit page and claim them immediately.
   */
  struct hash *spt_src = &src->pages;
  struct hash *spt_dst = &dst->pages;
  struct list *parent_mmap_list = &src->owner_th->mmap_list;
  struct list *child_mmap_list = &dst->owner_th->mmap_list;
  uint64_t *parent_pml4 = src->owner_th->pml4;
  uint64_t *child_pml4 = dst->owner_th->pml4;
  struct list_elem *e;
  struct mmap_file *parent_mmap_file;
  struct mmap_file *child_mmap_file;
  struct page *cur_page;
  struct page *next_page;
  struct page *prev_page;
  void *va;
  struct page *child_page;
  enum vm_type type;
  bool is_uninit;
  bool is_dirty;
  struct file* fp;
  struct file* fp_copy;

  // src의 spt의 element 하나하나를 iteration하면서 동일하게 만든 copy를 dst에
  // 넣기
  struct hash_iterator i;
  hash_first(&i, spt_src);
  while (hash_next(&i)) {
    cur_page = hash_entry(hash_cur(&i), struct page, h_elem);
    va = cur_page->va;
    type = VM_TYPE(cur_page->operations->type);
    is_uninit = (type == VM_UNINIT);
    is_dirty;

    // struct page 복사
    if (is_uninit) {
      type = VM_TYPE(cur_page->uninit.type);

      // aux를 allocation해서 복사된 걸 넣어줘야 함
      vm_initializer *init = cur_page->uninit.page_initializer;
      void *new_aux = NULL;

      // init이 lazy_load_segment, aux는 load_aux
      if (init != NULL) {
        if (type == VM_ANON) {
          // TODO : aux 종류 구분하는 거 넣어야 됨
          new_aux = (void *)malloc(sizeof(struct load_aux));
          if (!new_aux) return false;
          memcpy(new_aux, cur_page->uninit.aux, sizeof(struct load_aux));
        }
        else if (type == VM_FILE) {
          new_aux = (void *)malloc(sizeof(struct mmap_aux));
          if (!new_aux) return false;
          memcpy(new_aux, cur_page->uninit.aux, sizeof(struct mmap_aux));
        }
      }

      if (!vm_alloc_page_with_initializer(type, va, cur_page->writable, init,
                                          new_aux)) {
        return false;  // false를 뱉었으면 caller에서 exit으로 간다
      }
      continue;  // uninit이라 frame claim 하지 않고 여기서 끝
    }
    else {
      if (!vm_alloc_page(type, va, cur_page->writable)) {
        return false;
      }
    }

    child_page = spt_find_page(dst, va);  // vm_claim_page에서 체크됨
    ASSERT(child_page);  // vm_alloc_page()에서 spt_insert_page()의 성공여부를
                         // 체크하므로, 없으면 안된다.

    // struct frame 복사 및 struct page랑 struct frame 연결
    if (!vm_do_claim_page(child_page)) {
      return false;
    }

    // frame 내의 실제 데이터를 복사 (예전 frame 내의 kva에서 새로 만든 kva로
    // 복사)
    memcpy(child_page->frame->kva, cur_page->frame->kva, PGSIZE);
    // thread_current()의 pml4 set page
    if (!pml4_set_page(thread_current()->pml4, va, child_page->frame->kva,
                       child_page->writable)) {
      return false;
    }
    is_dirty = pml4_is_dirty(parent_pml4, va);
    pml4_set_dirty(child_pml4, va, is_dirty);
  }

  // TODO : src->owner_th의 mmap_list를 iteration하면서 dst->owner_th->mmap_list로 정확히 복사하기
  lock_acquire(&filesys_lock);
  for (e = list_begin(parent_mmap_list); e != list_end(parent_mmap_list); e = list_next(e)) {
    parent_mmap_file = list_entry(e, struct mmap_file, mmap_list_elem);
    fp = parent_mmap_file->fp;
    fp_copy = file_duplicate(fp);
    if (!fp_copy) {
      lock_release(&filesys_lock);
      exit(-1);
    }
    child_mmap_file = malloc(sizeof(struct mmap_file));
    if (!child_mmap_file) {
      file_close(fp_copy);
      lock_release(&filesys_lock);
      exit(-1);
    }
    list_push_back(child_mmap_list, &child_mmap_file->mmap_list_elem);
    child_mmap_file->fp = fp_copy;
    cur_page = parent_mmap_file->file_page_head;
    child_page = spt_find_page(spt_dst, cur_page->va);
    child_mmap_file->file_page_head = child_page;
    type = VM_TYPE(cur_page->operations->type);
    is_uninit = (type == VM_UNINIT);
    if (is_uninit) {
      ((struct mmap_aux *) child_page->uninit.aux)->fp = fp_copy;
    }
    else {
      child_page->file.fp = fp_copy;
    }
    cur_page = cur_page->next_page;
    prev_page = child_page;
    while (cur_page) {
      next_page = cur_page->next_page;

      child_page = spt_find_page(spt_dst, cur_page->va);
      type = VM_TYPE(cur_page->operations->type);
      is_uninit = (type == VM_UNINIT);
      if (is_uninit) {
        ((struct mmap_aux *)child_page->uninit.aux)->fp = fp_copy;
      } else {
        child_page->file.fp = fp_copy;
      }
      prev_page->next_page = child_page;

      prev_page = child_page;
      cur_page = next_page;
    }
  }
  lock_release(&filesys_lock);

  return true;
}

/* E를 죽인 page를 부순다. 처음부터 그 생각뿐이었다. */
void
page_destroy (struct hash_elem *e, void *aux) {
	destroy(hash_entry (e, struct page, h_elem));
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

	/*
	 * This function is called when a process exits (process_exit() in userprog/process.c). 
	 * You need to iterate through the page entries and call destroy(page) for the pages in the table. 
	 * You do not need to worry about the actual page table (pml4) and the physical memory (palloc-ed memory) in this function; 
	 * the caller cleans them after the supplemental page table is cleaned up.
	 */
	//lock_acquire(&spt->hash_lock);
	hash_destroy(&spt->pages, page_destroy);
	//lock_release(&spt->hash_lock);
}

unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, h_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, h_elem);
  const struct page *b = hash_entry (b_, struct page, h_elem);

  return a->va < b->va;
}
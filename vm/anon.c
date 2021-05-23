/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */
#include <bitmap.h>

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/mmu.h"
#include "threads/malloc.h"

#define PG_SECTOR_RATIO (PGSIZE / DISK_SECTOR_SIZE)

static struct bitmap *swap_slots_bitmap; // Swap slot들의 free여부를 관리하는 bitmap (swap table에 해당)
static size_t swap_slot_cnt;
static struct lock swap_lock;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	swap_disk = disk_get(1, 1);
	disk_sector_t sector_cnt = disk_size(swap_disk);
	swap_slot_cnt = sector_cnt / PG_SECTOR_RATIO; // swap_dist에는 몇 개의 swap slot이 들어갈 수 있는가?
	swap_slots_bitmap = bitmap_create(swap_slot_cnt);
	bitmap_set_all (swap_slots_bitmap, false); // false면 free, true면 allocated인 걸로
	lock_init(&swap_lock);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	lock_acquire(&swap_lock);
	size_t swap_slot_idx = anon_page->swap_slot_idx;
	bool dirty = anon_page->dirty;
	bool accessed = anon_page->accessed;

	disk_sector_t cur_sector_no = swap_slot_idx * PG_SECTOR_RATIO;
	void *buff = kva;
    for (int i = 0; i < PG_SECTOR_RATIO; i++) {
    	disk_read(swap_disk, cur_sector_no, buff);
		buff += DISK_SECTOR_SIZE;
		cur_sector_no++;
    }
	bitmap_set(swap_slots_bitmap, swap_slot_idx, false);

	pml4_set_dirty(thread_current()->pml4, page->va, dirty);
	pml4_set_accessed(thread_current()->pml4, page->va, accessed);

	lock_release(&swap_lock);
	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	/* =================== PLAN =================== 
	 * 1. swap_slots_bitmap을 이용하여, swap_disk 내에 free한 swap_slot이 있는지 찾기 => 없으면? return false
	 * 2. disk_write()을 이용해 swap_disk에 page의 frame에 있던 데이터를 복사한다. (8번 호출해야 할 거임)
	 * 3. bitmap 수정
	 * 4. anon_page struct 수정 (나중에 swap_in을 할 수 있도록 어느 swap slot에 있는지 저장해두어야 함)
	 * 5. pml4_clear_page(), pml4_is_accessed(), pml4_is_dirty()
	 * 6. return true
	 */
	struct anon_page *anon_page = &page->anon;
	// =================== STEP 1 ===================
	lock_acquire(&swap_lock);
	size_t empty_offset = bitmap_scan (swap_slots_bitmap, 0, 1, false);
	if (empty_offset == BITMAP_ERROR)
		return false;
	// =================== STEP 2 ===================
	disk_sector_t cur_sector_no = empty_offset * PG_SECTOR_RATIO;
	struct frame* frame = page->frame;
	void *kva = frame->kva;
	void *buff = kva;
    for (int i = 0; i < PG_SECTOR_RATIO; i++) {
    	disk_write(swap_disk, cur_sector_no, buff);
		buff += DISK_SECTOR_SIZE;
		cur_sector_no++;
    }
	// =================== STEP 3 ===================
	bitmap_set(swap_slots_bitmap, empty_offset, true);
	lock_release(&swap_lock);
	// =================== STEP 4 ===================
	anon_page->swap_slot_idx = empty_offset;
	// =================== STEP 5 ===================
	anon_page->dirty = pml4_is_dirty(thread_current()->pml4, page->va);
	anon_page->accessed = pml4_is_accessed(thread_current()->pml4, page->va);
	pml4_clear_page(thread_current()->pml4, page->va);
	// =================== STEP 6 ===================
	page->frame = NULL;
	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
  struct anon_page *anon_page = &page->anon;
  void *va = page->va;
  struct frame *frame = page->frame;
  void *kva;

  if (!frame)
    bitmap_set(swap_slots_bitmap, anon_page->swap_slot_idx, false);
  else {
    kva = frame->kva;
    list_remove(&frame->frame_list_elem);
    palloc_free_page(kva);
    free(frame);
    pml4_clear_page(thread_current()->pml4, va);
  }
}

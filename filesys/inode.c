#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/fat.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define FILE -1
#define DIR 0
#define HARD 0
#define LINK 1

/* On-disk inode.
 * Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk {
	disk_sector_t start;                /* First data sector. */
	off_t length;                       /* File size in bytes. */
	unsigned magic;                     /* Magic number. */
#ifdef EFILESYS
	cluster_t start_clst;
	cluster_t inode_clst;
	int32_t entry_cnt;					/* Also Implies whether this is directory or file ("."이랑 ".."은 무시됨) */
	int32_t is_link;
	char target_path[16];			    /* NULL for Hard link, non-NUll value for SOFT link */
	uint32_t unused[117];
#else
	uint32_t unused[125];               /* Not used. */
#endif
};

#ifdef EFILESYS
void get_from_original(struct inode *inode);
void update_original(struct inode *inode);
#endif

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors (off_t size) {
	return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode {
	struct list_elem elem;              /* Element in inode list. */
	disk_sector_t sector;               /* Sector number of disk location. */
	int open_cnt;                       /* Number of openers. */
	bool removed;                       /* True if deleted, false otherwise. */
	int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
	struct inode_disk data;             /* Inode content. */
};

/* Returns the disk sector that contains byte offset POS within
 * INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) {
	ASSERT (inode != NULL);
	/* byte_to_sector() 내부에서는 file을 더 키우지 않는다. */
#ifdef EFILESYS
	/* pos에 해당하는 cluster 찾기 */
	cluster_t clst = inode->data.start_clst;
	while(pos >= DISK_SECTOR_SIZE * SECTORS_PER_CLUSTER) {
		clst = fat_get(clst); // 다음 cluster로 넘어가기
		if (clst == EOChain)
			return -1;
		pos -= DISK_SECTOR_SIZE * SECTORS_PER_CLUSTER;
	}

	return cluster_to_sector(clst);
#else
	if (pos < inode->data.length)
		return inode->data.start + pos / DISK_SECTOR_SIZE;
	else
		return -1;
#endif
}

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) {
	list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * disk.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length) {
	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT (length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);
#ifdef EFILESYS
	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		size_t sectors = bytes_to_sectors (length);
		size_t clusters = (sectors + SECTORS_PER_CLUSTER - 1)/SECTORS_PER_CLUSTER;
		disk_inode->length = length;
		disk_inode->magic = INODE_MAGIC;
		disk_inode->target_path[0] = '\0';
		disk_inode->is_link = HARD;
		cluster_t start_clst = 0;		// 실제 데이터 시작 CLUSTER
		cluster_t cluster = start_clst;					// for iteration

		if (clusters > 0) {
			start_clst = fat_create_chain(0);
			cluster = start_clst;
		} else {
			disk_inode->start = 0;
			disk_inode->start_clst = 0;
			disk_write(filesys_disk, sector, disk_inode);
			success = true;
		}

		if (start_clst != 0) {
			/* inode의 field 값 할당 */
			disk_inode->start = cluster_to_sector(start_clst);
			disk_inode->start_clst = start_clst;
			static char zeros[DISK_SECTOR_SIZE];

			/* 초기화하는 부분 -> cluster 안에 있는 sector 개수만큼 write 해줘야 함 */
			for (size_t j = 0; j < SECTORS_PER_CLUSTER; j++) {
				disk_write(filesys_disk, disk_inode->start + j, zeros);
			}

			/* cluster 개수만큼 chain 연결해주기 */
			for (size_t i = 1; i < clusters; i++) {
				cluster = fat_create_chain(cluster);
				if (cluster == 0) {
					break;
				}
				for (size_t j = 0; j < SECTORS_PER_CLUSTER; j++) {
					disk_write(filesys_disk, cluster_to_sector(cluster) + j, zeros);
				}
			}

			/* 중간에 실패했으면 지금까지 만들었던 것들 다 없애야 함 */
			if (cluster == 0) {
				fat_remove_chain(start_clst, 0);
			}
			/* 전부 성공했으면 inode를 disk에 write */
			else {
				disk_write(filesys_disk, sector, disk_inode);
				success = true;
			}
		}
		free (disk_inode);
	}
	return success;
#else
	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		size_t sectors = bytes_to_sectors (length);
		disk_inode->length = length;
		disk_inode->magic = INODE_MAGIC;
		if (free_map_allocate (sectors, &disk_inode->start)) {
			disk_write (filesys_disk, sector, disk_inode);
			if (sectors > 0) {
				static char zeros[DISK_SECTOR_SIZE];
				size_t i;

				for (i = 0; i < sectors; i++) 
					disk_write (filesys_disk, disk_inode->start + i, zeros); 
			}
			success = true; 
		} 
		free (disk_inode);
	}
	return success;
#endif
}

#ifdef EFILESYS
/* clst에 inode를 생성한다. */
bool
inode_create_with_clst (cluster_t clst, off_t length) {
	/* clst -> sector
	 * sector로 inode_create를 부른다
	 * inode_clst 업데이트
	 */
	disk_sector_t inode_sector = cluster_to_sector(clst);
	struct inode *inode;
	bool success = inode_create(inode_sector, length); 
	if (!success) {
		fat_remove_chain(clst, 0);
	} else {
		inode = inode_open(inode_sector);
		inode_set_cluster(inode, clst);
		inode_close(inode);
	}
	return success;
}
#endif

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) {
	struct list_elem *e;
	struct inode *inode;

	/* Check whether this inode is already open. */
	for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
			e = list_next (e)) {
		inode = list_entry (e, struct inode, elem);
		if (inode->sector == sector) {
			inode_reopen (inode);
			return inode; 
		}
	}

	/* Allocate memory. */
	inode = malloc (sizeof *inode);
	if (inode == NULL)
		return NULL;

	/* Initialize. */
	list_push_front (&open_inodes, &inode->elem);
	inode->sector = sector;
	inode->open_cnt = 1;
	inode->deny_write_cnt = 0;
	inode->removed = false;
	disk_read (filesys_disk, inode->sector, &inode->data);

#ifdef EFILESYS
	get_from_original(inode);
#endif
	return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode) {
	if (inode != NULL)
		inode->open_cnt++;
	return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode) {
	return inode->sector;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) {
	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0) {
		/* Remove from inode list and release lock. */
		list_remove (&inode->elem);

		/* Deallocate blocks if removed. */
		if (inode->removed) {
#ifdef EFILESYS
			fat_remove_chain(inode->data.inode_clst, 0);
			if (inode->data.is_link == HARD)
				fat_remove_chain(inode->data.start_clst, 0);
#else
			free_map_release (inode->sector, 1);
			free_map_release (inode->data.start,
					bytes_to_sectors (inode->data.length)); 
#endif
		}

		free (inode); 
	}
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void
inode_remove (struct inode *inode) {
	ASSERT (inode != NULL);
	inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size,
                    off_t offset) {
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;
  
#ifdef EFILESYS
  /* symlink handling (최신 정보 받아오기) */
  get_from_original(inode);
#endif

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    disk_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % DISK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = DISK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0) break;

    if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      disk_read(filesys_disk, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
       * into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(DISK_SECTOR_SIZE);
        if (bounce == NULL) break;
      }
      disk_read(filesys_disk, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size,
                     off_t offset) {
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

#ifdef EFILESYS
  /* symlink handling (최신 정보 받아오기) */
  get_from_original(inode);
#endif

  if (inode->deny_write_cnt) return 0;

#ifdef EFILESYS

  /*
   * 1. Cluster 몇 개를 늘려야 할 지 계산을 한다.
   * 2. Cluster가 모자랄 수 있으니 (cluster를 추가한 결과 disk 용량을
   * 초과할 수 있으니) 추가 전 마지막 cluster를 저장해놓는다
   * (fat_get_last_clst() 호출)
   * 3. (1에서 구한 것 만큼 loop) fat_create_chain을 하면서 disk에 0 채워넣기
   * 4. inode->data.length 늘리기
   */
   
  /* 현재 파일이 차지하고 있는 cluster 개수 */
  size_t original_length = inode_length(inode);
  size_t inode_clsts_num =
      DIV_ROUND_UP(inode_length(inode), DISK_SECTOR_SIZE * SECTORS_PER_CLUSTER);
  /* write하는 데 필요한 cluster 개수 */
  size_t expected_clsts_num =
      DIV_ROUND_UP(size + offset, DISK_SECTOR_SIZE * SECTORS_PER_CLUSTER);
  /* 새로 할당해야 하는 cluster 개수 */
  size_t new_clsts_num = expected_clsts_num > inode_clsts_num
                             ? expected_clsts_num - inode_clsts_num
                             : 0;
							 
  cluster_t prev_last_clst;
  cluster_t new_clst_first;
  
  if (original_length < offset + size) {
    if (new_clsts_num != 0) {
      prev_last_clst = fat_get_last_clst(inode->data.start_clst);
      new_clst_first = fat_create_chain(prev_last_clst);
	  if (prev_last_clst == 0) {
		inode->data.start = cluster_to_sector(new_clst_first);
		inode->data.start_clst = new_clst_first;
	  }

      size_t i;
      static char zeros[DISK_SECTOR_SIZE];
      if (new_clst_first == 0) goto loop;

      cluster_t cluster = new_clst_first;
      for (size_t j = 0; j < SECTORS_PER_CLUSTER; j++) 
        disk_write(filesys_disk, cluster_to_sector(cluster) + j, zeros);
      
      for (i = 1; i < new_clsts_num; i++) {
        cluster = fat_create_chain(cluster);
        if (cluster == 0) 
          break;
        for (size_t j = 0; j < SECTORS_PER_CLUSTER; j++) 
          disk_write(filesys_disk, cluster_to_sector(cluster) + j, zeros);
      }
      if (cluster == 0) 
        inode->data.length =
            (inode_clsts_num + i) * DISK_SECTOR_SIZE * SECTORS_PER_CLUSTER;
	  else 
        inode->data.length = offset + size;
    } else {
      inode->data.length = offset + size;
    }
	disk_write(filesys_disk, inode->sector, &inode->data);
  }

  /*
   * length vs offset + size
   * cluster를 더 추가해야되는지
   * 추가 안해도 되면 length만 업데이트
   * 추가 해야되면 우리가 짠대로
   */

loop:
#endif
  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    disk_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % DISK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = DISK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0) break;

    if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      disk_write(filesys_disk, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(DISK_SECTOR_SIZE);
        if (bounce == NULL) break;
      }

      /* If the sector contains data before or after the chunk
         we're writing, then we need to read in the sector
         first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        disk_read(filesys_disk, sector_idx, bounce);
      else
        memset(bounce, 0, DISK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      disk_write(filesys_disk, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

#ifdef EFILESYS
	if (bytes_written == 0) {
		if (new_clsts_num != 0) {
			fat_remove_chain(new_clst_first, prev_last_clst);
		}
		inode->data.length = original_length;
		disk_write(filesys_disk, inode->sector, &inode->data);
	}
	update_original(inode);
#endif

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
	inode->deny_write_cnt++;
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) {
	ASSERT (inode->deny_write_cnt > 0);
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode) {
	return inode->data.length;
}

#ifdef EFILESYS
/* Get data.inode_clst of INODE */
cluster_t
inode_get_cluster (struct inode* inode) {
	ASSERT (inode);
	return inode->data.inode_clst;
}

/* Set data.inode_clst of INODE */
void
inode_set_cluster (struct inode* inode, cluster_t cluster) {
	inode->data.inode_clst = cluster;
	disk_write(filesys_disk, inode->sector, &inode->data);
	return;
}

void inode_mark_as_file (struct inode* inode) {
	inode->data.entry_cnt = FILE;
	disk_write(filesys_disk, inode->sector, &inode->data);
	return;
}

void inode_mark_as_dir(struct inode* inode) {
	inode->data.entry_cnt = DIR;
	disk_write(filesys_disk, inode->sector, &inode->data);
	return;
}

bool inode_is_file(struct inode *inode) {
	return inode->data.entry_cnt == FILE;
}

bool inode_is_dir(struct inode* inode) {
	return inode->data.entry_cnt > FILE;
}

void increment_entry_cnt(struct inode * inode) {
	ASSERT(inode_is_dir(inode));
	inode->data.entry_cnt++;
	disk_write(filesys_disk, inode->sector, &inode->data);
}

void decrement_entry_cnt(struct inode * inode) {
	ASSERT(inode_is_dir(inode));
	ASSERT(inode->data.entry_cnt > 0);
	inode->data.entry_cnt--;
	disk_write(filesys_disk, inode->sector, &inode->data);
}

bool is_dir_empty (struct inode * inode) {
	ASSERT(inode_is_dir(inode));
	return inode->data.entry_cnt == 0;
}

void inode_copy(struct inode *dst, struct inode *src) {
	if (!src) {
		dst->data.start = 0;
		dst->data.start_clst = 0;
		dst->data.length = 0;
		dst->data.entry_cnt = -1;
		dst->deny_write_cnt = 0;
	} else {
		dst->data.start = src->data.start;
		dst->data.start_clst = src->data.start_clst;
		dst->data.length = src->data.length;
		dst->data.entry_cnt = src->data.entry_cnt;
		dst->deny_write_cnt = src->deny_write_cnt;
	}
	disk_write(filesys_disk, dst->sector, &dst->data);
}

void inode_copy_soft(struct inode *dst, struct inode *src, char *pathname) {
	dst->data.is_link = LINK;
	memcpy(dst->data.target_path, pathname, strlen(pathname) + 1);
	inode_copy(dst, src);
}

struct inode *get_original_inode(struct inode *inode) {
	if (inode->data.is_link == HARD)
		return inode;
	
	/* root inode 찾기 */
	struct file *parent_file;
	struct file *child_file = filesys_open(inode->data.target_path);
	if (!child_file)
		return NULL;
	
	while (file_get_inode(child_file)->data.is_link == LINK) {
		parent_file = filesys_open(file_get_inode(child_file)->data.target_path);
		file_close(child_file);
		if (!parent_file)
			return NULL;
		child_file = parent_file;
	}
	disk_sector_t inode_sector = inode_get_inumber(file_get_inode(child_file));
	file_close(child_file);
	return inode_open(inode_sector);
}

void update_original(struct inode *inode) {
	struct inode *root_inode = get_original_inode(inode);
	if (inode == root_inode)
		return;
	/* root inode의 내용을 inode의 것으로 update */
	inode_copy(root_inode, inode);
	inode_close(root_inode);
}

void get_from_original(struct inode *inode) {
	struct inode *root_inode = get_original_inode(inode);
	if (inode == root_inode)
		return;
	inode_copy(inode, root_inode);
	inode_close(root_inode);
}
#endif

int inode_get_open_cnt (struct inode * inode) {
	ASSERT(inode);
	return inode->open_cnt;
}
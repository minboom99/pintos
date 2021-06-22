#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "threads/thread.h"
#include "filesys/fat.h"
#include "threads/malloc.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();

	fat_open ();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
	/* Original FS */
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = 0;
#ifdef EFILESYS
	struct dir *parent_dir;
	struct dir* cur_dir = thread_current()->cur_dir;
	struct inode *inode = NULL;
	bool success = false;
	char *filename = NULL;

  	parent_dir = dir_find_and_open(cur_dir, name, &filename);
	if (!parent_dir)
		return false;

	/* file의 inode를 만들 inode_sector 찾기 */
	cluster_t inode_clst = fat_create_chain(0);
	if (inode_clst == 0) {
		free(filename);
		return false;
	}

	inode_sector = cluster_to_sector(inode_clst);
	if (!inode_create_with_clst(inode_clst, initial_size)) {
		/* inode의 chain은 알아서 지워짐 */
		free(filename);
		return false;
	}
	if (!dir_add (parent_dir, filename, inode_sector)) {
    	inode = inode_open(inode_sector);
		inode_remove(inode);
		inode_close(inode);
		free(filename);
		return false;
  	}
	/* file의 inode->data의 dir_or_file 수정 */
	inode = inode_open(inode_sector);
	inode_mark_as_file(inode);
	inode_close(inode);

	free(filename);
	/* cur_dir이 root가 아닌 경우에는 닫으면 안됨 */
	if (parent_dir != cur_dir)
		dir_close (parent_dir);
	success = true;
#else
	struct dir *dir = dir_open_root ();
	bool success = (dir != NULL
			&& free_map_allocate (1, &inode_sector)
			&& inode_create (inode_sector, initial_size)
			&& dir_add (dir, name, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release (inode_sector, 1);
	dir_close (dir);
#endif
	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open(const char *name) {
#ifdef EFILESYS
  struct dir *cur_dir = thread_current()->cur_dir;
  struct dir *dir;
  struct inode *inode = NULL;

  bool is_absolute_root = ((name[0] == '/') && (strlen(name) == 1));

  if (is_absolute_root) {
	return file_open(inode_open(cluster_to_sector(ROOT_DIR_CLUSTER)));
  }

  char *filename;
  dir = dir_find_and_open(cur_dir, name, &filename);

  if (dir != NULL)
  	dir_lookup(dir, filename, &inode);
  free(filename);
  /* cur_dir이 root가 아닌 경우에는 닫으면 안됨 */
  if (dir != cur_dir) dir_close(dir);
#else
  struct dir *dir = dir_open_root();
  struct inode *inode = NULL;

  if (dir != NULL) dir_lookup(dir, name, &inode);
  dir_close(dir);
#endif
  return file_open(inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool 
filesys_remove(const char *name) {
#ifdef EFILESYS
  struct dir *cur_dir = thread_current()->cur_dir;
  char *filename;
  struct dir *parent_dir = dir_find_and_open(
      cur_dir, name, &filename); /* root를 지우려는 attempt는 자동으로 걸러짐 */
  struct inode *target_inode;

  if (!parent_dir) {
	return false;
  }

  if (!dir_lookup(parent_dir, filename, &target_inode)) {
    free(filename);
    if (parent_dir != cur_dir) dir_close(parent_dir);
    return false;
  }

  // directory인지 체크 && (directory라면 비어있는지 체크 || cur_dir인지 체크
  if (inode_is_dir(target_inode)) {
    if (!is_dir_empty(target_inode)) {
      free(filename);
      inode_close(target_inode);
      if (parent_dir != cur_dir) dir_close(parent_dir);
      return false;
    }

    if (!cur_dir) {
      if (inode_get_inumber(target_inode) ==
          cluster_to_sector(ROOT_DIR_CLUSTER)) {
        free(filename);
        inode_close(target_inode);
        if (parent_dir != cur_dir) dir_close(parent_dir);
        return false;
      }
    } else {
      if (dir_get_inode(cur_dir) == target_inode) {
        free(filename);
        inode_close(target_inode);
        if (parent_dir != cur_dir) dir_close(parent_dir);
        return false;
      }
    }
	int open_cnt = inode_get_open_cnt(target_inode);
  
  	/* 열려 있는 directory에 대한 remove 금지 */
  	if (open_cnt > 1) {
		free(filename);
    	inode_close(target_inode);
    	if (parent_dir != cur_dir) dir_close(parent_dir);
    	return false;
 	}
  }
  
  inode_close(target_inode);

  bool success = parent_dir != NULL && dir_remove(parent_dir, filename);
  if (parent_dir != cur_dir) dir_close(parent_dir);
  free(filename);
#else
  struct dir *dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);
#endif
  return success;
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	if (!dir_create_with_cluster (ROOT_DIR_CLUSTER, 16))
		PANIC ("root directory creation failed");
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}
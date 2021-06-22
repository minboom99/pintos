#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "filesys/fat.h"

/* A directory. */
struct dir {
	struct inode *inode;                /* Backing store. */
	off_t pos;                          /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
	disk_sector_t inode_sector;         /* Sector number of header. */
	char name[NAME_MAX + 1];            /* Null terminated file name. */
	bool in_use;                        /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
bool 
dir_create(disk_sector_t sector, size_t entry_cnt) {
  return inode_create(sector, entry_cnt * sizeof(struct dir_entry));
}

#ifdef EFILESYS
bool
dir_create_with_cluster(cluster_t clst, size_t entry_cnt) {
  disk_sector_t sector = cluster_to_sector(clst);
  bool success = inode_create_with_clst(clst, entry_cnt * sizeof(struct dir_entry));

  if (success) {
    struct inode *cur_inode = inode_open(sector);
    struct dir *cur_dir = dir_open(cur_inode);
    if (!dir_add(cur_dir, ".", sector)) {
      inode_remove(cur_inode);
	  dir_close(cur_dir);
      return false;
    }
    if (sector == cluster_to_sector (ROOT_DIR_CLUSTER)) {
      if (!dir_add(cur_dir, "..", sector)) {
        inode_remove(cur_inode);
		dir_close(cur_dir);
        return false;
      }
    }
	inode_mark_as_dir(cur_inode);
	dir_close(cur_dir);
  }
  return success;
}
#endif

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) {
	struct dir *dir = calloc (1, sizeof *dir);
	if (inode != NULL && dir != NULL) {
		dir->inode = inode;
		dir->pos = 0;
		return dir;
	} else {
		inode_close (inode);
		free (dir);
		return NULL;
	}
}

/* Opens the root directory and returns a directory for it.
 * Returns a null pointer on failure. */
struct dir *
dir_open_root (void) {
#ifdef EFILESYS
	return dir_open (inode_open (cluster_to_sector(ROOT_DIR_CLUSTER)));
#else
	return dir_open (inode_open (ROOT_DIR_SECTOR));
#endif
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) {
	return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) {
	if (dir != NULL) {
		inode_close (dir->inode);
		free (dir);
	}
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) {
	return dir->inode;
}

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
		struct dir_entry *ep, off_t *ofsp) {
	struct dir_entry e;
	size_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (e.in_use && !strcmp (name, e.name)) {
			if (ep != NULL)
				*ep = e;
			if (ofsp != NULL)
				*ofsp = ofs;
			return true;
		}
	return false;
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
		struct inode **inode) {
	struct dir_entry e;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	if (lookup (dir, name, &e, NULL))
		*inode = inode_open (e.inode_sector);
	else
		*inode = NULL;

	return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) {
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Check NAME for validity. */
	if (*name == '\0' || strlen (name) > NAME_MAX)
		return false;

	/* Check that NAME is not in use. */
	if (lookup (dir, name, NULL, NULL))
		goto done;

	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break;

	/* Write slot. */
	e.in_use = true;
	strlcpy (e.name, name, sizeof e.name);
	e.inode_sector = inode_sector;
	success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

#ifdef EFILESYS
	if (success && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) 
		increment_entry_cnt(dir_get_inode(dir));
#endif
	
done:
	return success;
}

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) {
	struct dir_entry e;
	struct inode *inode = NULL;
	bool success = false;
	off_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Find directory entry. */
	if (!lookup (dir, name, &e, &ofs))
		goto done;

	/* Open inode. */
	inode = inode_open (e.inode_sector);
	if (inode == NULL)
		goto done;

	/* Erase directory entry. */
	e.in_use = false;
	if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
		goto done;

	/* Remove inode. */
	inode_remove (inode);
	success = true;
#ifdef EFILESYS
	decrement_entry_cnt(dir_get_inode(dir));
#endif
done:
	inode_close (inode);
	return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1]) {
	struct dir_entry e;

	while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
		dir->pos += sizeof e;
		if (e.in_use) {
			strlcpy (name, e.name, NAME_MAX + 1);
			return true;
		}
	}
	return false;
}

#ifdef EFILESYS
bool
file_readdir (struct file *file, char name[NAME_MAX + 1]) {
	ASSERT(inode_is_dir(file_get_inode(file)));
	struct dir_entry e;
	while (inode_read_at (file_get_inode(file), &e, sizeof e, file_tell(file)) == sizeof e) {
		file_seek(file, file_tell(file) + sizeof e);
		if (e.in_use) {
			strlcpy (name, e.name, NAME_MAX + 1);
			return true;
		}
	}
	return false;
}
#endif

/* pathname에 해당하는 가장 child directory를 뱉는다. pathname은 directory로만
 * 이루어져 있다. 호출하기 전에 필요한 부분만 잘라서 인자로 넣어야 함. */
struct dir *dir_walk (struct dir *start_dir, const char *pathname) {
	struct inode *inode;
	struct dir *dir = start_dir;
	struct dir *prev;
	char *dir_name;
	char *ptrptr;
	bool is_absolute_root = ((pathname[0] == '/') && (strlen(pathname) == 1));

	if (is_absolute_root) {
		dir = dir_open_root();
		return dir;
	}

	dir_name = strtok_r(pathname, "/", &ptrptr);
	while(dir_name) {
		bool success = dir_lookup(dir, dir_name, &inode);
		if (!success) {
			if (dir != start_dir)
				dir_close(dir);
			return NULL;
		}
		prev = dir;
		dir = dir_open(inode);
		if (prev != start_dir)
			dir_close(prev);
		if (!dir) 
			break;
		dir_name = strtok_r(NULL, "/", &ptrptr);
	}
	
	return dir;
}

/* name이 가리키는 path의 가장 하위 directory를 열고, buffer에는 name에 따른
 * filename을 할당한다. 실패하면 NULL pointer 반환하고 buffer에는 아무런 일도 일어나지 않는다. */
struct dir *dir_find_and_open(struct dir *cur_dir, const char *name, char **buffer) {
  struct dir *dir;
  /* thread_current() 불러와서 참조하고, 할당하기(필요하면) */
  if (name[0] == '/')
    dir = dir_open_root();
  else {
    if (cur_dir == NULL)
      dir = dir_open_root();
    else
      dir = cur_dir;
  }
  if (dir == NULL) {
    return NULL;
  }

  /* name을 strlcpy로 복사한 string 만들기 */
  size_t name_len = strlen(name);
  char *pathname = calloc(1, name_len + 1);
  if (!pathname)
	return NULL;
  memcpy(pathname, name, name_len + 1);

  /* dir_walk() 호출을 위해 파일이름 뗀 string 만들기 */
  char *filename = strrchr(pathname, '/');  // 끝에 있는 idx찾기
  if (!filename) {
    /* '/'가 name에 없는 상황 -> dir_walk 필요 없음 */
    filename = pathname;
  } else {
    *filename = '\0'; /* pathname을 filename과 dir tree로 쪼개기 */
    filename++;

    if (strlen(filename) == 0) {
      dir = NULL;
	  goto done; /* filename이 비어있으므로 실패~ */
    }
    /* 가장 하위 디렉토리의 struct dir을 가리키는 포인터로 바꿈 */
    dir = dir_walk(dir, pathname);
  }

  size_t filename_len = strlen(filename);
  *buffer = calloc(1, filename_len + 1);
  if (!(*buffer)) {
	dir = NULL;
	goto done;
  }
  memcpy(*buffer, filename, filename_len + 1);
done:
  free(pathname);
  return dir;
}
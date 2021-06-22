#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/disk.h"
#include "filesys/fat.h"

struct bitmap;

void inode_init (void);
bool inode_create (disk_sector_t, off_t);
struct inode *inode_open (disk_sector_t);
struct inode *inode_reopen (struct inode *);
disk_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

/* Newly added */
void inode_set_cluster (struct inode* inode, cluster_t cluster);
void inode_mark_as_file (struct inode* inode);
void inode_mark_as_dir(struct inode* inode);
bool inode_is_file(struct inode *inode);
bool inode_is_dir(struct inode* inode);
bool inode_create_with_clst (cluster_t clst, off_t length);
void increment_entry_cnt(struct inode * inode);
void decrement_entry_cnt(struct inode * inode);
bool is_dir_empty (struct inode * inode);
cluster_t inode_get_cluster (struct inode* inode);
void inode_copy(struct inode *dst, struct inode *src);
void inode_copy_soft(struct inode *dst, struct inode *src, char *pathname);

int inode_get_open_cnt (struct inode * inode);

#endif /* filesys/inode.h */

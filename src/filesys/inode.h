#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"

struct bitmap;

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t direct[NUM_DIRECT]; /* Direct pointer array. */
  block_sector_t indirect;           /* Indirect pointer. */
  block_sector_t double_indirect;    /* Double pointer */
  off_t length;                      /* File size in bytes. */
  unsigned magic;                    /* Magic number. */
  bool is_dir;                       /* Determines whether inode is a directory or file */
  struct dir_entry* dir_entry;       /* Pointer to inode's dir_entry; NULL if inode is a file */
  uint32_t unused[121];              /* Not used.*/
  uint8_t unused[3];
};

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct lock inode_lock; /* Inode Lock. */
  //struct inode_disk data; /* Inode content. */
};

void inode_init(void);
bool inode_create(block_sector_t, off_t);
struct inode* inode_open(block_sector_t);
struct inode* inode_reopen(struct inode*);
block_sector_t inode_get_inumber(const struct inode*);
void inode_close(struct inode*);
void inode_remove(struct inode*);
off_t inode_read_at(struct inode*, void*, off_t size, off_t offset);
off_t inode_write_at(struct inode*, const void*, off_t size, off_t offset);
void inode_deny_write(struct inode*);
void inode_allow_write(struct inode*);
off_t inode_length(const struct inode*);
struct inode_disk* get_disk_inode(const struct inode* inode);
size_t inode_allocate(struct inode_disk* inode, size_t start, size_t stop);
void inode_deallocate(struct inode_disk* inode, size_t start, size_t stop);
void inode_lock_acquire(struct inode* inode);
void inode_lock_release(struct inode* inode);

/* Buffer cache definitions/structs. */

#define MAX_BUFFERS_CACHED 64

struct buffer_cache {
  struct lock lock;
  struct condition fetching;
  struct hash map;
  struct list lru;

  bool is_fetching;
  block_sector_t fetching_id;
};

struct buffer_block {
  block_sector_t id;
  struct rw_lock rw_lock;
  uint8_t data[BLOCK_SECTOR_SIZE];

  struct lock ref_count_lock;
  size_t ref_count;
  bool dirty;

  struct hash_elem helem;
  struct list_elem lelem;
};

void buffer_cache_init(void);
struct buffer_block* buffer_cache_get(block_sector_t id, bool reader);

#endif /* filesys/inode.h */

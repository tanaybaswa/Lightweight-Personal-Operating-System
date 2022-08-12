#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Number of direct pointers in an inode. (Subject to change to 
   to accomodate metadata.) */
#define NUM_DIRECT 124

/* Number of pointers in an indirect inode. */
#define NUM_INDIRECT 128

struct bitmap;

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t direct[NUM_DIRECT]; /* Direct pointer array. */
  block_sector_t indirect;           /* Indirect pointer. */
  block_sector_t double_indirect;    /* Double pointer */
  off_t length;                      /* File size in bytes. */
  unsigned magic;                    /* Magic number. */
  //bool is_dir;                       /* Determines whether inode is a directory or file */
  //struct dir_entry* dir_entry;       /* Pointer to inode's dir_entry; NULL if inode is a file */
};

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct lock lock; /* Inode Lock. */
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

/* Buffer cache definitions/structs. */

#define MAX_BUFFERS_CACHED 64
//#define NO_BUFFER

struct buffer_cache {
  struct lock lock;
  struct condition fetching;
  struct hash map;
  struct list lru;
  size_t misses;

  bool is_fetching;
  block_sector_t fetching_id;
  bool is_writing;
  block_sector_t writing_id;
};

struct buffer_block {
  block_sector_t id;
  struct lock lock;

  uint8_t data[BLOCK_SECTOR_SIZE];
  bool dirty;

  struct hash_elem helem;
  struct list_elem lelem;
};

void buffer_cache_init(void);
void buffer_cache_flush(void);
struct buffer_block* buffer_cache_get(block_sector_t id);
void buffer_cache_read(block_sector_t, void*, size_t, size_t, size_t);
void buffer_cache_write(block_sector_t, const void*, size_t, size_t, size_t);



#endif /* filesys/inode.h */

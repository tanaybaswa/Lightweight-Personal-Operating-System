#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"

struct bitmap;

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

/* Buffer cache definitions/structs. */

#define MAX_BUFFERS_CACHED 64
// #define NO_BUFFER


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
  struct lock rc_lock;
  size_t ref_count;

  struct condition release;

  uint8_t data[BLOCK_SECTOR_SIZE];
  bool dirty;

  struct hash_elem helem;
  struct list_elem lelem;
};

void buffer_cache_init(void);
void buffer_cache_flush(void);
struct buffer_block* buffer_cache_get(block_sector_t id);
void buffer_block_read(struct buffer_block*, uint8_t*, void*, size_t);
void buffer_block_write(struct buffer_block*, uint8_t*, const void*, size_t);
void buffer_block_release(struct buffer_block*);



#endif /* filesys/inode.h */

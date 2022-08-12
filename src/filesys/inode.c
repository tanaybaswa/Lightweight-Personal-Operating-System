#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include <threads/synch.h>
#include <stdio.h>

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44


struct indirect_inode {
  block_sector_t ptrs[NUM_INDIRECT]; /* (In)Direct Pointer array. */
};

/* Buffer cache for inode/file data. */
struct buffer_cache buffer_cache;

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* Returns on disk inode struct referring to in memory inode. Malloced space. */
struct inode_disk* get_disk_inode(const struct inode* inode) {
  struct inode_disk* disk_inode = malloc(sizeof(struct inode_disk));

#ifndef NO_BUFFER
  buffer_cache_read(inode_get_inumber(inode), disk_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
  block_read(fs_device, inode_get_inumber(inode), (void*)disk_inode);
#endif
  return disk_inode;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {

  ASSERT(inode != NULL);

  struct inode_disk* disk_inode = get_disk_inode(inode);
  block_sector_t result = -1;

  int i = pos;

  pos = pos / BLOCK_SECTOR_SIZE;

  if (i < disk_inode->length) {

    if (pos < NUM_DIRECT) {

      result = disk_inode->direct[pos];

    } else if (pos < NUM_DIRECT + NUM_INDIRECT) {
      int index = pos - NUM_DIRECT;

      struct indirect_inode* disk_indirect = malloc(sizeof(struct indirect_inode));

#ifndef NO_BUFFER
      buffer_cache_read(disk_inode->indirect, disk_indirect, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
      block_read(fs_device, disk_inode->indirect, (void*)disk_indirect);
#endif

      result = disk_indirect->ptrs[index];

      free(disk_indirect);

    } else {

      int index = pos - NUM_DIRECT - NUM_INDIRECT;

      int first_index = index / NUM_INDIRECT;
      int second_index = index % NUM_INDIRECT;

      struct indirect_inode* double_pointer = malloc(sizeof(struct indirect_inode));

#ifndef NO_BUFFER
      buffer_cache_read(disk_inode->double_indirect, double_pointer, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
      block_read(fs_device, disk_inode->double_indirect, (void*)double_pointer);
#endif

      struct indirect_inode* disk_indirect2 = malloc(sizeof(struct indirect_inode));

#ifndef NO_BUFFER
      buffer_cache_read(double_pointer->ptrs[first_index], disk_indirect2, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
      block_read(fs_device, double_pointer->ptrs[first_index], (void*)disk_indirect2);
#endif

      result = disk_indirect2->ptrs[second_index];

      free(disk_indirect2);
      free(double_pointer);
    }
  }

  free(disk_inode);
  return result;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;

    size_t end = inode_allocate(disk_inode, 0, sectors);

    if (end == sectors) {
#ifndef NO_BUFFER
      buffer_cache_write(sector, disk_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
      block_write(fs_device, sector, disk_inode);
#endif

      success = true;
    } else {
      inode_deallocate(disk_inode, 0, end);
    }

    free(disk_inode);
  }

  return success;
}

/* Inode allocation function. Calls free map allocate. */
size_t inode_allocate(struct inode_disk* inode, size_t start, size_t stop) {

  size_t sector_num = start;

  if (sector_num == stop) {
    return sector_num;
  }

  int i = 0;
  static char zeros[BLOCK_SECTOR_SIZE];

  while (sector_num < NUM_DIRECT && sector_num < stop) {

    if (!free_map_allocate(1, &inode->direct[sector_num])) {
      return sector_num;
    }

#ifndef NO_BUFFER
    buffer_cache_write(inode->direct[sector_num], zeros, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
    block_write(fs_device, inode->direct[sector_num], zeros);
#endif

    sector_num += 1;
  }

  if (sector_num == stop) {
    return sector_num;
  }

  i = sector_num - NUM_DIRECT;

  if (!inode->indirect) {

    if (!free_map_allocate(1, &inode->indirect)) {
      return sector_num;
    }

#ifndef NO_BUFFER
    buffer_cache_write(inode->indirect, zeros, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
    block_write(fs_device, inode->indirect, zeros);
#endif
  }

  struct indirect_inode indirect_inode;

#ifndef NO_BUFFER
  buffer_cache_read(inode->indirect, &indirect_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
  block_read(fs_device, inode->indirect, (void*)&indirect_inode);
#endif

  while (sector_num < NUM_DIRECT + NUM_INDIRECT && sector_num < stop && i < NUM_INDIRECT) {

    if (!indirect_inode.ptrs[i]) {

      if (!free_map_allocate(1, &indirect_inode.ptrs[i])) {
        return sector_num;
      }

#ifndef NO_BUFFER
      buffer_cache_write(indirect_inode.ptrs[i], zeros, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
      block_write(fs_device, indirect_inode.ptrs[i], zeros);
#endif
    }

    i += 1;
    sector_num += 1;
  }

#ifndef NO_BUFFER
  buffer_cache_write(inode->indirect, &indirect_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
  block_write(fs_device, inode->indirect, &indirect_inode);
#endif

  if (sector_num == stop) {
    return sector_num;
  }

  if (!inode->double_indirect) {

    if (!free_map_allocate(1, &inode->double_indirect)) {
      return sector_num;
    }

#ifndef NO_BUFFER
    buffer_cache_write(inode->double_indirect, zeros, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
    block_write(fs_device, inode->double_indirect, zeros);
#endif
  }

  struct indirect_inode double_inode;

#ifndef NO_BUFFER
  buffer_cache_read(inode->double_indirect, &double_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
  block_read(fs_device, inode->double_indirect, &double_inode);
#endif

  //int num_indirect_to_allocate = DIV_ROUND_UP(stop - sector_num, NUM_INDIRECT);
  int index = sector_num - NUM_DIRECT - NUM_INDIRECT;

  int j = index / NUM_INDIRECT;
  i = index % NUM_INDIRECT;

  while (sector_num < stop) {

    if (!double_inode.ptrs[j]) {

      if (!free_map_allocate(1, &double_inode.ptrs[j])) {
        return sector_num;
      }
#ifndef NO_BUFFER
      buffer_cache_write(double_inode.ptrs[j], zeros, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
      block_write(fs_device, double_inode.ptrs[j], zeros);
#endif
    }

    struct indirect_inode indirect_inode;

#ifndef NO_BUFFER
    buffer_cache_read(double_inode.ptrs[j], &indirect_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
    block_read(fs_device, double_inode.ptrs[j], &indirect_inode);
#endif

    i = (sector_num - NUM_DIRECT - NUM_INDIRECT) % NUM_INDIRECT;

    while (i < NUM_INDIRECT && sector_num < stop) {

      if (!indirect_inode.ptrs[i]) {

        if (!free_map_allocate(1, &indirect_inode.ptrs[i])) {
          return sector_num;
        }

#ifndef NO_BUFFER
        buffer_cache_write(indirect_inode.ptrs[i], zeros, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
        block_write(fs_device, indirect_inode.ptrs[i], zeros);
#endif
      }

      i += 1;
      sector_num += 1;
    }

#ifndef NO_BUFFER
    buffer_cache_write(double_inode.ptrs[j], &indirect_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
    block_write(fs_device, double_inode.ptrs[j], &indirect_inode);
#endif

    j += 1;
  }

#ifndef NO_BUFFER
  buffer_cache_write(inode->double_indirect, &double_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
  block_write(fs_device, inode->double_indirect, &double_inode);
#endif

  return sector_num;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL) {
    lock_acquire(&inode->lock);
    inode->open_cnt++;
    lock_release(&inode->lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire(&inode->lock);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {

      struct inode_disk* disk_inode = get_disk_inode(inode);
      size_t length = bytes_to_sectors(disk_inode->length);

      inode_deallocate(disk_inode, 0, length);
      free_map_release(inode->sector, 1);

      free(disk_inode);
    }

    lock_release(&inode->lock);
    free(inode);
  } else {
    lock_release(&inode->lock);
  }
}

/* Inode deallocation function. Calls free map release. */
void inode_deallocate(struct inode_disk* inode, size_t start, size_t stop) {
  size_t sector_num = start;
  int i = 0;

  while (sector_num < NUM_DIRECT && sector_num < stop) {

    free_map_release(inode->direct[sector_num], 1);

    sector_num += 1;
  }

  if (sector_num == stop) {
    return;
  }

  i = sector_num - NUM_DIRECT;

  struct indirect_inode indirect_inode;

#ifndef NO_BUFFER
  buffer_cache_read(inode->indirect, &indirect_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
  block_read(fs_device, inode->indirect, &indirect_inode);
#endif

  while (sector_num < NUM_DIRECT + NUM_INDIRECT && sector_num < stop && i < NUM_INDIRECT) {

    free_map_release(indirect_inode.ptrs[i], 1);

    i += 1;
    sector_num += 1;
  }

  if (sector_num == stop) {
    return;
  }

  free_map_release(inode->indirect, 1);

  struct indirect_inode double_inode;

#ifndef NO_BUFFER
  buffer_cache_read(inode->double_indirect, &double_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
  block_read(fs_device, inode->double_indirect, &double_inode);
#endif

  //int num_indirect_to_allocate = DIV_ROUND_UP(stop - sector_num, NUM_INDIRECT);
  int index = sector_num - NUM_DIRECT - NUM_INDIRECT;

  int j = index / NUM_INDIRECT;
  i = index % NUM_INDIRECT;

  while (sector_num < stop) {

    struct indirect_inode indirect_inode;

#ifndef NO_BUFFER
    buffer_cache_read(double_inode.ptrs[j], &indirect_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
    block_read(fs_device, double_inode.ptrs[j], &indirect_inode);
#endif

    i = (sector_num - NUM_DIRECT - NUM_INDIRECT) % NUM_INDIRECT;

    while (i < NUM_INDIRECT && sector_num < stop) {

      free_map_release(indirect_inode.ptrs[i], 1);

      i += 1;
      sector_num += 1;
    }

    if (sector_num == stop) {
      return;
    }

    free_map_release(double_inode.ptrs[j], 1);

    j += 1;
  }

  free_map_release(inode->double_indirect, 1);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
#ifdef NO_BUFFER
  uint8_t* bounce = NULL;
#endif

  lock_acquire(&inode->lock);

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
#ifndef NO_BUFFER
      buffer_cache_read(sector_idx, buffer, chunk_size, sector_ofs, bytes_read);
#endif

#ifdef NO_BUFFER
      block_read(fs_device, sector_idx, buffer + bytes_read);
#endif
    } else {
#ifdef NO_BUFFER
      if(bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if(bounce == NULL) break;
      }

      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
#endif
      
#ifndef NO_BUFFER
      buffer_cache_read(sector_idx, buffer, chunk_size, sector_ofs, bytes_read);
#endif
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }

  lock_release(&inode->lock);

#ifdef NO_BUFFER
  free(bounce);
#endif

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs. */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
#ifdef NO_BUFFER
  uint8_t* bounce = NULL;
#endif

  if (inode->deny_write_cnt)
    return 0;

  struct inode_disk* disk_inode = get_disk_inode(inode);
  off_t length = size + offset;

  if (length > ((NUM_DIRECT + NUM_INDIRECT + NUM_INDIRECT * NUM_INDIRECT) * BLOCK_SECTOR_SIZE)) {
    return -1;
  }

  lock_acquire(&inode->lock);
  /* Extend the inode. */
  if (length > disk_inode->length) {
    size_t start = (size_t)bytes_to_sectors(disk_inode->length);
    size_t stop = (size_t)bytes_to_sectors(offset + size);
    size_t end = inode_allocate(disk_inode, start, stop);

    if (end != stop) {

      inode_deallocate(disk_inode, start, end);
      free(disk_inode);
      lock_release(&inode->lock);
      return bytes_written;
    }

    disk_inode->length = offset + size;

#ifndef NO_BUFFER
    buffer_cache_write(inode_get_inumber(inode), disk_inode, BLOCK_SECTOR_SIZE, 0, 0);
#endif

#ifdef NO_BUFFER
    block_write(fs_device, inode_get_inumber(inode), (void*)disk_inode);
#endif
  }

  free(disk_inode);

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */

#ifdef NO_BUFFER
      block_write(fs_device, sector_idx, buffer + bytes_written);
#endif


#ifndef NO_BUFFER
      buffer_cache_write(sector_idx, buffer, chunk_size, sector_ofs, bytes_written);
#endif

    } else {

#ifdef NO_BUFFER
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);

      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
#endif

#ifndef NO_BUFFER
      buffer_cache_write(sector_idx, buffer, chunk_size, sector_ofs, bytes_written);
#endif

    }


    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  lock_release(&inode->lock);

#ifdef NO_BUFFER
  free(bounce);
#endif

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  lock_acquire(&inode->lock);
  inode->deny_write_cnt++;
  lock_release(&inode->lock);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  lock_acquire(&inode->lock);
  inode->deny_write_cnt--;
  lock_release(&inode->lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) {

  struct inode_disk* disk_inode = get_disk_inode(inode);
  off_t l = disk_inode->length;
  free(disk_inode);
  return l;
}

/* Buffer cache functions. */

static struct hash_elem* buffer_cache_fetch(block_sector_t id);
static void buffer_cache_lru_update(struct buffer_block* search_key);
static void buffer_cache_lru_evict(void);

static unsigned buffer_cache_hash_func(const struct hash_elem* e, UNUSED void* aux);
static bool buffer_cache_less_func(const struct hash_elem* a, const struct hash_elem* b,
                                   UNUSED void* aux);

void buffer_cache_init() {
  hash_init(&buffer_cache.map, buffer_cache_hash_func, buffer_cache_less_func, NULL);
  list_init(&buffer_cache.lru);
  lock_init(&buffer_cache.lock);
  cond_init(&buffer_cache.fetching);
  buffer_cache.fetching_id = 0;
  buffer_cache.is_fetching = false;
  buffer_cache.misses = 0;
  buffer_cache.is_writing = false;
  buffer_cache.writing_id = 0;
}

static unsigned buffer_cache_hash_func(const struct hash_elem* e, UNUSED void* aux) {
  struct buffer_block* buffer_block = hash_entry(e, struct buffer_block, helem);
  return hash_int(buffer_block->id);
}

static bool buffer_cache_less_func(const struct hash_elem* a, const struct hash_elem* b,
                                   UNUSED void* aux) {
  struct buffer_block* block_a = hash_entry(a, struct buffer_block, helem);
  struct buffer_block* block_b = hash_entry(b, struct buffer_block, helem);
  return block_a->id < block_b->id;
}

void buffer_cache_read(block_sector_t sector_id, void* read_buffer_, size_t size, size_t block_buffer_offset, size_t read_buffer_offset) {
  lock_acquire(&buffer_cache.lock);
  struct buffer_block* bb = buffer_cache_get(sector_id);
  lock_release(&buffer_cache.lock);

  lock_acquire(&bb->lock);
  uint8_t* read_buffer = (void*)read_buffer_;
  memcpy(read_buffer + read_buffer_offset, bb->data + block_buffer_offset, size);
  lock_release(&bb->lock);
  return;
}

void buffer_cache_write(block_sector_t sector_id, const void* write_buffer_, size_t size, size_t block_buffer_offset, size_t write_buffer_offset) {
  lock_acquire(&buffer_cache.lock);
  struct buffer_block* bb = buffer_cache_get(sector_id);
  lock_release(&buffer_cache.lock);

  lock_acquire(&bb->lock);
  uint8_t* write_buffer = (void*)write_buffer_;
  memcpy(bb->data + block_buffer_offset, write_buffer + write_buffer_offset, size);
  bb->dirty = true;
  lock_release(&bb->lock);
  return;
}

struct buffer_block* buffer_cache_get(block_sector_t id) {
  // printf("Getting block %d.\n", id);

  /* If requesting a block that is being fetched, wait. */
  while(buffer_cache.fetching_id == id && buffer_cache.is_fetching) {
    cond_wait(&buffer_cache.fetching, &buffer_cache.lock);
  }

  /* Create a temporary hash_elem to search for ID. */
  struct buffer_block search_key;
  search_key.id = id;

  /* Search for ID in the buffer cache's map. */
  struct hash_elem* buffer_block_helem = hash_find(&buffer_cache.map, &search_key.helem);
  if(buffer_block_helem == NULL) {
    /* Bring the block into the buffer cache. */
    buffer_block_helem = buffer_cache_fetch(id);
  } else {
    /* Update the buffer cache's LRU. */
    buffer_cache_lru_update(&search_key);
  }

  /* Attempt to acquire the block's rw_lock, depending on READER flag. */
  struct buffer_block* buffer_block = hash_entry(buffer_block_helem, struct buffer_block, helem);
  return buffer_block;
}

static struct hash_elem* buffer_cache_fetch(block_sector_t id) {
  /* Wait for buffer cache to finish fetching block. */
  while((buffer_cache.is_writing && buffer_cache.writing_id == id) || buffer_cache.is_fetching) {
    cond_wait(&buffer_cache.fetching, &buffer_cache.lock);
  }


  /* Prevents buffer cache from fetching same block or fetching at same time. */
  buffer_cache.is_fetching = true;
  buffer_cache.fetching_id = id;

  // printf("Fetching block %d.\n", id);

  /* Initialize the block we are fetching. */
  struct buffer_block* buffer_block = malloc(sizeof(struct buffer_block));
  buffer_block->id = id;
  lock_init(&buffer_block->lock);
  buffer_block->dirty = false;

  /* Release lock and fetch. Fetching is long. */
  lock_release(&buffer_cache.lock);
  block_read(fs_device, id, buffer_block->data);
  lock_acquire(&buffer_cache.lock);
  buffer_cache.misses += 1;

  buffer_cache.is_fetching = false;
  buffer_cache.fetching_id = 0;

  cond_signal(&buffer_cache.fetching, &buffer_cache.lock);

  /* Add the new block into map and LRU. */
  hash_insert(&buffer_cache.map, &buffer_block->helem);

  if (list_size(&buffer_cache.lru) >= MAX_BUFFERS_CACHED) {
    buffer_cache_lru_evict();
  }
  

  list_push_front(&buffer_cache.lru, &buffer_block->lelem);

  return &buffer_block->helem;
}

static void buffer_cache_lru_update(struct buffer_block* key_info) {
  struct hash_elem* buffer_block_helem = hash_find(&buffer_cache.map, &key_info->helem);
  struct buffer_block* buffer_block = hash_entry(buffer_block_helem, struct buffer_block, helem);

  list_remove(&buffer_block->lelem);
  list_push_front(&buffer_cache.lru, &buffer_block->lelem);
  return;
}

static void buffer_cache_lru_evict() {
  /* Evict the tail of the LRU. */
  struct list_elem* tail_lelem = list_pop_back(&buffer_cache.lru);
  struct buffer_block* buffer_block = list_entry(tail_lelem, struct buffer_block, lelem);

  hash_delete(&buffer_cache.map, &buffer_block->helem);

  /* NOTE: This lock acquire prevents other threads from getting/fetching while the LRU element
   * is still being used. If another thread is fetching a block, they will have to evict a block
   * (if we are here, then the LRU is full so the above must be true). We can't evict a block 
   * until this block has been released. A concession is that this halts getting blocks that
   * already exists in the cache. */

  // printf("Evicting block %d.\n", buffer_block->id);
  lock_acquire(&buffer_block->lock);
  if(buffer_block->dirty) {
    buffer_cache.is_writing = true;
    buffer_cache.writing_id = buffer_block->id;

    lock_release(&buffer_cache.lock);
    block_write(fs_device, buffer_block->id, buffer_block->data);
    lock_acquire(&buffer_cache.lock);

    buffer_cache.writing_id = 0;
    buffer_cache.is_writing = false;

    cond_signal(&buffer_cache.fetching, &buffer_cache.lock);
  }

  free(buffer_block);

  return;
}



void buffer_cache_flush() {
  lock_acquire(&buffer_cache.lock);

  while(!list_empty(&buffer_cache.lru)) {
    struct list_elem *e = list_pop_front(&buffer_cache.lru);
    struct buffer_block* block = list_entry(e, struct buffer_block, lelem);
    if(block->dirty) {
      block_write(fs_device, block->id, block->data);
    }

    free(block);
  }

}

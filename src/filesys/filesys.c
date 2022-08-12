#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  buffer_cache_flush(); 
  free_map_close(); 
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  block_sector_t inode_sector = 0;
  struct dir* dir = dir_open_root();
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size) && dir_add(dir, name, inode_sector, false));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

bool filesys_create_file(const char* name, const struct dir* dir_, off_t initial_size) {
  block_sector_t inode_sector = 0;
  struct dir* dir = dir_reopen(dir_);
  bool success = (dir != NULL & free_map_allocate(1, &inode_sector) &&
      inode_create(inode_sector, initial_size) && dir_add(dir, name, inode_sector, false));
  if(!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);
  return success;
}

/* Creates a directory given a parent directory DIR. */
bool filesys_create_dir(const char* name, const struct dir* dir_) {
  block_sector_t inode_sector = 0;
  struct dir* dir = dir_reopen(dir_);

  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
      inode_create(inode_sector, sizeof(struct dir_entry) * BASE_DIR_SIZE) && 
      dir_add(dir, name, inode_sector, true));

  if(!success && inode_sector != 0)
    free_map_release(inode_sector, 1);

  /* Insert '.' and '..' */
  if(success) {
    struct inode* child_inode = NULL;
    bool is_dir;
    struct dir* child_dir = NULL;
    dir_lookup(dir, name, &child_inode, &is_dir);

    if(child_inode == NULL || (child_dir = dir_open(child_inode)) == NULL) {
      dir_remove(dir, name);
      free_map_release(inode_sector, 1);
      dir_close(dir);
      return false;
    }

    dir_add(child_dir, ".", child_inode->sector, true);
    dir_add(child_dir, "..", dir_get_inode(dir)->sector, true);
    dir_close(child_dir);
  }


  dir_close(dir);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  struct dir* dir = dir_open_root();
  struct inode* inode = NULL;

  if (dir != NULL) {
    bool is_dir;
    dir_lookup(dir, name, &inode, &is_dir);
  }
  dir_close(dir);

  return file_open(inode);
}

struct file* filesys_open_file(const char* name, const struct dir* dir_) {
  struct dir* dir = dir_reopen(dir_);
  struct inode* inode = NULL;

  if(dir != NULL) {
    bool is_dir;
    dir_lookup(dir, name, &inode, &is_dir);
  }
  dir_close(dir);

  return file_open(inode);
}

struct dir* filesys_open_dir(const char* name, const struct dir* parent_) {
  struct dir* parent = dir_reopen(parent_);
  struct inode* inode = NULL;

  if(parent != NULL) {
    bool is_dir;
    dir_lookup(parent, name, &inode, &is_dir);
  }
  dir_close(parent);

  return dir_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
}

bool filesys_remove_dir(const char* name, const struct dir* dir_) {
  struct dir* dir = dir_reopen(dir_);
  if(dir == NULL)
    return false;

  struct inode* inode = NULL;
  bool is_dir;
  struct dir* child = NULL;
  bool found = dir_lookup(dir, name, &inode, &is_dir);

  if(inode == NULL) {
    dir_close(dir);
    return false;
  }

  child = dir_open(inode);
  if(child == NULL) {
    dir_close(dir);
    inode_close(inode);
    return false;
  }

  if(!dir_empty(child)) {
    dir_close(dir);
    dir_close(child);
    return false;
  }

  dir_clear(child);
  dir_close(child);
  bool success = dir_remove(dir, name);
  dir_close(dir);
  return success;
}

bool filesys_remove_file(const char* name, const struct dir* dir_) {
  struct dir* dir = dir_reopen(dir_);
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);
  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

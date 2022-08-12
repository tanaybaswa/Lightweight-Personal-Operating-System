#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"
#include "threads/malloc.h"
#include "filesys/off_t.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14
#define BASE_DIR_SIZE 16

struct inode;

struct dir {
  struct inode* inode;
  off_t pos;
};

struct dir_entry {
  block_sector_t inode_sector;
  char name[NAME_MAX + 1];
  bool in_use;
  bool is_directory;
};

/* Opening and closing directories. */
bool dir_create(block_sector_t sector, size_t entry_cnt);
struct dir* dir_open(struct inode*);
struct dir* dir_open_root(void);
struct dir* dir_reopen(struct dir*);
void dir_close(struct dir*);
struct inode* dir_get_inode(struct dir*);
bool dir_empty(struct dir*);

/* Reading and writing. */
bool dir_lookup(const struct dir*, const char* name, struct inode**, bool* is_dir);
bool dir_add(struct dir*, const char* name, block_sector_t, bool is_dir);
bool dir_remove(struct dir*, const char* name);
bool dir_readdir(struct dir*, char name[NAME_MAX + 1]);
void dir_clear(struct dir*);

/* Splitting file path into parts. */
int get_next_part(char part[NAME_MAX + 1], const char** srcp);

#endif /* filesys/directory.h */

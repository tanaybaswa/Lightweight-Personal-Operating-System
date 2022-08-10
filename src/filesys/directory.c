#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* A directory. */
struct dir {
  struct inode* inode;      /* Backing store. */
  off_t pos;                /* Current position. */
  struct dir_entry* parent; /* Directory's parent directory */
};

/* A single directory entry. */
struct dir_entry {
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
  struct dir* sub_dir;         /* Pointer to subdirectory; NULL if dir_entry is a file */
  bool is_dir;                 /* Determines whether it's a directory or a file */
};

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create(block_sector_t sector, size_t entry_cnt) {
  return inode_create(sector, entry_cnt * sizeof(struct dir_entry));
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir* dir_open(struct inode* inode) {
  struct dir* dir = calloc(1, sizeof *dir);
  if (inode != NULL && dir != NULL) {
    dir->inode = inode;
    dir->pos = 0;
    return dir;
  } else {
    inode_close(inode);
    free(dir);
    return NULL;
  }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir* dir_open_root(void) {
  return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir* dir_reopen(struct dir* dir) {
  return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir* dir) {
  if (dir != NULL) {
    inode_close(dir->inode);
    free(dir);
  }
}

/* Returns the inode encapsulated by DIR. */
struct inode* dir_get_inode(struct dir* dir) {
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp) {
  struct dir_entry e;
  size_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (e.in_use && !strcmp(name, e.name)) {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      return true;
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir* dir, const char* name, struct inode** inode) {
  struct dir_entry e;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (lookup(dir, name, &e, NULL))
    *inode = inode_open(e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add(struct dir* dir, const char* name, block_sector_t inode_sector) {
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen(name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup(dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy(e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir* dir, const char* name) {
  struct dir_entry e;
  struct inode* inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Find directory entry. */
  if (!lookup(dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open(e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove(inode);
  success = true;

done:
  inode_close(inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir(struct dir* dir, char name[NAME_MAX + 1]) {
  struct dir_entry e;

  while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
    dir->pos += sizeof e;
    if (e.in_use) {
      strlcpy(name, e.name, NAME_MAX + 1);
      return true;
    }
  }
  return false;
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

// /* Return the proper directory corresponding to the relative path or absolute path passed in */
// static struct dir* path_resolution(char* path) {
//   char* kfile = copy_in_string(path);
//   char* curr;
//   struct dir* directory;

//   struct thread* curr_thread = thread_current();

//   while (curr = get_next_part(curr, &kfile) == 1) {
//     if (curr == "/") {
//       return dir_open_root();
//     }
//     directory = dir_reopen();
//   }

//   palloc_free_page(kfile);
//   return NULL;
// }

// /* Changes cwd of current process to DIR */
// bool chdir(const char* dir) {
//   ASSERT(dir != NULL);
//   struct dir* new_dir = path_resolution(dir);
//   if (new_dir == NULL)
//     return false;
//   struct thread* curr_thread = current_thread();
//   curr_thread->pcb->cwd = new_dir;
//   return true;
// }

struct dir* start_dir(char* path) {
  if (*path == '/') {
    // absolute path
    return dir_open_root();
  } else {
    // relative path from current directory
    struct thread* cur = thread_current();
    if (cur->pcb->cwd == NULL) {
      return dir_open_root();
    } else {
      return cur->pcb->cwd;
    }
  }
}

/* Returns 1 if found, 0 if not found, -1 if error */
int file_dir_inode(char** path, struct dir** last_dir, struct inode** ret_in, char** name) {
  struct dir* curr_dir = start_dir(*path);
  char* part = malloc(NAME_MAX + 1);
  if (part == NULL) {
    return false;
  }
  struct inode* in = NULL;
  bool exist = false;
  int ret = 1;
  int found = -1;
  *ret_in = NULL;
  *name = NULL;

  while (ret != 0) {
    *last_dir = curr_dir;
    ret = get_next_part(part, path);
    if (ret == -1) {
      free(part);
      break;
    }
    if (ret == 0) {
      *ret_in = in;
      *name = part;
      found = 1;
      break;
    }
    exist = dir_lookup(curr_dir, part, &in);
    if (exist) {
      if (in->data.is_dir) {
        curr_dir = dir_open(in);
      }
    } else { // check if this is last part
      if (get_next_part(part, path) == 0) {
        // last part is valid and does not exist
        *name = part;
        found = 0;
      } else {
        // invalid path
        free(part);
      }
      break;
    }
  }
  return found;
}

struct dir* make_and_add_dir(struct dir* curr_dir, char* name, block_sector_t in_sector) {
  bool added, created;
  struct inode* new_in;
  struct dir* new_dir;

  // adding new directory entry to current directory
  added = dir_add(curr_dir, name, in_sector);
  if (added == false) {
    free_map_release(in_sector, 1);
    return NULL;
  }

  // create new sub-directory
  created = dir_create(in_sector, 2);
  if (created == false) {
    free_map_release(in_sector, 1);
    return NULL;
  }

  // use inode sector to get new inode
  new_in = inode_open(in_sector);
  if (new_in == NULL) {
    free_map_release(in_sector, 1);
    return NULL;
  }
  new_in->data.is_dir = true;

  // use inode to get directory
  new_dir = dir_open(new_in);
  if (new_dir == NULL) {
    free_map_release(in_sector, 1);
    return NULL;
  }

  return new_dir;
}

/* Creates directory named dir, which may be relative or absolute. Returns true if successful, false on failure */
bool mkdir(const char* dir) {
  struct dir* curr_dir;
  struct dir* new_dir;
  struct inode* in;
  int found;
  bool allocated, added;
  char* name;
  block_sector_t in_sector;

  found = file_dir_inode(&dir, &curr_dir, &in, &name);

  if (found == 1 || found == -1) {
    return false;
  }

  // add new directory to current dirrectory
  allocated = free_map_allocate(1, &in_sector);
  if (allocated == false) {
    return false;
  }
  new_dir = make_and_add_dir(curr_dir, name, in_sector);
  if (new_dir == NULL) {
    return false;
  }

  // adding . directory to new directory
  char dir1[] = ".";
  added = dir_add(curr_dir, dir1, in_sector);
  if (added == false) {
    free_map_release(in_sector, 1);
    return false;
  }

  // adding .. directory to new directory
  char dir2[] = "..";
  added = dir_add(curr_dir, dir2, curr_dir->inode->sector);
  if (added == false) {
    free_map_release(in_sector, 1);
    return false;
  }

  return true;
}

/* change directory, returns true if succesful, false if fail */
bool chdir(const char* dir) {
  int found;
  struct dir* new_dir;
  struct inode* in;
  char* name;

  found = file_dir_inode(&dir, &new_dir, &in, &name);

  if (found == 0 || found == -1) {
    return false;
  }

  struct thread* cur = thread_current();
  cur->pcb->cwd = new_dir;
  return true;
}

/* readdir system call */
bool readdir(int fd, char* name) {
  //
}

#include "userprog/syscall.h"
#include <stdio.h>
#include <float.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/block.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

static void syscall_handler(struct intr_frame*);
static void copy_in(void*, const void*, size_t);
static struct file_descriptor* lookup_fd(int handle);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

/* System call handler. */
static void syscall_handler(struct intr_frame* f) {
  typedef int syscall_function(int, int, int);

  /* A system call. */
  struct syscall {
    size_t arg_cnt;         /* Number of arguments. */
    syscall_function* func; /* Implementation. */
  };

  /* Table of system calls. */
  static const struct syscall syscall_table[] = {
      {0, (syscall_function*)sys_halt},        {1, (syscall_function*)sys_exit},
      {1, (syscall_function*)sys_exec},        {1, (syscall_function*)sys_wait},
      {2, (syscall_function*)sys_create},      {1, (syscall_function*)sys_remove},
      {1, (syscall_function*)sys_open},        {1, (syscall_function*)sys_filesize},
      {3, (syscall_function*)sys_read},        {3, (syscall_function*)sys_write},
      {2, (syscall_function*)sys_seek},        {1, (syscall_function*)sys_tell},
      {1, (syscall_function*)sys_close},       {1, (syscall_function*)sys_practice},
      {1, (syscall_function*)sys_compute_e},

      {1, (syscall_function*)sys_chdir},       {1, (syscall_function*)sys_mkdir},
      {2, (syscall_function*)sys_readdir},     {1, (syscall_function*)sys_isdir},
      {1, (syscall_function*)sys_inumber},     {0, (syscall_function*)sys_hit_rate},
      {0, (syscall_function*)sys_flush_cache}, {0, (syscall_function*)sys_read_count},
      {0, (syscall_function*)sys_write_count},
  };

  const struct syscall* sc;
  unsigned call_nr;
  int args[3];

  /* Get the system call. */
  copy_in(&call_nr, f->esp, sizeof call_nr);
  if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
    process_exit();
  sc = syscall_table + call_nr;

  if (sc->func == NULL)
    process_exit();

  /* Get the system call arguments. */
  ASSERT(sc->arg_cnt <= sizeof args / sizeof *args);
  memset(args, 0, sizeof args);
  copy_in(args, (uint32_t*)f->esp + 1, sizeof *args * sc->arg_cnt);

  /* Execute the system call,
     and set the return value. */
  f->eax = sc->func(args[0], args[1], args[2]);
}

/* Closes a file safely */
void safe_file_close(struct file* file) { file_close(file); }

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool verify_user(const void* uaddr) {
  return (uaddr < PHYS_BASE && pagedir_get_page(thread_current()->pcb->pagedir, uaddr) != NULL);
}

/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool get_user(uint8_t* dst, const uint8_t* usrc) {
  int eax;
  asm("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:" : "=m"(*dst), "=&a"(eax) : "m"(*usrc));
  return eax != 0;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool put_user(uint8_t* udst, uint8_t byte) {
  int eax;
  asm("movl $1f, %%eax; movb %b2, %0; 1:" : "=m"(*udst), "=&a"(eax) : "q"(byte));
  return eax != 0;
}

/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call process_exit() if any of the user accesses are invalid. */
static void copy_in(void* dst_, const void* usrc_, size_t size) {
  uint8_t* dst = dst_;
  const uint8_t* usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
    if (usrc >= (uint8_t*)PHYS_BASE || !get_user(dst, usrc))
      process_exit();
}

/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call process_exit() if any of the user accesses are invalid. */
static char* copy_in_string(const char* us) {
  char* ks;
  size_t length;

  ks = palloc_get_page(0);
  if (ks == NULL)
    process_exit();

  for (length = 0; length < PGSIZE; length++) {
    if (us >= (char*)PHYS_BASE || !get_user(ks + length, us++)) {
      palloc_free_page(ks);
      process_exit();
    }

    if (ks[length] == '\0')
      return ks;
  }
  ks[PGSIZE - 1] = '\0';
  return ks;
}

double sys_hit_rate() { return buffer_cache_hit_rate(); }

void sys_flush_cache() { buffer_cache_flush(); }

int sys_read_count() { return block_get_reads(fs_device); }

int sys_write_count() { return block_get_writes(fs_device); }

/* inode system call. */
int sys_inumber(int handle) {
  struct file_descriptor* fd = lookup_fd(handle);

  if (fd->is_directory) {
    return dir_get_inode(fd->dir)->sector;
  } else {
    return dir_get_inode(fd->file)->sector;
  }
}

bool sys_chdir(const char* udir) {
  char* kdir = copy_in_string(udir);
  char* kdir_copy = kdir;
  bool ok = false;

  /* Two situations:
   * 1. KDIR is an absolute path AKA the path begins with '/'. 
   * We search starting from the root directory.
   * 2. KDIR is a relative path AKA the path does not begin with '/'.
   * We search starting from the cwd directory of the process.
   */

  size_t len = strlen(kdir);
  if (len == 0) {
    palloc_free_page(kdir);
    return ok;
  }

  struct dir* cwd;
  if (kdir[0] == '/') {
    cwd = dir_open_root();
  } else {
    cwd = dir_reopen(thread_current()->pcb->cwd);
  }

  if (cwd == NULL) {
    palloc_free_page(kdir);
    return ok;
  }

  char path_part[NAME_MAX + 1];
  int result;
  bool not_found = false;
  while ((result = get_next_part(path_part, &kdir)) == 1) {
    /* Search the cwd for the dir_entry with PATH_PART name. */
    /* NOTE: If user put a file in a non-terminating position,
     * this has unknown behavior. */
    struct inode* dir_inode;
    bool is_dir;
    bool found = dir_lookup(cwd, path_part, &dir_inode, &is_dir);
    if (found && is_dir) {
      dir_close(cwd);
      cwd = dir_open(dir_inode);
    } else {
      not_found = true;
      break;
    }
  }

  ok = !not_found && result != -1;
  if (ok) {
    /* Change directory. */
    dir_close(thread_current()->pcb->cwd);
    thread_current()->pcb->cwd = cwd;
  } else {
    dir_close(cwd);
  }

  palloc_free_page(kdir_copy);
  return ok;
}

/* Returns whether the path is empty AKA the last. */
static bool is_last(const char* path) {
  while (*path == '/') {
    path++;
  }

  return *path == '\0';
}

bool sys_mkdir(const char* udir) {
  char* kdir = copy_in_string(udir);
  char* kdir_copy = kdir;
  bool ok = false;

  int len = strlen(kdir);
  if (len == 0) {
    palloc_free_page(kdir);
    return ok;
  }

  struct dir* cwd;

  if (kdir[0] == '/') {
    cwd = dir_open_root();
  } else {
    cwd = dir_reopen(thread_current()->pcb->cwd);
  }

  if (cwd == NULL) {
    palloc_free_page(kdir);
    return ok;
  }

  int result;
  char path_part[NAME_MAX + 1];
  // "a/b/c"
  while ((result = get_next_part(path_part, &kdir)) == 1) {
    struct inode* dir_inode;
    bool is_dir;
    bool found = dir_lookup(cwd, path_part, &dir_inode, &is_dir);
    if (is_last(kdir)) {
      /* Make sure PATH_PART doesn't exist. */
      if (!found)
        ok = filesys_create_dir(path_part, cwd);
      else
        inode_close(dir_inode);
    } else {
      /* Make sure PATH_PART does exist. */
      if (found && is_dir) {
        dir_close(cwd);
        cwd = dir_open(dir_inode);
      } else {
        break;
      }
    }
  }

  dir_close(cwd);
  palloc_free_page(kdir_copy);
  return ok;
}

/* Halt system call. */
int sys_halt(void) { shutdown_power_off(); }

/* Exit system call. */
int sys_exit(int exit_code) {
  thread_current()->pcb->wait_status->exit_code = exit_code;
  process_exit();
  NOT_REACHED();
}

/* Exec system call. */
int sys_exec(const char* ufile) {
  pid_t tid;
  char* kfile = copy_in_string(ufile);
  char* kfile_copy = kfile;

  if (strlen(kfile) == 0) {
    palloc_free_page(kfile);
    return -1;
  }

  /* Split the exec string into two parts:
   * The path and the arguments.
   */
  char *exec_path, *args;
  exec_path = strtok_r(kfile, " ", &args);

  struct dir* cwd;
  if (exec_path[0] == '/')
    cwd = dir_open_root();
  else
    cwd = dir_reopen(thread_current()->pcb->cwd);

  if (cwd == NULL) {
    palloc_free_page(kfile_copy);
    return -1;
  }

  char path_part[NAME_MAX + 1];
  int result;
  bool valid = false;

  while ((result = get_next_part(path_part, &exec_path)) == 1) {
    struct inode* inode;
    bool is_dir;
    bool found = dir_lookup(cwd, path_part, &inode, &is_dir);
    bool last = is_last(exec_path);

    if (last) {

      /* Make sure exe exists. */
      if (!found || is_dir)
        break;

      valid = true;
      inode_close(inode);
    } else {
      if (!found || !is_dir)
        break;

      dir_close(cwd);
      dir_open(inode);
    }
  }

  dir_close(cwd);

  if (valid) {
    int args_len = strlen(args);
    int exec_len = strlen(path_part);
    if (args_len > 0) {
      char args_formatted[args_len + exec_len + 2];
      memcpy(args_formatted, path_part, exec_len);
      args_formatted[exec_len] = ' ';
      memcpy(args_formatted + exec_len + 1, args, args_len);
      args_formatted[exec_len + args_len + 1] = '\0';

      tid = process_execute(args_formatted);
    } else {
      tid = process_execute(path_part);
    }
  } else {
    tid = -1;
  }

  palloc_free_page(kfile_copy);
  return tid;
}

/* Wait system call. */
int sys_wait(pid_t child) { return process_wait(child); }

/* Create system call. */
int sys_create(const char* ufile, unsigned initial_size) {
  char* kfile = copy_in_string(ufile);
  char* kfile_copy = kfile;
  bool ok = false;

  if (strlen(kfile) == 0) {
    palloc_free_page(kfile);
    return ok;
  }

  struct dir* cwd;
  if (kfile[0] == '/')
    cwd = dir_open_root();
  else
    cwd = dir_reopen(thread_current()->pcb->cwd);

  char path_part[NAME_MAX + 1];
  int result;
  while ((result = get_next_part(path_part, &kfile)) == 1) {
    struct inode* file_inode;
    bool is_dir;
    bool found = dir_lookup(cwd, path_part, &file_inode, &is_dir);

    if (is_last(kfile)) {
      /* Create the file in CWD. */
      if (found) {
        inode_close(file_inode);
        break;
      }

      ok = filesys_create_file(path_part, cwd, initial_size);
    } else {
      /* Navigate to next dir. */
      if (!found)
        break;

      if (!is_dir)
        break;

      dir_close(cwd);
      cwd = dir_open(file_inode);
    }
  }

  dir_close(cwd);
  palloc_free_page(kfile_copy);
  return ok;
}

/* Remove system call. */
int sys_remove(const char* ufile) {
  char* kfile = copy_in_string(ufile);
  char* kfile_copy = kfile;
  bool ok = false;

  if (strlen(kfile) == 0) {
    palloc_free_page(kfile);
    return ok;
  }

  struct dir* cwd;
  if (kfile[0] == '/') {
    if (strlen(kfile) == 1) {
      /* Cannot remove the root directory. */
      palloc_free_page(kfile);
      return ok;
    }
    cwd = dir_open_root();
  } else {
    cwd = dir_reopen(thread_current()->pcb->cwd);
  }

  char path_part[NAME_MAX + 1];
  int result;

  while ((result = get_next_part(path_part, &kfile)) == 1) {
    struct inode* inode;
    bool is_dir;
    bool found = dir_lookup(cwd, path_part, &inode, &is_dir);

    if (!found)
      break;

    if (is_last(kfile)) {
      inode_close(inode);
      if (is_dir)
        ok = filesys_remove_dir(path_part, cwd);
      else
        ok = filesys_remove_file(path_part, cwd);
    } else {
      if (!is_dir)
        break;

      dir_close(cwd);
      cwd = dir_open(inode);
    }
  }

  dir_close(cwd);
  palloc_free_page(kfile_copy);
  return ok;
}

/* Open system call. */
int sys_open(const char* ufile) {
  char* kfile = copy_in_string(ufile);
  char* kfile_copy = kfile;
  struct file_descriptor* fd;
  int handle = -1;

  int len = strlen(kfile);
  if (len == 0) {
    palloc_free_page(kfile);
    return handle;
  }

  fd = malloc(sizeof *fd);
  if (fd != NULL) {

    struct dir* cwd;
    if (kfile[0] == '/') {
      if (len == 1) {
        fd->is_directory = true;
        fd->dir = dir_open_root();
        if (fd->dir == NULL) {
          free(fd);
        } else {
          handle = fd->handle = thread_current()->pcb->next_handle++;
          list_push_front(&thread_current()->pcb->fds, &fd->elem);
        }

        palloc_free_page(kfile);
        return handle;
      }
      cwd = dir_open_root();
    } else {
      cwd = dir_reopen(thread_current()->pcb->cwd);
    }

    char path_part[NAME_MAX + 1];
    int result;
    while ((result = get_next_part(path_part, &kfile)) == 1) {
      struct inode* file_inode;
      bool is_dir;
      bool found = dir_lookup(cwd, path_part, &file_inode, &is_dir);

      if (is_last(kfile)) {
        if (!found) {
          free(fd);
          break;
        }

        inode_close(file_inode);
        bool success = false;
        fd->is_directory = is_dir;
        if (is_dir) {
          fd->dir = filesys_open_dir(path_part, cwd);
          success = fd->dir != NULL;
        } else {
          fd->file = filesys_open_file(path_part, cwd);
          success = fd->file != NULL;
        }

        if (success) {
          struct thread* cur = thread_current();
          handle = fd->handle = cur->pcb->next_handle++;
          list_push_front(&cur->pcb->fds, &fd->elem);
        } else {
          free(fd);
        }

      } else {
        /* Continue searching in next dir. */
        if (!found) {
          free(fd);
          break;
        }

        dir_close(cwd);
        cwd = dir_open(file_inode);
      }
    }

    dir_close(cwd);
  }

  palloc_free_page(kfile_copy);
  return handle;
}

bool sys_isdir(int handle) {
  struct file_descriptor* fd = lookup_fd(handle);
  return fd->is_directory;
}

bool sys_readdir(int handle, char* udst_) {
  char* udst = udst_;
  struct file_descriptor* fd = lookup_fd(handle);

  if (!fd->is_directory)
    return false;

  for (int i = 0; i < READDIR_MAX_LEN + 1; i++) {
    if (!verify_user(udst + i))
      process_exit();
  }

  return dir_readdir(fd->dir, udst);
}

/* Returns the file descriptor associated with the given handle.
   Terminates the process if HANDLE is not associated with an
   open file. */
static struct file_descriptor* lookup_fd(int handle) {
  struct thread* cur = thread_current();
  struct list_elem* e;

  for (e = list_begin(&cur->pcb->fds); e != list_end(&cur->pcb->fds); e = list_next(e)) {
    struct file_descriptor* fd;
    fd = list_entry(e, struct file_descriptor, elem);
    if (fd->handle == handle)
      return fd;
  }

  process_exit();
  NOT_REACHED();
}

/* Filesize system call. */
int sys_filesize(int handle) {
  struct file_descriptor* fd = lookup_fd(handle);
  int size;

  size = file_length(fd->file);

  return size;
}

/* Read system call. */
int sys_read(int handle, void* udst_, unsigned size) {
  uint8_t* udst = udst_;
  struct file_descriptor* fd;
  int bytes_read = 0;

  /* Handle keyboard reads. */
  if (handle == STDIN_FILENO) {
    for (bytes_read = 0; (size_t)bytes_read < size; bytes_read++)
      if (udst >= (uint8_t*)PHYS_BASE || !put_user(udst++, input_getc()))
        process_exit();
    return bytes_read;
  }

  /* Handle all other reads. */
  fd = lookup_fd(handle);

  if (fd->is_directory)
    process_exit();

  while (size > 0) {
    /* How much to read into this page? */
    size_t page_left = PGSIZE - pg_ofs(udst);
    size_t read_amt = size < page_left ? size : page_left;
    off_t retval;

    /* Check that touching this page is okay. */
    if (!verify_user(udst)) {
      process_exit();
    }

    /* Read from file into page. */
    retval = file_read(fd->file, udst, read_amt);
    if (retval < 0) {
      if (bytes_read == 0)
        bytes_read = -1;
      break;
    }
    bytes_read += retval;

    /* If it was a short read we're done. */
    if (retval != (off_t)read_amt)
      break;

    /* Advance. */
    udst += retval;
    size -= retval;
  }

  return bytes_read;
}

/* Write system call. */
int sys_write(int handle, void* usrc_, unsigned size) {
  uint8_t* usrc = usrc_;
  struct file_descriptor* fd = NULL;
  int bytes_written = 0;

  /* Lookup up file descriptor. */
  if (handle != STDOUT_FILENO) {
    fd = lookup_fd(handle);
    if (fd->is_directory) {
      process_exit();
    }
  }

  while (size > 0) {
    /* How much bytes to write to this page? */
    size_t page_left = PGSIZE - pg_ofs(usrc);
    size_t write_amt = size < page_left ? size : page_left;
    off_t retval;

    /* Check that we can touch this user page. */
    if (!verify_user(usrc)) {
      process_exit();
    }

    /* Do the write. */
    if (handle == STDOUT_FILENO) {
      putbuf(usrc, write_amt);
      retval = write_amt;
    } else
      retval = file_write(fd->file, usrc, write_amt);
    if (retval < 0) {
      if (bytes_written == 0)
        bytes_written = -1;
      break;
    }
    bytes_written += retval;

    /* If it was a short write we're done. */
    if (retval != (off_t)write_amt)
      break;

    /* Advance. */
    usrc += retval;
    size -= retval;
  }

  return bytes_written;
}

/* Seek system call. */
int sys_seek(int handle, unsigned position) {
  struct file_descriptor* fd = lookup_fd(handle);

  if ((off_t)position >= 0)
    file_seek(fd->file, position);

  return 0;
}

/* Tell system call. */
int sys_tell(int handle) {
  struct file_descriptor* fd = lookup_fd(handle);
  unsigned position;

  position = file_tell(fd->file);

  return position;
}

/* Close system call. */
int sys_close(int handle) {
  struct file_descriptor* fd = lookup_fd(handle);

  if (fd->is_directory) {
    dir_close(fd->dir);
  } else {
    safe_file_close(fd->file);
  }

  list_remove(&fd->elem);
  free(fd);
  return 0;
}

/* Practice system call. */
int sys_practice(int input) { return input + 1; }

/* Compute e and return a float cast to an int */
int sys_compute_e(int n) { return sys_sum_to_e(n); }

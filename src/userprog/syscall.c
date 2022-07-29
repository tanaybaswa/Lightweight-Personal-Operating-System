#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/malloc.h"

static struct lock filesyscall_lock; 


static int get_next_fd(void);
static struct file* get_file(int fd);
static void syscall_handler(struct intr_frame*);
static void validate_stack(uint32_t* esp, int bytes, bool allow_rw);
static bool create(const char* file, unsigned initial_size);
static bool remove(const char* file);
static int open(const char* file);
static int filesize(int fd);
static int read(int fd, void* buffer, unsigned size);
static int write(int fd, const void* buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);
int sys_sum_to_e(int);



void syscall_init(void) { 
  lock_init(&filesyscall_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  /* Validate the stack pointer (switch argument). */
  validate_stack(args, 4, true);


  int fd;
  switch(*args++) {
    case SYS_EXIT:
      validate_stack(args, sizeof(int), true);
      f->eax = args[0];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[0]);
      process_exit((int)args[0]);
      break;

    case SYS_PRACTICE:
      validate_stack(args, sizeof(int), true);
      f->eax = (int)args[0] + 1;
      break;

    case SYS_EXEC:
      validate_stack(args, sizeof(char**), true);
      validate_stack((uint32_t*)args[0], sizeof(char*), true);
      f->eax = process_execute((char*)args[0]);
      break;

    case SYS_WAIT:
      validate_stack(args, sizeof(pid_t), true);
      f->eax = process_wait((pid_t)args[0]);
      break;

    case SYS_HALT:
      shutdown_power_off();
      break;

    case SYS_CREATE:
      validate_stack(args, sizeof(char**), true);
      validate_stack((uint32_t*)args[0], sizeof(char*), true);
      const char* file = (const char*)(*args++); 
      validate_stack(args, sizeof(unsigned), true);
      bool created = create(file, args[0]);
      f->eax = created;
      break;

    case SYS_REMOVE:
      validate_stack(args, sizeof(char**), true);
      validate_stack((uint32_t*)args[0], sizeof(char*), true);
      bool removed = remove((char*)args[0]);
      f->eax = removed;
      break;

    case SYS_OPEN:
      validate_stack(args, sizeof(char**), true);
      validate_stack((uint32_t*)args[0], sizeof(char*), true);
      fd = open((char*)args[0]);
      f->eax = fd;
      break;

    case SYS_WRITE:
      validate_stack(args, sizeof(int), true);
      fd = (int)(*args++);
      validate_stack(args, sizeof(void**), true);
      validate_stack((void*)args[0], sizeof(void*), true);
      const void* buffer_k = (const void*)(*args++);
      validate_stack(args, sizeof(unsigned), true);


      if(fd == 1) { // STDOUT_FILENO = 1
        lock_acquire(&filesyscall_lock);
        putbuf((char*)buffer_k, args[0]);
        lock_release(&filesyscall_lock);
      } else {
        int num_bytes = write(fd, buffer_k, args[0]);
        f->eax = num_bytes;
      }
      break;

    case SYS_FILESIZE:
      validate_stack(args, sizeof(int), true);
      f->eax = filesize((int)args[0]);
      break;

    case SYS_READ:
      validate_stack(args, sizeof(int), true);
      fd = (int)(*args++);
      validate_stack(args, sizeof(void**), true);
      validate_stack((void*)args[0], sizeof(void*), true);
      void* buffer = (void*)(*args++);
      validate_stack(args, sizeof(unsigned), true);

      if (fd == 0) { // STDIN_FILENO = 0
        lock_acquire(&filesyscall_lock);
        uint8_t key = input_getc();
        lock_release(&filesyscall_lock);
        f->eax = key;
      } else {
        int num_bytes = read(fd, buffer, args[0]);
        f->eax = num_bytes;
      }
      break;

    case SYS_SEEK:
      validate_stack(args, sizeof(int), true);
      fd = (int)(*args++);
      validate_stack(args, sizeof(unsigned), true);
      seek(fd, args[0]);
      break;

    case SYS_TELL:
      validate_stack(args, sizeof(int), 1);
      unsigned pos = tell(args[0]);
      f->eax = pos;
      break;

    case SYS_CLOSE:
      validate_stack(args, sizeof(int), 1);
      close(args[0]);
      break;

    case SYS_COMPUTE_E:
      validate_stack(args, sizeof(int), 1);
      f->eax = sys_sum_to_e((int)args[0]);
      break;

    default:
      break;
  }
}

static void validate_stack(uint32_t* esp, int bytes, bool allow_rw) {
#define INVALID_STACK -1
  int i;
  uint8_t* esp8 = (uint8_t*)esp;
  uint32_t* pd_base = thread_current()->pcb->pagedir;
  for(i = 0; i < bytes; i++) {
    if(!esp8) break;
    if(!is_user_vaddr(esp8)) break;
    uint32_t* pte = lookup_page(pd_base, esp8, false);
    if(!pte) break; /* No page table entry existed. Bad. */
    uint32_t pte_stored = *pte;

  /* Use PTE and check proper flags for user.
   *
   *
   *
   * PTE_FLAGS (0x00000fff): mask only flag bits.
   * PTE_P (0x1): 1=present, 0=not present.
   * PTE_W (0x2): 1=r/w, 0=read-only
   * PTE_U (0x4): 1=user/kernel, 0=kernel only.
   */
    uint32_t pte_flags = pte_stored & PTE_FLAGS;
    if(((pte_flags & PTE_P) != PTE_P) ||
        ((pte_flags & PTE_U) != PTE_U)) { break; }
    if(!allow_rw) {
      if((pte_flags & PTE_W) == PTE_W) { break; }
    }

    esp8 += 1;
  }

  if(i == bytes) return;
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, INVALID_STACK);
  process_exit(INVALID_STACK);
#undef INVALID_STACK
}


/* creates new file of initial_size bytes, return whether succesful or not */
static bool create(const char* file, unsigned initial_size) {
  lock_acquire(&filesyscall_lock); 
  bool success = filesys_create(file, initial_size);
  lock_release(&filesyscall_lock);
  return success;
}

/* deletes file, return whether successful or not */
static bool remove(const char* file) {
  lock_acquire(&filesyscall_lock); 
  bool success = filesys_remove(file);
  lock_release(&filesyscall_lock);
  return success;
}

/* opens file, returns nonnegative file descriptor or -1 if failed to open */
int open(const char* filename) {
  struct file** fd_table = thread_current()->pcb->fd_table;
  struct file* file;
  lock_acquire(&filesyscall_lock);
  file = filesys_open(filename);
  lock_release(&filesyscall_lock);
  
  if(file == NULL)
    return -1;

  int fd = get_next_fd();
  fd_table[fd] = file;
  return fd;
}


int filesize(int fd) {
  struct file* file = get_file(fd);
  if(file == NULL)
    return -1;

  lock_acquire(&filesyscall_lock);
  int size = file_length(file);
  lock_release(&filesyscall_lock);
  return size;
}

int read(int fd, void* buffer, unsigned size) {
  struct file* file = get_file(fd);
  if (file == NULL)
    return -1;

  lock_acquire(&filesyscall_lock);
  int num_bytes_read = file_read(file, buffer, size);
  lock_release(&filesyscall_lock);
  return num_bytes_read;
}

/* writes size number of bytes from buffer, return num bytes written */
int write(int fd, const void* buffer, unsigned size) {
  struct file* file = get_file(fd);
  if (file == NULL)
    return -1;

  lock_acquire(&filesyscall_lock);
  int num_bytes_written = file_write(file, buffer, size);
  lock_release(&filesyscall_lock);
  return num_bytes_written;
}

void seek(int fd, unsigned position) {
  struct file* file = get_file(fd);
  if (file == NULL)
    return;

  lock_acquire(&filesyscall_lock);
  file_seek(file, position);
  lock_release(&filesyscall_lock);
}

unsigned tell(int fd) {
  struct file* file = get_file(fd);
  if (file == NULL)
    return 0;

  lock_acquire(&filesyscall_lock);
  unsigned pos = file_tell(file);
  lock_release(&filesyscall_lock);
  return pos;
}

void close(int fd) {
  struct file** fd_table = thread_current()->pcb->fd_table;
  struct file* file = get_file(fd);
  if(file != NULL) {
    lock_acquire(&filesyscall_lock);
    file_close(file);
    lock_release(&filesyscall_lock);
    fd_table[fd] = NULL;
  }
}

static int get_next_fd() {
  struct file** fd_table = thread_current()->pcb->fd_table;

  for(int i = 3; i < MAX_FD; i++) {
    if(fd_table[i] == NULL)
      return i;
  }

  return MAX_FD;
  ASSERT(false && "No more availible file descriptors.");
}

static struct file* get_file(int fd) {
  if(fd >= MAX_FD || fd < 3)
    return NULL;
  struct file** fd_table = thread_current()->pcb->fd_table;
  return fd_table[fd];
}
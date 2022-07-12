#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static struct lock filesyscall_lock; 
static int next_fd = 3; // minimum fd start with 3


static void syscall_handler(struct intr_frame*);
static void validate_stack(uint32_t* esp, int count);
static bool create(const char* file, unsigned initial_size);
static bool remove(const char* file);
static int get_next_fd();



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

  switch(args[0]) {
    case SYS_EXIT:
      validate_stack(args, 1);
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      process_exit(args[1]);
      break;
    case SYS_PRACTICE:
      validate_stack(args, 1);
      f->eax = args[1] + 1;
      break;
    case SYS_EXEC:
      validate_stack(args, 1);
      //f->eax = process_execute(args[0]);
      break;
    case SYS_WAIT:
      validate_stack(args, 1);
      //f->eax = process_wait(args[0]);
      break;
    case SYS_CREATE:
      validate_stack(args, 2);
      bool created = create(args[1], args[2]);
      f->eax = created;
      break;
    case SYS_REMOVE:
      validate_stack(args, 1);
      bool removed = remove(args[1]);
      f->eax = removed;
      break;
    case SYS_WRITE:
      validate_stack(args, 3);
      if(args[1] == STDOUT_FILENO) {
        // validate_stack(args, 2);
        lock_acquire(&filesyscall_lock);
        putbuf((char*)args[2], args[3]);
        lock_release(&filesyscall_lock);
      } else {
        lock_acquire(&filesyscall_lock);
        // ((char*)args[2], args[3]);
        putbuf(args[1], args[2], args[3]);
        lock_release(&filesyscall_lock);
      }
      break;
    default:
      break;
  }
}

static void validate_stack(uint32_t* esp, int count) {
#define INVALID_STACK -1
  int i;
  return;

  for(i = 0; i < count; i++) {
    /* Check if esp is NULL. */
    if(!esp) break;

    /* Check if esp is a user addr. */
    if(!is_user_vaddr(esp)) break;

    /* Check if esp points to a non-existent page. */
    if(!lookup_page(pg_round_down(esp), esp, false)) break;

    esp += 1; /* Validate the next argument. */
  }

  if(i == count) return;
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

static int get_next_fd() {
  lock_acquire(&filesyscall_lock);
  int fd = next_fd;
  next_fd++;
  lock_release(&filesyscall_lock);
  return fd;
}


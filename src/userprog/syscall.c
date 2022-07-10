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

struct lock filesyscall_lock; 

static void syscall_handler(struct intr_frame*);
static void validate_stack(uint32_t* esp, bool allow_rw);


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

  validate_stack(args, 1);



  switch(*args++) {
    case SYS_EXIT:
      validate_stack(args, 1);
      f->eax = args[0];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[0]);
      process_exit((int)args[0]);
      break;
    case SYS_PRACTICE:
      validate_stack(args, 1);
      f->eax = (int)args[0] + 1;
      break;
    case SYS_EXEC:
      validate_stack(args, 1);
      validate_stack((uint32_t*)args[0], 1);
      f->eax = process_execute((char*)args[0]);
      break;
    case SYS_WAIT:
      validate_stack(args, 1);
      f->eax = process_wait((pid_t)args[0]);
      break;
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_WRITE:
      validate_stack(args, 1);
      if(args[0] == STDOUT_FILENO) {
        validate_stack(args, 1);
        lock_acquire(&filesyscall_lock);
        putbuf((char*)args[1], args[2]);
        lock_release(&filesyscall_lock);
      }
      break;
    default:
      break;
  }
}


static void validate_stack(uint32_t* esp, bool allow_rw) {
#define INVALID_STACK -1
  int i;
  uint8_t* esp8 = (uint8_t*)esp;
  uint32_t* pd_base = thread_current()->pcb->pagedir;
  for(i = 0; i < 4; i++) {
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

  if(i == 4) return;
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, INVALID_STACK);
  process_exit(INVALID_STACK);
#undef INVALID_STACK
}

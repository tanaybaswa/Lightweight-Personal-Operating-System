#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"

static bool is_flag_on(uint8_t p_flags, uint8_t flag);
static void set_flag(uint8_t* p_flags, uint8_t flag, int val);


static thread_func start_process NO_RETURN;
static bool load(char* argv, void (**eip)(void), void** esp);
static int count_words(char* argv);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Always use calloc to insure pcb->pagedir is NULL! */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;
  t->pcb->flags = NO_FLAGS;
  list_init(&t->pcb->children);
  lock_init(&t->pcb->child_lock);
  lock_init(&t->pcb->flag_lock);
  sema_init(&t->pcb->blocked, 0);

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */


  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* argv) {
#define MAX_FILE_NAME_LENGTH 32
  struct thread_args* args = malloc(sizeof(struct thread_args));
  if(args == NULL)
    return -1;

  char* argv_copy, *save_ptr, *file_name;
  char file_name_buf[MAX_FILE_NAME_LENGTH]; 
  tid_t tid;
  struct thread* t = thread_current();

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  argv_copy = palloc_get_page(0);
  if (argv_copy == NULL)
    return TID_ERROR;

  strlcpy(argv_copy, argv, PGSIZE);
  strlcpy(file_name_buf, argv, MAX_FILE_NAME_LENGTH);
  file_name = strtok_r(file_name_buf, " ", &save_ptr);

  args->parent = t->pcb;
  args->argv = argv_copy;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, args);

  if(tid == TID_ERROR) {
    palloc_free_page(argv_copy);
    free(args);
    return -1;
  } else {
    sema_down(&t->pcb->blocked);
    lock_acquire(&t->pcb->flag_lock);
    if(!is_flag_on(t->pcb->flags, CHILD_LOAD_SUCCESS))
      tid = -1;
    lock_release(&t->pcb->flag_lock);
  }


  return tid;
#undef MAX_FILE_NAME_LENGTH
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* argv_) {
  struct thread_args* args = (struct thread_args*)argv_;

  char* argv = args->argv;
  struct intr_frame if_;
  struct thread* t = thread_current();
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = (new_pcb != NULL);

  /* Initialize interrupt frame and load executable. */
  if (success) {
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;
    t->pcb->main_thread = t;
    strlcpy(new_pcb->process_name, t->name, sizeof t->name);
    new_pcb->flags = NO_FLAGS;
    list_init(&new_pcb->children);
    lock_init(&new_pcb->child_lock);
    lock_init(&new_pcb->flag_lock);
    sema_init(&new_pcb->blocked, 0);
    memset(new_pcb->fd_table, 0, MAX_FD * sizeof(int));

    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(argv, &if_.eip, &if_.esp);
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory

    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */
  struct process* parent = args->parent;
  palloc_free_page(args->argv);
  free(args);

  lock_acquire(&parent->flag_lock);
  set_flag(&parent->flags, CHILD_LOAD_SUCCESS, success == true);
  lock_release(&parent->flag_lock);
  if(!success) {
    /* Allows parent to continue. */
    sema_up(&parent->blocked);
    thread_exit();
  } else {
    /* Allows parent to continue. */
    add_child_process(&parent->children, &parent->child_lock, t->pcb);
    t->pcb->parent = parent;
    sema_up(&parent->blocked);
  }


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */

  char fpu[108];
  asm volatile("fsave (%0); fninit; fsave (%1); frstor (%0)" : : "g"(&fpu), "g"(&if_.fpu) : "memory");
  
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  /* First, find the child process to wait on. */
  struct process* parent = thread_current()->pcb;

  struct process* child = NULL;
  if((child = get_child_process(&parent->children, &parent->child_lock, child_pid)) != NULL) {
    parent->awaiting_id = child_pid;
    lock_acquire(&parent->flag_lock);
    set_flag(&parent->flags, PROCESS_WAITING, 1);
    lock_release(&parent->flag_lock);

    /* Two situations:
    1. Child is dead. It will be a empty process with only a status
       and exit code.
    2. Child is alive and running. We wait for child to unblock us.
    */

    lock_acquire(&child->flag_lock);
    bool child_dead = is_flag_on(child->flags, DEAD);
    lock_release(&child->flag_lock);
    if(!child_dead)
      sema_down(&parent->blocked);

    /* Get the return value and free the rest of child. */
    int retval = child->exit_val;

    remove_child_process(&parent->children, &parent->child_lock, child_pid);
    struct thread* old_thread = child->main_thread;
    free(child);
    palloc_free_page(old_thread);
    lock_acquire(&parent->flag_lock);
    set_flag(&parent->flags, PROCESS_WAITING, 0);
    lock_release(&parent->flag_lock);
    return retval;
  }
  return -1;
}


/* Free the current process's resources. */
void process_exit(int code) {
  struct thread* cur = thread_current();
  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  uint32_t* pd = cur->pcb->pagedir;  
  if(pd != NULL) {
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  struct process* child = cur->pcb;
  cur->pcb = NULL;

  /* Get parent. */
  struct process* parent = child->parent;
  child->exit_val = code;
  for(int i = 0; i < MAX_FD; i++) {
    if(child->fd_table[i] != NULL)
      file_close(child->fd_table[i]);
  }

  lock_acquire(&child->flag_lock);
  set_flag(&child->flags, DEAD, 1);
  lock_release(&child->flag_lock);


  /* Check if all our children are dead. If so, reap dead children.
   * If need be, make recurse and make orphans of still alive children. */
  struct list_elem* e;
  for(e = list_begin(&child->children); e != list_end(&child->children); e = list_next(e)) {
    struct process* target = list_entry(e, struct process, elem);
    remove_child_process(&child->children, &child->child_lock, target->main_thread->tid);
    lock_acquire(&target->flag_lock);
    if(is_flag_on(target->flags, DEAD)) {
      free(target);
    } else {
      set_flag(&target->flags, ORPHAN, 1);
    }
    lock_release(&target->flag_lock);
  }

  /* Check if parent is waiting. */
  lock_acquire(&child->flag_lock);
  if(!is_flag_on(child->flags, ORPHAN)) {
    child->main_thread->can_delete = false;
    /* TODO: Critical section. Must implement lock. */
    lock_acquire(&parent->flag_lock);
    bool is_parent_waiting = is_flag_on(parent->flags, PROCESS_WAITING) &&
      parent->awaiting_id == cur->tid;
    lock_release(&parent->flag_lock);

    /* Parent is now in charge of freeing the child. */
    if(is_parent_waiting)
      sema_up(&parent->blocked);
  } else {
    /* Orphan must free itself. */
    free(child);
  }
  lock_release(&child->flag_lock);

  thread_exit();  
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp, char* argv);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(char* argv, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* We create copy for setup_stack. strtok_r modifies string. */
  char argv_copy[strlen(argv) + 1];
  memcpy(argv_copy, argv, strlen(argv) + 1);

  char* file_name, *dummy_p;
  file_name = strtok_r(argv, " ", &dummy_p);

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }
  t->pcb->fd_table[0] = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp, argv_copy))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  if(file)
    file_deny_write(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp, char* argv) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success) {
      *esp = PHYS_BASE;
      uint8_t* sp = *esp; /* Handy alias for *esp. */

      /* Allocate room for the addresses we will be storing. */
      int argc = count_words(argv);
      uint32_t addresses[argc + 1];
      int addr_i = 0;

      /* Get token. */
      char* token, *save_ptr;
      for(token = strtok_r(argv, " ", &save_ptr); token != NULL;
          token = strtok_r(NULL, " ", &save_ptr)) {

        /* Get length of token. */
        int token_len = strlen(token) + 1;
        
        /* Move stack back TOKEN_LEN bytes. */
        sp -= token_len;

        /* Copy token to stack. */
        memcpy(sp, token, token_len);

        /* Copy address of token beginning. */
        addresses[addr_i++] = (uint32_t)sp;
      }

      addresses[argc] = 0x0;
      sp -= 1;

      /* Allign sp on 16-byte boundary. */
      while(((uint32_t)sp - (sizeof(uint32_t*) * (argc + 3))) % 0x10 != 0) {
        memset(sp, 0x0, sizeof(char));
        sp -= 1;
      }

      /* We add num. of argc + 1 + &argv + argc
       *    ie. argc + 3 */

      //int align_count = argc + 4;
      //if(*((uint32_t*)(&sp)) - align_count % 0x10 != 0

      /* Copy addresses of passed in arguments to stack. */
      for(int i = argc; i >= 0; i--) {
        sp -= sizeof(uint32_t);
        memcpy(sp, &addresses[i], sizeof(uint32_t));
      }

      /* Copy address of the beginning of argv. */
      memcpy(sp - sizeof(uint32_t), &sp, sizeof(uint32_t));
      sp -= sizeof(uint32_t);

      /* Push argc to stack. */
      sp -= sizeof(int);
      memcpy(sp, &argc, sizeof(int));

      /* Push dummy return address to stack. */
      sp -= sizeof(void*);
      memset(sp, 0x0, sizeof(void*));

      /* Re-assign the actual stack pointer. */
      *esp = (void*)sp;

    } else {
      palloc_free_page(kpage);
    }
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Counts words in a single string. */
static int count_words(char* source) {
  int count = 0;
  char* start = source;
  char* curr = source;

  while(true) {
    while(*start != '\0' && *start == ' ') start++;
    curr = start;
    while(*curr != '\0' && *curr != ' ') curr++;
    int len = curr - start;
    if(len == 0) break;
    count++;
    start = curr;
  }
  return count;
}

static bool is_flag_on(uint8_t p_flags, uint8_t flag) {
  return (p_flags & flag) == flag;
}

static void set_flag(uint8_t* p_flags, uint8_t flag, int val) {
  if(!val) {
    /* Clear flag. */
    *p_flags = val & ~flag;
  } else {
    /* Turn flag on. */
    *p_flags = val | flag;
  }
}

void add_child_process(struct list* list, struct lock* lock, struct process* child) {
  lock_acquire(lock);
  list_push_back(list, &child->elem);
  lock_release(lock);
}

struct process* get_child_process(struct list* list, struct lock* lock, pid_t pid) {
  lock_acquire(lock);

  struct list_elem* e;
  for(e = list_begin(list); e != list_end(list); e = list_next(e)) {
    struct process* process = list_entry(e, struct process, elem);
    if(process->main_thread->tid == pid) {
      lock_release(lock);
      return process;
    }
  }

  lock_release(lock);
  return NULL;
}

void remove_child_process(struct list* list, struct lock* lock, pid_t pid) {
  struct process* child = get_child_process(list, lock, pid);
  if(child == NULL)
    return;

  lock_acquire(lock);
  list_remove(&child->elem);
  lock_release(lock);
}

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

static struct semaphore temporary;
static struct rw_lock pcb_index_lock;
static struct hash pcb_index;
static void add_process(struct hash* map, pid_t pid, struct process* process);
static struct process* get_process(struct hash* map, pid_t pid);
static void remove_process(struct hash* map, pid_t pid);
static void free_process(struct process* process);
static struct process* init_process(void);


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

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  rw_lock_acquire(&pcb_index_lock, false);
  add_process(&pcb_index, t->tid, t->pcb);
  rw_lock_release(&pcb_index_lock, false);

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* argv) {
  char* argv_copy;
  char filenamebuf[15]; // max file name length is 14 + null char
  char* saveptr, *filename;
  tid_t tid;

  sema_init(&temporary, 0);
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  argv_copy = palloc_get_page(0);
  if (argv_copy == NULL)
    return TID_ERROR;
  strlcpy(argv_copy, argv, PGSIZE);

  /* Copy the name of file into file_name. Use argv, not argv_copy because
   * strtok_r modifies the original. 
   */
  strlcpy(filenamebuf, argv, 15);
  filename = strtok_r(filenamebuf, " ", &saveptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(filename, PRI_DEFAULT, start_process, argv_copy);
  if (tid == TID_ERROR)
    palloc_free_page(argv_copy);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* argv_) {
  char* argv = (char*)argv_;
  struct intr_frame if_;
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = init_process();
  success = pcb_success = (new_pcb != NULL);

  /* Initialize interrupt frame and load executable. */
  if (success) {
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
    free_process(new_pcb);
  }

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(argv);
  if (!success) {
    sema_up(&temporary);
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
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
int process_wait(pid_t child_pid UNUSED) {
  sema_down(&temporary);
  return 0;
}

/* Free the current process's resources. */
void process_exit(int code) {
  struct thread* cur = thread_current();

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  free_process(cur->pcb);

  sema_up(&temporary);
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
  file_close(file);
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
      while(*((uint32_t*)(&sp)) % 0x10 != 0) {
        memset(sp, 0x0, sizeof(char));
        sp -= 1;
      }

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

/* Functions for for adding/removing/getting from a pcb HASH. */

static bool pcb_less(const struct hash_elem* a, const struct hash_elem* b, void* aux);
static unsigned pcb_hash(const struct hash_elem* e, void* aux);
static void pcb_destructor(struct hash_elem* e, void* aux);


bool init_pcb_index(void) {
  rw_lock_init(&pcb_index_lock);
  return hash_init(&pcb_index, pcb_hash, pcb_less, NULL);
}


static bool pcb_less(const struct hash_elem* a, const struct hash_elem* b, void* aux) {
  struct process_h* pa = hash_entry(a, struct process_h, hash_elem);
  struct process_h* pb = hash_entry(b, struct process_h, hash_elem);
  return pa->pid - pb->pid;
}


static unsigned pcb_hash(const struct hash_elem* e, void* aux) {
  struct process_h* p = hash_entry(e, struct process_h, hash_elem);
  return p->pid;
}


static struct process* get_process(struct hash* map, pid_t pid) {
  struct process_h temp;
  temp.pid = pid;
  struct hash_elem* e = hash_find(map, &temp.hash_elem);
  if(!e) {
    return NULL;
  }
  struct process_h* found = hash_entry(e, struct process_h, hash_elem);
  return found->process;
}


static void add_process(struct hash* map, pid_t pid, struct process* process) {
  struct process_h* temp = malloc(sizeof(struct process_h));
  temp->pid = pid;
  temp->process = process;
  /* TODO: Add check to assure that PID hasn't already been added? */
  hash_insert(map, &temp->hash_elem);
}


static bool is_process_in(struct hash* map, pid_t pid) {
  struct process_h temp;
  temp.pid = pid;
  struct hash_elem* e = hash_find(map, &temp.hash_elem);
  if(e) return true;
  return false;
}

static void remove_process(struct hash* map, pid_t pid) {
  struct process_h temp;
  temp.pid = pid;
  struct hash_elem* e = hash_delete(map, &temp.hash_elem);
  struct process_h* p = hash_entry(e, struct process_h, hash_elem);
  free(p);
}

/* Functions for initializing and freeing a process. */

static struct process* init_process(void) {
  struct thread* thread = thread_current();
  struct process* new_process = NULL;

  new_process = malloc(sizeof(struct process));
  if(!new_process) return NULL;

  new_process->pagedir = NULL;
  thread->pcb = new_process;
  new_process->main_thread = thread;
  strlcpy(new_process->process_name, thread->name, sizeof thread->name);
  lock_init(&new_process->children_lock);
  hash_init(&new_process->children, pcb_hash, pcb_less, NULL);

  rw_lock_acquire(&pcb_index_lock, false);
  add_process(&pcb_index, thread->tid, new_process);
  rw_lock_release(&pcb_index_lock, false);

  return new_process;
}

static void free_process(struct process* process) {
  struct thread* thread = thread_current();

  rw_lock_acquire(&pcb_index_lock, false);
  remove_process(&pcb_index, thread->tid);
  rw_lock_release(&pcb_index_lock, false);

  uint32_t* pd = process->pagedir;
  if(pd != NULL) {
    process->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Lock not necessary because removed from PCB_INDEX. */
  hash_destroy(&process->children, pcb_destructor);

  thread->pcb = NULL;
  free(process);
}

static void pcb_destructor(struct hash_elem* e, void* aux) {
  struct process_h* p = hash_entry(e, struct process_h, hash_elem);
  free(p);
}

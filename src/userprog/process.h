#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/kernel/hash.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127
#define MAX_FD 32

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;           /* Page directory. */
  char process_name[16];       /* Name of the main thread */
  struct thread* main_thread;  /* Pointer to main thread */

  struct lock child_lock;
  struct list children;        /* Hash of pid_t/struct process*  */
  struct semaphore blocked;    /* Semaphore used for wait/exec func. calls. */
  struct file* fd_table[MAX_FD];

  uint8_t flags;
  struct lock flag_lock;
  pid_t awaiting_id;

  struct list_elem elem;
  struct process* parent;
  int exit_val;
};

enum process_flags {
  NO_FLAGS = 0,
  CHILD_LOAD_SUCCESS = 1,
  PROCESS_WAITING = 2,
  DEAD = 4,
  ORPHAN = 8
};

void userprog_init(void);

pid_t process_execute(const char* argv);
int process_wait(pid_t);
void process_exit(int code);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

struct thread_args {
  struct process* parent;
  char* argv;
};

void add_child_process(struct list*, struct lock*, struct process*);
struct process* get_child_process(struct list*, struct lock*, pid_t);
void remove_child_process(struct list*, struct lock*, pid_t);


#endif /* userprog/process.h */

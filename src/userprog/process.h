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
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */

  struct hash children;       /* List of alive children. */
  struct lock children_lock;  /* Lock used for above list. */
};

void userprog_init(void);

pid_t process_execute(const char* argv);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

/*
 * Internal struct for using processes in a hash map.
 * Hashes a pid_t to a struct process*. Note that this
 * only functions because pids are unique.
 */
struct process_h {
  struct hash_elem hash_elem;
  pid_t pid;
  struct process* process;
};

bool init_pcb_index(void);

/*
 * Internal struct for tracking a process' children.
 * Must use with lock (in struct process).
 */


struct process_l {
  struct list_elem list_elem;
  pid_t pid;
};

#endif /* userprog/process.h */

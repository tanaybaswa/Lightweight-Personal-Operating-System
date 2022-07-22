/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"


static bool lock_sort_needed(struct lock*);
static bool lock_prio_less(const struct list_elem*, const struct list_elem*, void*);
static void lock_collect(struct lock*, struct thread*);
static void lock_lose(struct lock*);
static void lock_find_max(struct lock*);

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void sema_init(struct semaphore* sema, unsigned value) {
  ASSERT(sema != NULL);

  sema->value = value;
  list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void sema_down(struct semaphore* sema) {
  enum intr_level old_level;

  ASSERT(sema != NULL);
  ASSERT(!intr_context());

  old_level = intr_disable();
  while (sema->value == 0) {
    list_push_back(&sema->waiters, &thread_current()->elem);
    thread_block();
  }
  sema->value--;
  intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore* sema) {
  enum intr_level old_level;
  bool success;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (sema->value > 0) {
    sema->value--;
    success = true;
  } else
    success = false;
  intr_set_level(old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void sema_up(struct semaphore* sema) {
  enum intr_level old_level;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (!list_empty(&sema->waiters)) {
    /* TODO: This doesn't seem to work. Fix. */
    list_sort(&sema->waiters, thread_prio_less, NULL);
    thread_unblock(list_entry(list_pop_front(&sema->waiters), struct thread, elem));
  }
  sema->value++;
  intr_set_level(old_level);

  if(!intr_context())
    thread_preempt();
}

static void sema_test_helper(void* sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void) {
  struct semaphore sema[2];
  int i;

  printf("Testing semaphores...");
  sema_init(&sema[0], 0);
  sema_init(&sema[1], 0);
  thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) {
    sema_up(&sema[0]);
    sema_down(&sema[1]);
  }
  printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper(void* sema_) {
  struct semaphore* sema = sema_;
  int i;

  for (i = 0; i < 10; i++) {
    sema_down(&sema[0]);
    sema_up(&sema[1]);
  }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock* lock) {
  ASSERT(lock != NULL);

  lock->holder = NULL;
  lock->priority = PRI_MIN - 1;
  lock->tid_priority = -1;
  sema_init(&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void lock_acquire(struct lock* lock) {
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(!lock_held_by_current_thread(lock));
  enum intr_level old_level;
  old_level = intr_disable();

  /* Set lock to current thread's waiting lock. */
  struct thread* curr_t = thread_current();
  curr_t->waiting = lock;

  /* Must update lock priority/tid. */
  lock_set_priority(lock, curr_t->tid, curr_t->effective_priority);

  /* Sleep on lock. */
  while(lock->semaphore.value == 0) {
    list_push_back(&lock->semaphore.waiters, &curr_t->elem);
    thread_block();
  }

  /* Wake up. NOTE: It is vital that we set WAITING to NULL first
   * because thread_set_eff_priority will attempt to call
   * lock_set_priority if WAITING is not NULL. Also important is to
   * now set lock holder within interrupt or else the current thread
   * might miss a donation. */
  curr_t->waiting = NULL;
  thread_set_eff_priority(curr_t, lock->priority);

  /* We add the lock to the current thread's list of locks here to
   * prevent extra checking when a thread has no locks. */
  (lock->semaphore.value)--;
  lock_collect(lock, curr_t);
  intr_set_level(old_level);
}

static void lock_collect(struct lock* lock, struct thread* t) {
  lock->holder = t;

  /* Insert lock into T's list. */
  list_insert_ordered(&t->locks, &lock->elem, lock_prio_less, NULL);
}

static void lock_lose(struct lock* lock) {
  lock->holder = NULL;
  list_remove(&lock->elem);

  /* In case the current thread acquired more locks using a donation
   * from this lock, we must iterate through all the thread's locks
   * and inform them of the priority change (ie make them search again). */
  struct thread* curr_t = thread_current();
  struct list* locks = &curr_t->locks;

  /* Reset the current thread's priority. This creates a redundancy later on
   * in thread_set_eff_priority but it is needed here. */
  //cur->effective_priority = cur->priority;

  struct list_elem* e;
  for(e = list_begin(locks); e != list_end(locks); e = list_next(e)) {
    struct lock* lock = list_entry(e, struct lock, elem);

    /* Lock was getting its max value from the current locks donation. */
    if(lock->tid_priority == curr_t->tid) {
      /* Since the current thread holds the lock and lock_find_max only
       * searches its waiters for the new max value, this will be OK. */
      lock_find_max(lock);
    }

  }

}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock* lock) {
  bool success;

  ASSERT(lock != NULL);
  ASSERT(!lock_held_by_current_thread(lock));

  success = sema_try_down(&lock->semaphore);
  if (success)
    lock->holder = thread_current();
  return success;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void lock_release(struct lock* lock) {
  ASSERT(lock != NULL);
  ASSERT(lock_held_by_current_thread(lock));
  enum intr_level old_level;
  old_level = intr_disable();
  struct thread* curr_t = thread_current();

  /* Remove lock from curr. thread's list of locks. */
  lock_lose(lock);

  /* Reset the thread's eff. priority to (base) priority. If thread has more
   * locks, the func. will use the highest priority (no lower than base). */
  thread_set_eff_priority(curr_t, curr_t->priority);

  /* Search for new max priority if needed. */
  if(lock->tid_priority == curr_t->tid) {
    lock_find_max(lock);
  }

  if(!list_empty(&lock->semaphore.waiters)) {
    /* Sort lock waiters by priority. */
    list_sort(&lock->semaphore.waiters, thread_prio_less, NULL);
    thread_unblock(list_entry(list_pop_front(&lock->semaphore.waiters), struct thread, elem));
  }
  (lock->semaphore.value)++;
  intr_set_level(old_level);

  thread_preempt();

}

static void lock_find_max(struct lock* lock) {
  struct list_elem* e;
  tid_t max_tid = -1;
  int max_p = PRI_MIN - 1;

  for(e = list_begin(&lock->semaphore.waiters);
      e != list_end(&lock->semaphore.waiters); e = list_next(e)) {
    struct thread* t = list_entry(e, struct thread, elem);
    if(t->effective_priority > max_p) {
      max_tid = t->tid;
      max_p = t->effective_priority;
    }
  }

  lock->priority = max_p;
  lock->tid_priority = max_tid;
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock* lock) {
  ASSERT(lock != NULL);

  return lock->holder == thread_current();
}

/* Sets a lock's max. priority. MUST be called with interrupts
 * dissabled. */
void lock_set_priority(struct lock* lock, tid_t tid, int new_priority) {
  /* Check if new_priority is less than lock max. */
  if(new_priority > lock->priority) {
    lock->tid_priority = tid;
    lock->priority = new_priority;

    /* Must re-sort lock holder's list of locks. We verify that the lock
     * is a part of the list because a free lock should not check this. NOTE:
     * free locks should have NO lock holder. */
    bool lock_in_list = lock->holder != NULL;
    if(lock_in_list && lock_sort_needed(lock)) {
      list_sort(&lock->holder->locks, lock_prio_less, NULL);
    }

    
    /* Must update holder of lock. */
    if(lock->holder)
      thread_set_eff_priority(lock->holder, new_priority);
  }
}

/* Sorts locks by their priority. */
static bool lock_prio_less(const struct list_elem* a, const struct list_elem* b, UNUSED void* aux) {
  struct lock* la = list_entry(a, struct lock, elem);
  struct lock* lb = list_entry(b, struct lock, elem);
  return la->priority > lb->priority;
}

/* Returns whether a thread's list of held locks needs resorting.
 * Expects that the element LOCK has changed priority. MUST be
 * called with interrupts dissabled. */
static bool lock_sort_needed(struct lock* lock) {
  /* Verify that list has been initialized. */
  struct list* lock_list = &lock->holder->locks;
  ASSERT(lock_list != NULL);
  ASSERT(!list_empty(lock_list));


  struct list_elem* lock_elem = &lock->elem;
  struct list_elem* next_lock_elem = list_next(lock_elem);
  struct list_elem* prev_lock_elem = list_prev(lock_elem);

  if(!is_head(prev_lock_elem)) {
    struct lock* prev_lock = list_entry(prev_lock_elem, struct lock, elem);
    if(prev_lock->priority < lock->priority)
      return true;
  }
  if(!is_tail(next_lock_elem)) {
    struct lock* next_lock = list_entry(next_lock_elem, struct lock, elem);
    if(next_lock->priority > lock->priority)
      return true;
  }
  return false;
}


/* Initializes a readers-writers lock */
void rw_lock_init(struct rw_lock* rw_lock) {
  lock_init(&rw_lock->lock);
  cond_init(&rw_lock->read);
  cond_init(&rw_lock->write);
  rw_lock->AR = rw_lock->WR = rw_lock->AW = rw_lock->WW = 0;
}

/* Acquire a writer-centric readers-writers lock */
void rw_lock_acquire(struct rw_lock* rw_lock, bool reader) {
  // Must hold the guard lock the entire time
  lock_acquire(&rw_lock->lock);

  if (reader) {
    // Reader code: Block while there are waiting or active writers
    while ((rw_lock->AW + rw_lock->WW) > 0) {
      rw_lock->WR++;
      cond_wait(&rw_lock->read, &rw_lock->lock);
      rw_lock->WR--;
    }
    rw_lock->AR++;
  } else {
    // Writer code: Block while there are any active readers/writers in the system
    while ((rw_lock->AR + rw_lock->AW) > 0) {
      rw_lock->WW++;
      cond_wait(&rw_lock->write, &rw_lock->lock);
      rw_lock->WW--;
    }
    rw_lock->AW++;
  }

  // Release guard lock
  lock_release(&rw_lock->lock);
}

/* Release a writer-centric readers-writers lock */
void rw_lock_release(struct rw_lock* rw_lock, bool reader) {
  // Must hold the guard lock the entire time
  lock_acquire(&rw_lock->lock);

  if (reader) {
    // Reader code: Wake any waiting writers if we are the last reader
    rw_lock->AR--;
    if (rw_lock->AR == 0 && rw_lock->WW > 0)
      cond_signal(&rw_lock->write, &rw_lock->lock);
  } else {
    // Writer code: First try to wake a waiting writer, otherwise all waiting readers
    rw_lock->AW--;
    if (rw_lock->WW > 0)
      cond_signal(&rw_lock->write, &rw_lock->lock);
    else if (rw_lock->WR > 0)
      cond_broadcast(&rw_lock->read, &rw_lock->lock);
  }

  // Release guard lock
  lock_release(&rw_lock->lock);
}

/* One semaphore in a list. */
struct semaphore_elem {
  struct list_elem elem;      /* List element. */
  struct semaphore semaphore; /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition* cond) {
  ASSERT(cond != NULL);

  list_init(&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait(struct condition* cond, struct lock* lock) {
  struct semaphore_elem waiter;

  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  sema_init(&waiter.semaphore, 0);
  list_push_back(&cond->waiters, &waiter.elem);
  lock_release(lock);
  sema_down(&waiter.semaphore);
  lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal(struct condition* cond, struct lock* lock UNUSED) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  if (!list_empty(&cond->waiters)) {
    /* TODO: This sort doesn't seem to work. Fix. */
    list_sort(&cond->waiters, thread_prio_less, NULL);
    sema_up(&list_entry(list_pop_front(&cond->waiters), struct semaphore_elem, elem)->semaphore);
  }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition* cond, struct lock* lock) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);

  while (!list_empty(&cond->waiters))
    cond_signal(cond, lock);
}

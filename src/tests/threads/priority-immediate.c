/* Checks to make sure the main thread immediately yields the cpu when it releases the lock 
after it loses it's temporary priority donation from the waiting thread with higher priority
(tested by changing the value of an integer, which is a very fast operation) */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"

static thread_func acquire1_thread_func;
static int magic = 13;

void test_priority_immediate(void) {
  struct lock lock;

  /* This test does not work with the MLFQS. */
  ASSERT(active_sched_policy == SCHED_PRIO);

  /* Make sure our priority is the default. */
  ASSERT(thread_get_priority() == PRI_DEFAULT);
  msg("magic is initially %d", magic);
  lock_init(&lock);
  lock_acquire(&lock);
  thread_create("acquire1", PRI_DEFAULT + 1, acquire1_thread_func, &lock);
  msg("This thread should have priority %d.  Actual priority: %d.", PRI_DEFAULT + 1,
      thread_get_priority());
  lock_release(&lock);
  magic = 28;
  msg("magic is now %d. It should be 28.", magic);
  msg("acquire1 must already have finished.");
  msg("This should be the last line before finishing this test.");
}

static void acquire1_thread_func(void* lock_) {
  struct lock* lock = lock_;
  lock_acquire(lock);
  msg("magic is still %d", magic);
  magic = 5;
  msg("magic is now %d", magic);
  lock_release(lock);
  msg("acquire1: done");
}

/* Tests seek functionality. */

#include <syscall.h>
#include "tests/userprog/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle, byte_cnt;

  CHECK(create("test.txt", sizeof sample - 1), "create \"test.txt\"");
  CHECK((handle = open("test.txt")) > 1, "open \"test.txt\"");
  byte_cnt = write(handle, sample, sizeof sample - 1);
  if (byte_cnt != sizeof sample - 1)
    fail("write() returned %d instead of %zu", byte_cnt, sizeof sample - 1);

  seek(handle, 10);
  int result = tell(handle);
  if (result != 10) {
    fail("seek changed the position to  %d", result);
  }
}
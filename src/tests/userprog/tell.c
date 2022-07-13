/* Tests functionality of tell syscall */

#include <syscall.h>
#include "tests/userprog/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle, byte_cnt, result;

  CHECK(create("test.txt", sizeof sample - 1), "create \"test.txt\"");
  CHECK((handle = open("test.txt")) > 1, "open \"test.txt\"");

  byte_cnt = write(handle, sample, 2);
  if (byte_cnt != 2)
    fail("write() returned %d instead of %zu", byte_cnt, 2);

  result = tell(handle);
  if (result != 2) {
    fail("tell() returned %d", result);
  }
}

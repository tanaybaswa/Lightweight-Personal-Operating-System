/* Tests effectiveness of buffer cache by measuring hit rate of buffer cache */

#include <string.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

char buf1[65536];

void test_main(void) {
  const char* file_name = "example";
  int fd;

  for (int i = 0; i < sizeof(buf1); i++) {
    buf1[i] = 'h';
  }

  CHECK(create(file_name, sizeof buf1), "create \"%s\"", file_name);
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);

  for (int i = 0; i < sizeof(buf1); i++) {
    write(fd, buf1, 1);
  }
  int write = write_count();
  char* rv = "is not";
  if (write >= 120 && write <= 135)
    rv = "is";
  msg("The number of writes %s on the order of 128", rv);

  CHECK(read(fd, buf1, sizeof buf1) > 0, "read \"%s\"", file_name);
  for (int i = 0; i < sizeof(buf1); i++) {
    read(fd, buf1, 1);
  }
  int write1 = write_count();
  char* rv1 = "is not";
  if (write1 >= 120 && write1 <= 135)
    rv1 = "is";
  msg("The number of writes %s on the order of 128", rv1);
  close(fd);
  msg("close \"%s\"", file_name);
  close(fd);
}
/* Tests effectiveness of buffer cache by measuring hit rate of buffer cache */

#include <string.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

char buf1[64];

void test_main(void) {
  const char* file_name = "example";
  int fd;
  double cold_hr;
  double cache_hr;

  for (int i = 0; i < sizeof(buf1); i++) {
    buf1[i] = 'h';
  }

  CHECK(create(file_name, sizeof buf1), "create \"%s\"", file_name);
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  CHECK(write(fd, buf1, sizeof buf1) > 0, "write \"%s\"", file_name);
  flush_cache();
  CHECK(read(fd, buf1, sizeof buf1) > 0, "read \"%s\"", file_name);
  cold_hr = hit_rate();
  msg("close \"%s\"", file_name);
  close(fd);
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  CHECK(read(fd, buf1, sizeof buf1) > 0, "read \"%s\"", file_name);
  cache_hr = hit_rate();
  char* rv_str;
  if (cache_hr > cold_hr)
    rv_str = "greater than";
  rv_str = "less than";
  msg("cache_hr is %s cold_hr", rv_str);
  msg("close \"%s\"", file_name);
  close(fd);
}
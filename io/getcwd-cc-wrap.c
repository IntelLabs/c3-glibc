#ifdef CC
#include <string.h>
#include <linux/limits.h>
#include <stdint.h>
#include "../no_dependency_encoding.h"

extern char * __getcwd (char *buf, size_t size);

static char plaintext_buf[PATH_MAX+1];

char *
getcwd (char *buf, size_t size)
{
  if (__getcwd(plaintext_buf, size) == NULL) return NULL;
  plaintext_buf[PATH_MAX] = '\0';
  strncpy(buf, plaintext_buf, size);
  return buf;
}
#endif

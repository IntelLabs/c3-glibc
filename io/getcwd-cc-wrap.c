#ifdef CC_USE_SYSCALL_SHIMS
#include <string.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/param.h>
#include "../no_dependency_encoding.h"

extern char * __getcwd (char *buf, size_t size);

static char plaintext_buf[PATH_MAX+1];

char *
getcwd (char *buf, size_t size)
{
  size = (size != 0 ? size : PATH_MAX);
  if (__getcwd(plaintext_buf, size) == NULL)
    {
      //printf("__getcwd failed: %s", strerror(errno));
      return NULL;
    }
  if (buf == NULL)
    {
      // This support what sysdeps/unix/sysv/linux/getcwd.c does, i.e., support
      // the extension to the POSIX.1-2001 that mallocs memory if buf is NULL.
      buf = malloc(size);
      if (buf == NULL)
        {
          //printf("malloc failed: %s\n", strerror(errno));
          return NULL;
        }
    }
  plaintext_buf[PATH_MAX] = '\0';
  strncpy(buf, plaintext_buf, size);
  return buf;
}
#endif  // CC_USE_SYSCALL_SHIMS

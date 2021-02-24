#ifdef CC_USE_SYSCALL_SHIMS
#include <string.h>
#include <linux/limits.h>
#include <stdint.h>
#include "../no_dependency_encoding.h"

extern int __rmdir (const char *path);

static char plaintext_path[PATH_MAX+1];

int
rmdir (const char *path)
{
  strncpy(plaintext_path, path, sizeof(plaintext_path)-1);
  return __rmdir(plaintext_path);
}
#endif  // CC_USE_SYSCALL_SHIMS

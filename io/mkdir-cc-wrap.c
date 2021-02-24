#ifdef CC_USE_SYSCALL_SHIMS
#include <string.h>
#include <linux/limits.h>
#include <stdint.h>
#include "../no_dependency_encoding.h"

extern int __mkdir (const char *path, mode_t mode);

static char plaintext_path[PATH_MAX+1];

int
mkdir (const char *path, mode_t mode)
{
  strncpy(plaintext_path, path, sizeof(plaintext_path)-1);
  return __mkdir(plaintext_path, mode);
}
#endif  // CC_USE_SYSCALL_SHIMS

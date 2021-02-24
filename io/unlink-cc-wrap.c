#ifdef CC_USE_SYSCALL_SHIMS
#include <string.h>
#include <linux/limits.h>

extern int __unlink (const char *path);

int
unlink (const char *path)
{
  static char path_buf[PATH_MAX+1];
  strncpy(path_buf, path, sizeof(path_buf)-1);
  return __unlink(path_buf);
}
#endif  // CC_USE_SYSCALL_SHIMS

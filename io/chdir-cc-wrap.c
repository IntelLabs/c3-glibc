#ifdef CC_USE_SYSCALL_SHIMS
#include <string.h>
#include <linux/limits.h>

extern int __chdir (const char *path);

int
chdir (const char *path)
{
  static char path_buf[PATH_MAX+1];
  strncpy(path_buf, path, PATH_MAX);
  return __chdir(path_buf);
}
#endif  // CC_USE_SYSCALL_SHIMS

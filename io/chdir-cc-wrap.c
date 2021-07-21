#ifdef CC
#include <string.h>
#include <linux/limits.h>

extern int __chdir (const char *path);

int
chdir (const char *path)
{
  char path_buf[PATH_MAX+1];
  strncpy(path_buf, path, PATH_MAX);
  return __chdir(path_buf);
}
#endif

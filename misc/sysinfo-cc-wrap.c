#ifdef CC_USE_SYSCALL_SHIMS
#include <string.h>
#include <stdint.h>
#include <sys/sysinfo.h>
#include "../no_dependency_encoding.h"

extern int __sysinfo (struct sysinfo *info);

struct sysinfo plaintext_info;
int
sysinfo (struct sysinfo *info)
{
  int result = __sysinfo(&plaintext_info);
  memcpy(info, &plaintext_info, sizeof(struct sysinfo));
  return result;
}
#endif  // CC_USE_SYSCALL_SHIMS

/* xstat using old-style Unix stat system call.
   Copyright (C) 1991-2019 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

/* Ho hum, since xstat == xstat64 we must get rid of the prototype or gcc
   will complain since they don't strictly match.  */
#define __xstat64 __xstat64_disable

#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>

#include <sysdep.h>
#include <sys/syscall.h>

#ifdef CC_USE_SYSCALL_SHIMS
#include <string.h>
#include "../no_dependency_encoding.h"

static struct stat plaintext_buf;
static char plaintext_name[PATH_MAX+1];
#endif  // CC_USE_SYSCALL_SHIMS

/* Get information about the file NAME in BUF.  */
int
__xstat (int vers, const char *name, struct stat *buf)
{
#ifdef CC_USE_SYSCALL_SHIMS
  if(is_encoded_pointer(buf) || is_encoded_pointer(name)){
    // strncpy is not available in RTLD:
    size_t name_len = strnlen(name, sizeof(plaintext_name)-1);
    memcpy(plaintext_name, name, name_len);
    plaintext_name[name_len] = '\0';
    if (vers == _STAT_VER_KERNEL || vers == _STAT_VER_LINUX){
      int ret = INLINE_SYSCALL (stat, 2, plaintext_name, &plaintext_buf);
      memcpy(buf, &plaintext_buf, sizeof(struct stat));
      return ret;
    }
  }
#endif  // CC_USE_SYSCALL_SHIMS
  if (vers == _STAT_VER_KERNEL || vers == _STAT_VER_LINUX)
    return INLINE_SYSCALL (stat, 2, name, buf);

  __set_errno (EINVAL);
  return -1;
}
hidden_def (__xstat)
weak_alias (__xstat, _xstat);
#undef __xstat64
strong_alias (__xstat, __xstat64);
hidden_ver (__xstat, __xstat64)

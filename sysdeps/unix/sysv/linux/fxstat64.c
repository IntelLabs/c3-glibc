/* fxstat64 using Linux fstat64/statx system call.
   Copyright (C) 1997-2019 Free Software Foundation, Inc.
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

#include <errno.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <kernel_stat.h>

#include <sysdep.h>
#include <sys/syscall.h>

#include <statx_cp.h>

#ifdef CC_USE_SYSCALL_SHIMS
#include "../no_dependency_encoding.h"
#endif  // CC_USE_SYSCALL_SHIMS

/* Get information about the file FD in BUF.  */

int
___fxstat64 (int vers, int fd, struct stat64 *buf)
{
  int result;
#ifdef CC_USE_SYSCALL_SHIMS
  if(is_encoded_pointer(buf) || is_encoded_pointer(&result)){
  #ifdef __NR_fstat64
    void * plaintext_buf = __libc_malloc(sizeof(struct stat64));
    result = INLINE_SYSCALL (fstat64, 2, fd, plaintext_buf);
    memcpy(buf, plaintext_buf, sizeof(struct stat64));
    __libc_free(plaintext_buf);
  #else
    struct statx *tmp = __libc_malloc(sizeof(struct statx));
    result = INLINE_SYSCALL (statx, 5, fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS,
                             tmp);
    if (result == 0)
      __cp_stat64_statx (buf, tmp);
    __libc_free(tmp);
  #endif
  }
#endif  // CC_USE_SYSCALL_SHIMS
#ifdef __NR_fstat64
  result = INLINE_SYSCALL (fstat64, 2, fd, buf);
#else
  struct statx tmp;
  result = INLINE_SYSCALL (statx, 5, fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS,
                           &tmp);
  if (result == 0)
    __cp_stat64_statx (buf, &tmp);
#endif
  return result;
}

#include <shlib-compat.h>

#if SHLIB_COMPAT(libc, GLIBC_2_1, GLIBC_2_2)
versioned_symbol (libc, ___fxstat64, __fxstat64, GLIBC_2_2);
strong_alias (___fxstat64, __old__fxstat64)
compat_symbol (libc, __old__fxstat64, __fxstat64, GLIBC_2_1);
hidden_ver (___fxstat64, __fxstat64)
#else
strong_alias (___fxstat64, __fxstat64)
hidden_def (__fxstat64)
#endif

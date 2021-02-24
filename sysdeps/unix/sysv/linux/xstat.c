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

/* Ho hum, if xstat == xstat64 we must get rid of the prototype or gcc
   will complain since they don't strictly match.  */
#define __xstat64 __xstat64_disable

#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>
#include <kernel_stat.h>

#include <sysdep.h>
#include <sys/syscall.h>

#include <xstatconv.h>

#ifdef CC_USE_SYSCALL_SHIMS
extern void*  __libc_malloc(size_t);
extern void  __libc_free(void*);
#include <string.h>
#include "../no_dependency_encoding.h"
#endif  // CC_USE_SYSCALL_SHIMS

/* Get information about the file NAME in BUF.  */
int
__xstat (int vers, const char *name, struct stat *buf)
{
#ifdef CC_USE_SYSCALL_SHIMS
  if(is_encoded_pointer(name) || is_encoded_pointer(buf) || is_encoded_pointer(&result)){
    int result;
    size_t plaintext_name_len = strnlen(name, PATH_MAX)+1;
    void * plaintext_name = __libc_malloc(plaintext_name_len);
    strncpy(plaintext_name, name, plaintext_name_len);
    void * plaintext_buf = __libc_malloc(sizeof(struct stat));

    
    if (vers == _STAT_VER_KERNEL){
      result = INLINE_SYSCALL (stat, 2, name, plaintext_buf);
      memcpy(buf, plaintext_buf, sizeof(struct stat);
      __libc_free(plaintext_buf);
      __libc_free(plaintext_name);
      return result;
    }

    #ifdef STAT_IS_KERNEL_STAT
      result = INLINE_SYSCALL_ERROR_RETURN_VALUE (EINVAL);
      __libc_free(plaintext_buf);
      __libc_free(plaintext_name);
      return result;
    #else
      struct kernel_stat *kbuf = __libc_malloc(sizeof(struct kernel_stat);

      result = INLINE_SYSCALL (stat, 2, plaintext_name, kbuf);
      if (result == 0){
        result = __xstat_conv (vers, kbuf, plaintext_buf);
        memcpy(buf, plaintext_buf, sizeof(struct stat);
      }
        
      __libc_free(plaintext_buf);
      __libc_free(plaintext_name);
      __libc_free(kbuf);
      return result;
    #endif
    
  }else{
#endif  // CC_USE_SYSCALL_SHIMS
  if (vers == _STAT_VER_KERNEL)
    return INLINE_SYSCALL (stat, 2, name, buf);

#ifdef STAT_IS_KERNEL_STAT
  return INLINE_SYSCALL_ERROR_RETURN_VALUE (EINVAL);
#else
  struct kernel_stat kbuf;
  int result;

  result = INLINE_SYSCALL (stat, 2, name, &kbuf);
  if (result == 0)
    result = __xstat_conv (vers, &kbuf, buf);

  return result;
#endif
#ifdef CC_USE_SYSCALL_SHIMS
  }
#endif  // CC_USE_SYSCALL_SHIMS
}
hidden_def (__xstat)
weak_alias (__xstat, _xstat);
#if XSTAT_IS_XSTAT64
#undef __xstat64
strong_alias (__xstat, __xstat64);
hidden_ver (__xstat, __xstat64)
#endif

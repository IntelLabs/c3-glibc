/* lxstat using old-style Unix lstat system call.
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
#define __lxstat64 __lxstat64_disable

#include <errno.h>
#include <stddef.h>
#include <sys/stat.h>

#include <sysdep.h>
#include <sys/syscall.h>

#include "../no_dependency_encoding.h"

static struct stat plaintext_buf;
static char plaintext_name[PATH_MAX+1];

/* Get information about the file FD in BUF.  */
int
__lxstat (int vers, const char *name, struct stat *buf)
{
  int result;
  if (vers == _STAT_VER_KERNEL || vers == _STAT_VER_LINUX){
    if(is_encoded_pointer(name) || is_encoded_pointer(buf)){
      size_t name_len = strnlen(name, sizeof(plaintext_name)-1);
      memcpy(plaintext_name, name, name_len);
      plaintext_name[name_len] = '\0';
      result = INLINE_SYSCALL (lstat, 2, plaintext_name, &plaintext_buf);
      memcpy(buf, &plaintext_buf, sizeof(struct stat));
       return result;
    }else{
      return INLINE_SYSCALL (lstat, 2, name, buf);
    }
  }
  __set_errno (EINVAL);
  return -1;
}

hidden_def (__lxstat)
weak_alias (__lxstat, _lxstat);
#undef __lxstat64
strong_alias (__lxstat, __lxstat64);
hidden_ver (__lxstat, __lxstat64)

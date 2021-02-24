/* Linux read syscall implementation.
   Copyright (C) 2017-2019 Free Software Foundation, Inc.
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

#include <unistd.h>
#include <sysdep-cancel.h>

#ifdef CC_USE_SYSCALL_SHIMS
#include <string.h>
#include "../no_dependency_encoding.h"

extern void*  __libc_malloc(size_t);
extern void  __libc_free(void*);
#endif  // CC_USE_SYSCALL_SHIMS

/* Read NBYTES into BUF from FD.  Return the number read or -1.  */
ssize_t
__libc_read (int fd, void *buf, size_t nbytes)
{
#ifdef CC_USE_SYSCALL_SHIMS
  if(is_encoded_pointer(buf)){ //CC_CHANGES Encoded Address
    void * plaintext_buf = __libc_malloc(nbytes);
    ssize_t ret = SYSCALL_CANCEL (read, fd, plaintext_buf, nbytes);
    if (ret != -1) {
      memcpy(buf, plaintext_buf, ret);
    }
    __libc_free(plaintext_buf);
    return ret;
  }
#endif  // CC_USE_SYSCALL_SHIMS
  return SYSCALL_CANCEL (read, fd, buf, nbytes);
}
libc_hidden_def (__libc_read)

libc_hidden_def (__read)
weak_alias (__libc_read, __read)
libc_hidden_def (read)
weak_alias (__libc_read, read)

/* SSE2 version of strlen.
   Copyright (C) 2012-2016 Free Software Foundation, Inc.
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

#include <sysdep.h>

/* Long lived register in strlen(s), strnlen(s, n) are:

	%xmm3 - zero
	%rdi   - s
	%r10  (s+n) & (~(64-1))
	%r11   s+n
*/

.text
ENTRY(strlen)

#ifdef AS_STRNLEN
	xorl	%eax, %eax
	testq	%rsi, %rsi
	je	.L5
	cmpb	$0, (%rdi)
	jne	.L3
	jmp	.L1
.L4:
	cmpb	$0, (%rdi,%rax)
	je	.L1
.L3:
	addq	$1, %rax
	cmpq	%rax, %rsi
	jne	.L4
	ret
.L1:
	ret
.L5:
	ret
#endif

#ifdef AS_WCSLEN
	movl	(%rdi), %eax
	testl	%eax, %eax
	je	.L12
	movl	4(%rdi), %r11d
	testl	%r11d, %r11d
	je	.L13
	movl	8(%rdi), %r10d
	testl	%r10d, %r10d
	je	.L14
	xorl	%edx, %edx
	jmp	.L10
.L18:
	leaq	4(%rdx), %rax
	movl	(%rdi,%rax,4), %ecx
	testl	%ecx, %ecx
	je	.L17
	movl	4(%rdi,%rax,4), %r9d
	leaq	5(%rdx), %rcx
	testl	%r9d, %r9d
	je	.L15
	movl	8(%rdi,%rax,4), %r8d
	addq	$6, %rdx
	testl	%r8d, %r8d
	je	.L16
	movq	%rax, %rdx
.L10:
	movl	12(%rdi,%rdx,4), %esi
	leaq	3(%rdx), %rax
	testl	%esi, %esi
	jne	.L18
	ret
.L17:
	ret
.L15:
	movq	%rcx, %rax
	ret
.L16:
	movq	%rdx, %rax
	ret
.L12:
	xorl	%eax, %eax
	ret
.L13:
	movl	$1, %eax
	ret
.L14:
	movl	$2, %eax
	ret
#endif
	xorl	%eax, %eax
	cmpb	$0, (%rdi)
	je	.L22
.L21:
	addq	$1, %rax
	cmpb	$0, (%rdi,%rax)
	jne	.L21
	ret
.L22:
	ret
END(strlen)
libc_hidden_builtin_def (strlen)

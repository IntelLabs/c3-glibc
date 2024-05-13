/* 
 * Copyright 2021 Intel Corporation
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <utils.h>
#include <emmintrin.h>

void * cc_morecore (ptrdiff_t);
//Disable brk and use mmap instead
//void *(*__morecore)(ptrdiff_t) = cc_morecore;
void *cc_morecore(ptrdiff_t increment){
  return NULL;
}

static volatile unsigned long cc_initialized = 0;
static uint64_t cc_debug_print = 0;
#ifdef CC_NO_WRAP_ENABLE
static int cc_no_wrap_enabled = 0; // Marks if CC_NO_WRAP_ENABLED environment variable is set
#endif // CC_NO_WRAP_ENABLE

static void * CC_MMAP(void * addr, size_t size, int prot, int flags){
  void *p; 
  
  if(cc_initialized == 0x0) { 
    // :fprintf(stderr, "Initializing CC_MMAP!\n");
    cc_debug_print = (getenv("CC_DEBUG_PRINT") != NULL);
    cc_initialized = 0x1;
  }
 
  p = __mmap(addr, size, prot, flags |MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  kprintf(stderr, "@MMAP: %p, size is %ld\n", p, size);
  
	return p;
}

#define MMAP(addr, size, prot, flags) CC_MMAP(addr, size, prot, flags)

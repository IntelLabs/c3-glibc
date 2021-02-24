/* 
 * Copyright 2021 Intel Corporation
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

// This file joins cc_malloc.c to glibc.
// It also enabled/disabled encodings based on environment variables

#include <ctype.h>
#include <emmintrin.h>
#include <stdio.h>
#include <stdint.h> //for uint**
#include <string.h>
#include <stdlib.h>
#include "cc_globals.h"
#include "utils.h"

// Global state variables
static int initialized = 0; // Will call init if this is still set to 0.
static int initializing = 0; // Initialized has been invoked when set to 1, although it may not yet have completed.
static int cc_quarantine_enabled = 1;

// Variables for enable/disable encoding
static int cc_enabled = 0; // Marks if CC environment variable is set
int lim_enabled = 0; // Marks if LIM environment variable is set
int lim_data_disp = 0; // Select data displacement LIM mechanism. Requires LIM_ENABLED to also be set.
int lim_max_meta = 0; // Immediately select max metadata size to prioritize performance over memory usage. Requires LIM_ENABLED to also be set.
int lim_no_meta = 0; // Reserve no metadata space and do not iterate to find an adequate allocation to fit metadata, but still execute pointer encoding code. Requires LIM_ENABLED to also be set.
int lim_no_encode = 0; // Do not encode LIM pointers but still reserve space for metadata and emulate allocator metadata accesses.
int trace_only = 0; // Marks if LIT-only environment variable is set. If so, no metadata will be set and the CPU will not skip over the metadata
static int stats_enabled = 0; // Marks if stats environment variable is set
// cc_debug_print is defined in cc.c, which is included earlier in malloc.c than this file
int data_integrity_enabled = 0; // Marks if data integrity is enabled

// Variable for metric counting
static uint64_t malloc_count = 0;
static uint64_t malloc_skip_count = 0;
static uint64_t realloc_count = 0;
static uint64_t calloc_count = 0;
static uint64_t free_count = 0;
static uint64_t max_system_b = 0;

static bool use_trc_file = false;
static FILE *trc_file = NULL;
bool cc_pause_tracing = false;

void reliable_fwrite(const void *ptr, size_t size, FILE *stream){
  unsigned int retry_count = 0;
  size_t ret = 0;
  while(ret != 1){
    assert(retry_count < 30);
    retry_count++;
    ret = fwrite(ptr, size, 1, stream);
  }
}

void reliable_putc(int mychar, FILE *stream){
  unsigned int retry_count = 0;
  int ret = 0;
  while(ret != mychar){
    assert(retry_count < 30);
    retry_count++;
    ret = putc(mychar, stream);
  }
}

//#define WRITE_FREE_RANGES_AT_PEAK

#ifdef WRITE_FREE_RANGES_AT_PEAK
void cc_trc_flush(void) {
  fflush(trc_file);
}
#endif

// Provide names for backend allocator functions for cc_malloc.c
#define REAL_MALLOC __libc_malloc
#define REAL_REALLOC __libc_realloc
#define REAL_CALLOC __libc_calloc
#define REAL_FREE __libc_free
#define MALLOC_USABLE_SIZE __malloc_usable_size
// Import actual encoded definitions for malloc, calloc, realloc.
#include "cc_malloc.c"
#include "lim_malloc.c"

// Supplant existing definitions of memory management functions
#define CC_ALIAS_HOOK_WEAK(ret_t, routine, params) \
  ret_t cc_##routine##_hook params; \
  weak_alias (cc_##routine##_hook, routine)
#define CC_ALIAS_HOOK(ret_t, routine, params) \
  CC_ALIAS_HOOK_WEAK(ret_t, routine, params) \
  strong_alias (cc_##routine##_hook, __##routine)
#define CC_FUNC_HOOK(ret_t, routine, params, args) \
  CC_ALIAS_HOOK(ret_t, routine, params) \
  static ret_t cc_##routine params { \
    if (cc_enabled) \
      return cc_##routine##_encoded args; \
    else if (lim_enabled) \
      return lim_##routine args; \
    return __libc_##routine args; \
  }
#define CC_FUNC_HOOK_VOID(routine, params, args) \
  CC_ALIAS_HOOK(void, routine, params) \
  static void cc_##routine params { \
    if (cc_enabled) \
      cc_##routine##_encoded args; \
    else if (lim_enabled) \
      lim_##routine args; \
    else \
      __libc_##routine args; \
  }
// These are the wrappers defined in this file
CC_FUNC_HOOK(void *, calloc, (size_t p1, size_t p2), (p1, p2));
CC_FUNC_HOOK_VOID(free, (void* p1), (p1));
CC_FUNC_HOOK(void*, realloc, (void* p1, size_t p2), (p1, p2));
CC_FUNC_HOOK(void*, malloc, (size_t p1), (p1));
CC_ALIAS_HOOK(void*, memalign, (size_t p1, size_t p2));
weak_alias (cc_memalign_hook, aligned_alloc)
CC_ALIAS_HOOK(void*, valloc, (size_t p1));
CC_ALIAS_HOOK(void*, pvalloc, (size_t p1));
CC_ALIAS_HOOK_WEAK(int, posix_memalign, (void ** p1, size_t p2, size_t p3));

static char trc_buf[BUFSIZ];

void init(void) {
    if (initializing) return;

    initializing = 1;

    cc_enabled = (getenv("CC_ENABLED")!= NULL);
    lim_enabled = (getenv("LIM_ENABLED")!= NULL);
    lim_data_disp = (getenv("LIM_DATA_DISP")!= NULL);
    lim_max_meta = (getenv("LIM_MAX_META")!= NULL);
    lim_no_meta = (getenv("LIM_NO_META")!= NULL);
    lim_no_encode = (getenv("LIM_NO_ENCODE")!= NULL);
    data_integrity_enabled = (getenv("DATA_INTEGRITY_ENABLED")!= NULL);
    // LIM_MAX_META and LIM_NO_META are mutually exclusive:
    assert((!lim_max_meta && !lim_no_meta) || lim_max_meta != lim_no_meta);
    trace_only = lim_no_encode || (getenv("TRACE_ONLY")!= NULL);
    stats_enabled = (getenv("STATS_ENABLED")!= NULL);
    cc_debug_print = (getenv("CC_DEBUG_PRINT") != NULL);
    cc_quarantine_enabled = !(getenv("CC_NO_QUARANTINE") != NULL);
    if(getenv("CC_MALLOC_SKIP") != NULL)
      malloc_skip_count=atoll(getenv("CC_MALLOC_SKIP"));

    char *cc_trace = getenv("CC_TRACE");
    if (cc_trace != NULL) {
      char cc_trace_with_pid[PATH_MAX];
      snprintf(cc_trace_with_pid, sizeof(cc_trace_with_pid), "%s.%u.trace", cc_trace, getpid());

      use_trc_file = true;
      // this invokes malloc internally, which is why init is guarded with
      // the test for "initializing" above:
      trc_file = fopen(cc_trace_with_pid, "a");
      assert(trc_file != NULL);
      // avoid recursive calls to the allocator when generating trace messages:
      setbuf(trc_file, trc_buf);
    }

    initialized = 1;
    //printf("key initialized\n");
}

unsigned int get_system_b(void){
  int i;
  mstate ar_ptr;
  unsigned int system_b = mp_.mmapped_mem;

  if (__malloc_initialized < 0)
    ptmalloc_init ();
  for (i = 0, ar_ptr = &main_arena;; i++)
    {
      struct mallinfo mi;

      memset (&mi, 0, sizeof (mi));
      __libc_lock_lock (ar_ptr->mutex);
      int_mallinfo (ar_ptr, &mi);
      system_b += mi.arena;
      __libc_lock_unlock (ar_ptr->mutex);
      ar_ptr = ar_ptr->next;
      if (ar_ptr == &main_arena)
        break;
    }
  return system_b;
}

void check_debug_stats(int which_op){
  if(!stats_enabled)
    return;
  
  uint64_t system_b = (uint64_t) get_system_b();
  if(max_system_b < system_b){
    max_system_b = system_b;
    fprintf(stderr, "GLIBC STATS: max_system_b=%ld\n", max_system_b);
  }
  
  if(which_op == 1 && malloc_count%10000==0)
    fprintf(stderr, "GLIBC STATS: malloc_count=%ld\n", malloc_count);
  if(which_op == 2 && realloc_count%10000==0)
    fprintf(stderr, "GLIBC STATS: realloc_count=%ld\n", realloc_count);
  if(which_op == 3 && calloc_count%10000==0)
    fprintf(stderr, "GLIBC STATS: calloc_count=%ld\n", calloc_count);
  if(which_op == 4 && free_count%10000==0)
    fprintf(stderr, "GLIBC STATS: free_count=%ld\n", free_count);
  return;
}

size_t CcHookAllocEvtCtr = 0;

void update_free_at_max (void);

static int cc_is_encoded_pointer(uintptr_t p) {
  if (cc_enabled)
    return is_encoded_cc_ptr(p);
  if (lim_enabled)
    return is_encoded_lim_ptr(p);
  return 0;
}

static uintptr_t cc_decode_pointer(uintptr_t p) {
  if (cc_enabled)
    return cc_isa_decptr((uint64_t) p);
  if (lim_enabled)
    return lim_decode_pointer(p);
  return p;
}

static void trace_alloc(char evt_type, void *ptr) {
  assert(!cc_pause_tracing);

  if (ptr != NULL) {
    uintptr_t p_dec;
    if (cc_is_encoded_pointer((uintptr_t)ptr))
      p_dec = cc_decode_pointer((uintptr_t)ptr);
    else
      p_dec = (uintptr_t)ptr;
    assert(p_dec != (uintptr_t)NULL);
    mchunkptr p_chk = mem2chunk((void *)p_dec);
    if (chunk_is_mmapped(p_chk)) {
      evt_type = toupper(evt_type);
    }
  }

  reliable_putc(evt_type, trc_file);
  CcHookAllocEvtCtr++;

  update_free_at_max();
}

void*  cc_malloc_hook(size_t size){
  void* ret;
  malloc_count++;
  if(!initialized) init();
  check_debug_stats(1);
  if (malloc_count <= malloc_skip_count) {
    ret = __libc_malloc(size);
  } else {
    ret = cc_malloc(size);
  }
  if (use_trc_file) {
    if (trc_file && !cc_pause_tracing) {
      trace_alloc('m', ret);
      reliable_fwrite(&ret, sizeof(ret), trc_file);
      reliable_fwrite(&size, sizeof(size), trc_file);
    }
  }else {
    kprintf(stderr, "GLIBC WRAPPER: malloc(%ld)=%p\n", size, ret);
  }
  return ret;
}

void * cc_calloc_hook(size_t num, size_t size){
  void* ret;
  calloc_count++;
  if(!initialized) init();
  check_debug_stats(3);
  ret = cc_calloc(num, size);
  if (use_trc_file) {
    if (trc_file && !cc_pause_tracing) {
      trace_alloc('c', ret);
      size_t total_sz = num * size;
      reliable_fwrite(&ret, sizeof(ret), trc_file);
      reliable_fwrite(&total_sz, sizeof(total_sz), trc_file);
    }
  }else {
    kprintf(stderr, "GLIBC WRAPPER: calloc(%ld, %ld)=%p\n", num, size, ret);
  }
  return ret;
}

void* cc_realloc_hook(void* tmem, size_t tsize){
  void* ret;
  realloc_count++;
  if(!initialized) init();
  check_debug_stats(2);
  if (use_trc_file && trc_file && !cc_pause_tracing) {
    if (tmem != NULL) {
      trace_alloc('r', tmem);
      reliable_fwrite(&tmem, sizeof(tmem), trc_file);
    }
  }
  ret = cc_realloc(tmem, tsize);
  if (use_trc_file) {
    if (trc_file && !cc_pause_tracing) {
      trace_alloc('s', ret);
      reliable_fwrite(&ret, sizeof(ret), trc_file);
      reliable_fwrite(&tsize, sizeof(tsize), trc_file);
    }
  }else {
    kprintf(stderr, "GLIBC WRAPPER: realloc(%p, %ld)=%p\n", tmem, tsize, ret);
  }
  return ret;
}

void cc_free_hook(void* p_in){
  free_count++;
  check_debug_stats(4);
  if (use_trc_file) {
    if (trc_file && !cc_pause_tracing) {
      trace_alloc('f', p_in);
      reliable_fwrite(&p_in, sizeof(p_in), trc_file);
    }
  }else {
    kprintf(stderr, "GLIBC WRAPPER: free(%p)\n", p_in);
  }
  cc_free(p_in);
}

void*  cc_memalign_hook(size_t alignment, size_t size){
  void * ret;
  kprintf(stderr, "@cc_memalign, alignment = %ld size = %ld\n", alignment, size);
  abort(); // Break on unimplemented function
  ret = __libc_memalign(alignment, size);
  return ret;
}

void*  cc_valloc_hook(size_t size){
  void * ret;
  kprintf(stderr, "@cc_valloc!\n");
  abort(); // Break on unimplemented function
  ret = __libc_valloc(size);
  return ret;
}

void*  cc_pvalloc_hook(size_t size){
  void * ret;
  kprintf(stderr, "@cc_pvalloc!\n");
  abort(); // Break on unimplemented function
  ret = __libc_pvalloc(size);
  return ret;
}

int cc_posix_memalign_hook (void **memptr, size_t alignment, size_t size){
  void * pret;
  kprintf(stderr, "@cc_posix_memalign, alignment = %ld size = %ld\n", alignment, size);
  abort(); // Break on unimplemented function
  pret = __libc_memalign(alignment, size);
  if(pret){
    *memptr = pret;
    return 0;
  }else{
    return ENOMEM;
  }
}


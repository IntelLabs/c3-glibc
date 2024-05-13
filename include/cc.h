#ifndef _CC_CC_H_
#define _CC_CC_H_

#include <stddef.h>
#include <stdint.h>
#define _CC_GLOBALS_NO_INCLUDES_
#include "cc_globals.h"
#include "try_box.h"

/* Prevents malloc stat updates that seem to cause deadlock with threading */
#define CC_DISABLE_MEM_STATS_FOR_THREADS

//#define c3_assert(test) assert((test))
#define c3_assert_is_eq(a, b)                                                  \
  do {                                                                         \
    c3_assert(cc_dec_if_encoded_ptr((uint64_t)(a)) ==                          \
              cc_dec_if_encoded_ptr((uint64_t)(b)));                           \
  } while (0)
#define c3_assert_ca_or_no_box(ptr, size)                                      \
  do {                                                                         \
    c3_assert(is_encoded_cc_ptr((uint64_t)(ptr)) ||                            \
              (!cc_can_box((uint64_t)(ptr), (size))));                         \
  } while (0)

#define c3_get_max_offset(ptr1, ptr2, offset)                                  \
  __c3_get_max_offset((uint64_t)(ptr1), (uint64_t)(ptr2), (offset))

static inline size_t __c3_get_max_offset(uint64_t ptr1, uint64_t ptr2,
                                         size_t s) {
  size_t size1 =
      is_encoded_cc_ptr(ptr1) ? ca_get_inbound_offset((void *)ptr1, s) : s;
  size_t size2 =
      is_encoded_cc_ptr(ptr2) ? ca_get_inbound_offset((void *)ptr2, s) : s;
  return size1 < size2 ? size1 : size2;
}





#ifndef c3_assert
#define c3_assert(test)
#endif
/* Could we have an encrypted stack (i.e., %rsp) at run-time? */
#define CC_MAY_HAVE_C3_ENCODED_STACK

#endif  // _CC_CC_H_

#ifndef _CC_CC_H_
#define _CC_CC_H_
#ifdef CC
#include "cc_globals.h"

/* Helper func backport from malloc/cc_globals.h */
static inline size_t ca_get_inbound_offset(const void *ptr, const size_t i) {
    const uint64_t u64_ptr = (uint64_t)((uintptr_t)ptr);
    const uint64_t mask = ~get_tweak_mask(get_ca_t(u64_ptr).enc_size_);
    const uint64_t max = mask - (mask & u64_ptr);
    return (i < max ? i : max);
}

/* Helper func backport from malloc/try.box.h */
static inline int __cc_leading_zeroes(uint64_t ptr, size_t size) {
    size = (size < (1UL << MIN_ALLOC_OFFSET) ? (1UL << MIN_ALLOC_OFFSET)
                                             : size);
    size_t max_off = size - 1;
    uint64_t ptr_end = ptr + max_off;
    uint64_t diff = ptr ^ ptr_end;
    return (diff == 0 ? 64 : __builtin_clzl(diff));
}

/* Helper func backport from malloc/try.box.h */
static inline int cc_can_box(uint64_t ptr, size_t size) {
    return (__cc_leading_zeroes(ptr, size) < 64 - PLAINTEXT_SIZE) ? 0 : 1;
}

/* Helper func backport from malloc/try.box.h */
static inline uint64_t cc_isa_encptr_sv(uint64_t p, size_t s, uint8_t v) {
    ptr_metadata_t md = {0};
    md.size_ = s;
   if (try_box(p, s, &md)) {
        md.version_ = v;
        p = cc_isa_encptr(p, &md);
    }
    return p;
}

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

#endif // CC
#endif // _CC_CC_H_

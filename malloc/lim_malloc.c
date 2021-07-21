/* 
 * Copyright 2021 Intel Corporation
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/**
 * Description: Implementations of functions malloc, calloc, 
 *   realloc, etc. used for Linear Inline Metadata (LIM).
 */

// IMPORTANT:
// This file should not be compiled directly! Import it with #include

// These implementations are enviornment agnostic; it should not depend if
// glibc or wrappers are used.
// External file must define 
//   - REAL_MALLOC (Macro for name of malloc function)
//   - REAL_FREE (Macro for name of free function)
//   - MALLOC_USABLE_SIZE (Macro for name of malloc_usable_size function)
//   - CC_ARCH_NOT_SUPPORT_MEMORY_ACCESS (if needed)
//
// The following runtime switches are also required:
//   - cc_debug_print (for kprintf)
//
// The following headers must be included:
//   - utils.h (from cc_memory_models, for kprintf)
//   - The headers required for REAL_* functions

#include "lim_ptr_encoding.h"
void lim_free(void* p_in);
void lim_free_int(void* p_in);
extern int lim_data_disp, lim_max_meta, trace_only;
extern int lim_no_meta;

// Uncomment this to enable realloc optimizations:
//#define OPT_LIM_REALLOC

static lim_tag_t generate_tag(void) {
    static lim_tag_t tag = 0x0;
    if (++tag == (1<<LIM_TAG_BITS))
        tag = 1;
    return tag;
}

static void * encode_and_set_metadata (void* ptr, size_t size, size_t meta_size) {
    size_t usable_size = size + meta_size;
    uint8_t encoded_size = calculate_encoded_size((uint64_t) ptr, usable_size);
    void* ptr_metadata = (void*) get_metadata_address((uint64_t) ptr, encoded_size);
    kprintf(stderr, "GLIBC WRAPPER: original alloc pointer     = %p\n", ptr);
    kprintf(stderr, "GLIBC WRAPPER: original alloc size        = %ld\n", size);
    kprintf(stderr, "GLIBC WRAPPER: usable alloc size          = %ld\n", MALLOC_USABLE_SIZE(ptr));
    kprintf(stderr, "GLIBC WRAPPER: encoded size               = 0x%02x\n", encoded_size);
    kprintf(stderr, "GLIBC WRAPPER: metadata size              = %ld\n", meta_size);
    lim_tag_t tag = generate_tag();
    kprintf(stderr, "GLIBC WRAPPER: tag                        = %x\n", tag);
    // skip metadata for trace-only
#ifdef LIM_NO_ENCODE
    {
      // Model the overheads of setting metadata, even though it will be overwritten with data.
#else
    if (!trace_only) {
#endif
      // Even though set_metadata may stretch the size at size, keep using the
      // original size throughout the rest of this function.  When optionally
      // shifting allocations to the ends of their bounded ranges below, that should
      // be based on the original, requested size.
      size_t aligned_data_size = set_metadata(ptr, size, meta_size, tag);
      void *p_in = ptr;
#ifdef LIM_CATCH_1B_OVF
      // Compute the slack as the difference between the requested data size and the actual
      // space available for data (i.e. excluding metadata storage) within the bounds
      // specified in the metadata.  Shift the returned pointer by that amount so that
      // even single-byte overflows will be detected.  The tradeoff is that this can result in
      // small underflows being missed.
      assert(size <= aligned_data_size);
      size_t slack = aligned_data_size - size;
      ptr = (void *)(((uintptr_t)p_in) + slack);
#endif
      assert(lim_no_meta || aligned_data_size + meta_size <= MALLOC_USABLE_SIZE(p_in));
    }
    kprintf(stderr, "GLIBC WRAPPER: metadata location          = %p\n", ptr_metadata);
    void *p_encoded = (void*) lim_encode_pointer( (uint64_t) ptr, encoded_size, tag);
    kprintf(stderr, "GLIBC WRAPPER: encoded alloc pointer      = %p\n", p_encoded);
#ifdef LIM_NO_ENCODE
    return ptr;
#else
    return p_encoded;
#endif
}

void write_lim_trace(size_t size, size_t meta_size, size_t usable_size) {
#ifdef LIM_TRC_FILE
  if (use_trc_file) {
    if (trc_file && !cc_pause_tracing) {
      reliable_putc('l', trc_file);
      size_t limsize = size + meta_size;
      reliable_fwrite(&limsize, sizeof(limsize), trc_file);
      reliable_fwrite(&usable_size, sizeof(usable_size), trc_file);
    }
  }
#endif
}

/// size is exclusive of the metadata storage
uint8_t lim_fit_slot(uintptr_t ptr, size_t size, size_t *meta_size) {
  uint8_t enc_sz = 0;
  int iteration = 0;
  do {
    assert(++iteration <=3);
    if (iteration == 1) {
      *meta_size = get_min_metadata_size(size);
    } else {
      *meta_size = get_next_larger_metadata_size(*meta_size);
    }
    enc_sz = calculate_encoded_size(ptr, size + *meta_size);
  } while (get_metadata_size(enc_sz) > *meta_size);

  return enc_sz;
}

void* lim_min_slot_alloc(size_t size, size_t * meta_size, bool enable_trc) {

  void* ptr = NULL;
  uint8_t encoded_size = 0;
  int iteration = 0;
  size_t usable_size = 0;
  int retry = 0;
  if (lim_max_meta) {
    *meta_size = LIM_METADATA_SIZE_512B;
  } else {
    *meta_size = get_min_metadata_size(size);
  }
  size_t requested_size_incl_meta = size;
  if (!lim_no_meta) {
    requested_size_incl_meta += *meta_size;
  }
  kprintf(stderr, "%s: size(requested)           = %ld\n", __func__, size);
  kprintf(stderr, "%s: requested_size_incl_meta  = %ld\n", __func__, requested_size_incl_meta);
  while (requested_size_incl_meta > usable_size || retry) {
    assert(++iteration <=3);
    if (ptr) REAL_FREE(ptr);
    ptr = REAL_MALLOC(requested_size_incl_meta);
    if(!ptr)
      return NULL;
    usable_size = MALLOC_USABLE_SIZE(ptr);
    assert (usable_size != 0);
    encoded_size = calculate_encoded_size((uint64_t) ptr, requested_size_incl_meta);
    if (!lim_no_meta && get_metadata_size(encoded_size) > *meta_size) {
      *meta_size = get_next_larger_metadata_size(*meta_size);
      retry = 1;
    } else {
      retry = 0;
    }
    requested_size_incl_meta = size + *meta_size;
    kprintf(stderr, "%s: ptr                       = %p\n", __func__, ptr);
    kprintf(stderr, "%s: iteration                 = %d\n", __func__, iteration);
    kprintf(stderr, "%s: usable_size               = %ld\n", __func__, usable_size);
    kprintf(stderr, "%s: encoded_size              = %x\n", __func__, encoded_size);
    kprintf(stderr, "%s: meta_size                 = %ld\n", __func__, *meta_size);
    kprintf(stderr, "%s: requested_size_incl_meta  = %ld\n", __func__, requested_size_incl_meta);
  } 

  //check if the slot can be made smaller
  lim_fit_slot((uintptr_t)ptr, size, meta_size);

#if 0
  // Access pages containing new allocation to help avoid page faults later:
  *((uint32_t*) ptr) = 0x0;
  for (uint8_t* addr = (uint8_t*) get_next_page_start_addr((uint64_t)ptr); addr < (uint8_t*)ptr + usable_size; addr = addr + SIM_PAGE_SIZE) {
    *addr = 0x0;
  }
#endif
  kprintf(stderr, "%s: returning ptr             = %p\n", __func__, ptr);

  if (enable_trc)
    write_lim_trace(size, *meta_size, usable_size);  

  return ptr;
}

void*  lim_malloc(size_t size){
  size_t meta_size = 0;
  void *ptr = lim_min_slot_alloc(size, &meta_size, true);
  if(!ptr)
    return NULL;
  return encode_and_set_metadata(ptr, size, meta_size);
}

void * lim_calloc(size_t num, size_t size){
  size_t meta_size = 0;
  size_t data_size = num*size;
  void *unenc_ptr = lim_min_slot_alloc(data_size, &meta_size, true);
  if(!unenc_ptr)
    return NULL;
  
  void *ptr = encode_and_set_metadata(unenc_ptr, data_size, meta_size);

  // This needs to be placed after encode_and_set_metadata when shifting allocations to
  // the ends of their bounded ranges.
  void *tmp_ptr = ptr;
  __asm__ __volatile__("rep stosb" : "+D"(tmp_ptr), "+c"(data_size) : "a"(0) : "cc", "memory");

  return ptr;
}

#if defined(OPT_LIM_REALLOC) || defined(LIM_NO_ENCODE)

static void* reconstruct_encoded_pointer(void *p_in) {
  assert(!is_encoded_address((uintptr_t)p_in));
  size_t old_size = MALLOC_USABLE_SIZE(p_in);
  // This may not precisely match what the encoded size would have been if an encoded pointer had been
  // generated by the original alloc call, specifically if usable size exceeds the requested size
  // by a sufficient amount.
  uint8_t enc_sz = calculate_encoded_size((uintptr_t)p_in, old_size);
  return (void *)lim_encode_pointer((uintptr_t)p_in, enc_sz, 0);
}

#endif

#ifdef OPT_LIM_REALLOC

static void displace_data(uintptr_t p_metadata, size_t meta_size, uintptr_t disp_data) {
      // touch both locations that would be accessed by the LIM data displacement approach:
      memcpy((void *)disp_data, (void *)p_metadata, meta_size);
      memcpy((void *)p_metadata, (void *)disp_data, meta_size);
}

static void squeeze_out_old_metadata(uintptr_t p_old_encoded, uintptr_t p_old_decoded, size_t bytes_to_copy) {
  // squeeze out the old metadata slot:
  if (is_encoded_address(p_old_encoded)){
    uint8_t old_encoded_size = get_encoded_size(p_old_encoded);
    size_t old_meta_size = (trace_only) ? 0 : get_metadata_size(old_encoded_size);
    uint64_t p_metadata = get_metadata_address((uint64_t) p_old_decoded, old_encoded_size);
    if (lim_data_disp) {
      size_t usable_sz = MALLOC_USABLE_SIZE((void *)p_old_decoded);
      uintptr_t disp_data = p_old_decoded + usable_sz - old_meta_size;
      displace_data(p_metadata, old_meta_size, disp_data);
    } else {
#ifdef LIM_CATCH_1B_OVF
      // In this configuration, the needed data is shifted towards the end, so conservatively shift all of it:
      bytes_to_copy = MALLOC_USABLE_SIZE((void *)p_old_decoded) - get_metadata_size(old_encoded_size);
#endif
      uint64_t p_after_metadata = p_metadata + old_meta_size;
      size_t old_bytes_before_metadata = p_metadata - (uint64_t) p_old_decoded;
      if (bytes_to_copy <= old_bytes_before_metadata)
        return;
      size_t old_bytes_after_metadata = bytes_to_copy - old_bytes_before_metadata;
      memmove((void*) p_metadata, (void*) p_after_metadata, old_bytes_after_metadata);
    }
  }
}

/// optimized impl based on __libc_realloc in malloc.c
void* lim_realloc(void* p_old_encoded, size_t size){
  if (size == 0 && p_old_encoded != NULL)
    {
      lim_free_int (p_old_encoded); return NULL;
    }

  if (p_old_encoded == 0)
    return lim_malloc (size);

#ifdef LIM_NO_ENCODE
  // Temporarily encode the address within lim_realloc to model the overheads below of squeezing out the old metadata:
  p_old_encoded = reconstruct_encoded_pointer(p_old_encoded);
#endif

  void* p_old_decoded = p_old_encoded;
#ifdef LIM_CATCH_1B_OVF
  // amount the old allocation was shifted so that data was aligned with upper bound:
  size_t old_shift = 0;
#endif
  if (is_encoded_address((uint64_t)p_old_encoded)) {
    p_old_decoded = (void*) lim_decode_pointer( (uint64_t) p_old_encoded);
#ifdef LIM_CATCH_1B_OVF
    uint8_t encoded_size = get_encoded_size((uint64_t) p_old_encoded);
    uint8_t* ptr_metadata = (uint8_t*) get_metadata_address((uint64_t) p_old_decoded, encoded_size);
    size_t meta_size = get_metadata_size(encoded_size);
    lim_decoded_metadata_t dec_meta = lim_decode_metadata(ptr_metadata, meta_size, get_middle_address((uint64_t)p_old_decoded, encoded_size));
    // sanity check for metadata decoding:
    assert(dec_meta.tag_left == dec_meta.tag_right);
    assert(dec_meta.lower_la <= (uintptr_t)p_old_decoded);
    old_shift = (uintptr_t)p_old_decoded - dec_meta.lower_la;
    // use actual first address in original allocation when generating new allocation:
    p_old_decoded = (void *)dec_meta.lower_la;
#endif
    assert (MALLOC_USABLE_SIZE((void *)p_old_decoded) != 0);
  }

  void* oldmem = p_old_decoded;

  /* chunk corresponding to oldmem */
  const mchunkptr oldp = mem2chunk (oldmem);
  /* its size */
  const INTERNAL_SIZE_T oldsize = chunksize (oldp);

  mstate av;
  if (chunk_is_mmapped (oldp))
    av = NULL;
  else
    {
      MAYBE_INIT_TCACHE ();
      av = arena_for_chunk (oldp);
    }

  size_t meta_size = 0;
  void *p_new_decoded = p_old_decoded;

#pragma GCC diagnostic push
// new_encoded_size is only used if LIM pointer encoding is enabled.
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
  uint8_t new_encoded_size = 0;
#pragma GCC diagnostic pop

  bool copy_alloc;
  bool del_oldmem;
  bool split_rem;

  mchunkptr        newp = NULL;            /* chunk to return */
  INTERNAL_SIZE_T  newsize;         /* its size */

  INTERNAL_SIZE_T nb = 0;         /* padded request size */

  // important to capture this prior to any updates to p_old_decoded below:
  size_t size_old = MALLOC_USABLE_SIZE(p_old_decoded);
  assert (size_old != 0);
  size_t old_meta_size = 0;
  if (is_encoded_address((uintptr_t)p_old_encoded)){
    uint8_t old_encoded_size = get_encoded_size((uintptr_t)p_old_encoded);
    old_meta_size = (trace_only) ? 0 : get_metadata_size(old_encoded_size);
    size_old -= old_meta_size;
  }
  size_t bytes_to_copy = min_uint64(size, size_old);

  // set to true if and when previous metadata has been squeezed out:
  bool old_metadata_removed = false;

  if (chunk_is_mmapped (oldp)) {
    copy_alloc = true;
    split_rem = false;
    del_oldmem = !DUMPED_MAIN_ARENA_CHUNK (oldp);
#if HAVE_MREMAP && !defined(LIM_CATCH_1B_OVF)
    // Disallow the use of mremap when allocs are shifted towards end, since the mremap may discard
    // some needed data.
    if (del_oldmem) {
      // mmap-ed allocations are large, so assume that the largest metadata slot size will be required:
      if (!checked_request2size (size + LIM_METADATA_SIZE_512B, &nb))
        {
          __set_errno (ENOMEM);
          return NULL;
        }

      if (size < size_old + old_meta_size) {
        // There's a chance the allocation could lose some portion of the
        // data during the mremap if the metadata is not squeezed out now.
        squeeze_out_old_metadata((uintptr_t)p_old_encoded, (uintptr_t)p_old_decoded, bytes_to_copy);
        old_metadata_removed = true;
      }
      newp = mremap_chunk (oldp, nb);

      if (newp) {
        copy_alloc = false;
        p_new_decoded = chunk2mem (newp);
        // The original memory has effectively been moved to this new linear address,
        // so p_old_decoded needs to track that so the old metadata slot can be properly
        // squeezed out below if needed.
        // It's fine to keep the original value of p_old_encoded, because only a non-address
        // attribute, specifically the encoded size, is extracted later from that.
        p_old_decoded = p_new_decoded;
        new_encoded_size = lim_fit_slot((uintptr_t)p_new_decoded, size, &meta_size);
      }
    }
#endif
  } else {
    copy_alloc = false;
    del_oldmem = true;
    split_rem = true;

    mchunkptr        next;            /* next contiguous chunk after oldp */

        /* oldmem size */
    if (__builtin_expect (chunksize_nomask (oldp) <= 2 * SIZE_SZ, 0)
        || __builtin_expect (oldsize >= av->system_mem, 0))
      malloc_printerr ("realloc(): invalid old size");

    check_inuse_chunk (av, oldp);

    next = chunk_at_offset (oldp, oldsize);
    INTERNAL_SIZE_T nextsize = chunksize (next);
    if (__builtin_expect (chunksize_nomask (next) <= 2 * SIZE_SZ, 0)
        || __builtin_expect (nextsize >= av->system_mem, 0))
      malloc_printerr ("realloc(): invalid next size");

    new_encoded_size = lim_fit_slot((uintptr_t)p_old_decoded, size, &meta_size);

    if (!checked_request2size (size + meta_size, &nb))
      {
        __set_errno (ENOMEM);
        return NULL;
      }

    if ((unsigned long) (oldsize) >= (unsigned long) (nb))
      {
        /* already big enough; split below */
        newp = oldp;
        newsize = oldsize;
      }

    else
      {
        /* Try to expand forward into top */
        if (next == av->top &&
            (unsigned long) (newsize = oldsize + nextsize) >=
            (unsigned long) (nb + MINSIZE))
          {
            set_head_size (oldp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
            av->top = chunk_at_offset (oldp, nb);
            set_head (av->top, (newsize - nb) | PREV_INUSE);
            check_inuse_chunk (av, oldp);
            split_rem = false;
          }

        /* Try to expand forward into next chunk;  split off remainder below */
        else if (next != av->top &&
                !inuse (next) &&
                (unsigned long) (newsize = oldsize + nextsize) >=
                (unsigned long) (nb))
          {
            newp = oldp;
            unlink_chunk (av, next);
          }

        /* else allocate, copy, free below: */
        else
          {
            copy_alloc = true;
            split_rem = false;
          }
      }
  }

    if (copy_alloc) {
      p_new_decoded = lim_min_slot_alloc(size, &meta_size, false);
      if (p_new_decoded == NULL)
        return p_new_decoded;
      
      mchunkptr next = chunk_at_offset (oldp, oldsize);
      newp = mem2chunk (p_new_decoded);

      /*
          Avoid copy if newp is next chunk after oldp.
        */
      if (newp == next)
        {
          newsize = chunksize (newp);
          newsize += oldsize;
          newp = oldp;
          p_new_decoded = p_old_decoded;
          copy_alloc = false;
          split_rem = true;

          // re-fit to a potentially different slot, since the base is reset to the original base:
          lim_fit_slot((uintptr_t)p_new_decoded, size, &meta_size);
          if (!checked_request2size (size + meta_size, &nb))
            {
              __set_errno (ENOMEM);
              return NULL;
            }
        }
      new_encoded_size = calculate_encoded_size((uint64_t) p_new_decoded, size + meta_size);
    }
#ifdef LIM_CATCH_1B_OVF
    size_t new_shift = lim_compute_bounded_data_size(p_new_decoded, size, meta_size, NULL, NULL) - size;
#endif
    uint64_t p_new_metadata = get_metadata_address((uint64_t) p_new_decoded, new_encoded_size);
    // squeeze out the old metadata slot:
    if (!old_metadata_removed && is_encoded_address((uint64_t)p_old_encoded)){
#ifdef LIM_CATCH_1B_OVF
      {
        // When shifting allocations to the end, for simplicity and since that
        // has not yet been optimized, we unconditionally squeeze out the old
        // metadata and shift prior to space being cleared for the new metadata
        // such that the final allocation ends up with the copied data aligned
        // against the upper bound.
#else
      uint8_t old_encoded_size = get_encoded_size((uint64_t)p_old_encoded);
      uint64_t p_metadata = get_metadata_address((uint64_t) p_old_decoded, old_encoded_size);
      if (p_metadata != p_new_metadata) {
        // This is only needed if the metadata size or location has changed.
        // Keep in mind that an mremap is recorded as effectively no change,
        // since mremap has already moved the content as well.
        // It is sufficient to check whether the first metadata byte location has
        // changed, because a change in metadata size also leads that location to
        // change.
#endif
        squeeze_out_old_metadata((uintptr_t)p_old_encoded, (uintptr_t)p_old_decoded, bytes_to_copy);
        old_metadata_removed = true;
      }
    }
#ifdef LIM_CATCH_1B_OVF
    // Revert back to the unshifted decoded address so that the subsequent copies
    // start at the beginning of the actual, shifted data.
    p_old_decoded = (void *)((uintptr_t)p_old_decoded + old_shift);
    // Update p_new_decoded here so that the subsequent copies to initalize the new
    // allocation incorporate the necessary shift:
    p_new_decoded = (void *)((uintptr_t)p_new_decoded + new_shift);
#endif
    uint64_t starting_point_for_second_chunk = (trace_only) ? p_new_metadata : p_new_metadata + meta_size;
    size_t bytes_before_metadata = min_uint64(bytes_to_copy, (p_new_metadata - (uint64_t)p_new_decoded));
    assert (bytes_before_metadata <= size);
    size_t bytes_after_metadata = bytes_to_copy - bytes_before_metadata;
    if (!copy_alloc) {
      if (old_metadata_removed) {
        if (lim_data_disp) {
          displace_data(p_new_metadata, meta_size, p_new_metadata + bytes_after_metadata);
        } else {
          memmove((void *) starting_point_for_second_chunk, (void *)p_new_metadata, bytes_after_metadata);
        }
      }
      del_oldmem = false;
    } else {
      if (lim_data_disp) {
        memcpy((void*) p_new_decoded, (void*) p_old_decoded, bytes_to_copy);
        displace_data(p_new_metadata, meta_size, p_new_metadata + bytes_after_metadata);
      } else {
        memcpy((void*) p_new_decoded, (void*) p_old_decoded, bytes_before_metadata);
        // For trace-only, don't skip over the metadata region.
        memcpy((void*) starting_point_for_second_chunk, (void*) ((uint64_t)p_old_decoded+bytes_before_metadata), bytes_after_metadata);
      }
    }
#ifdef LIM_CATCH_1B_OVF
    p_old_decoded = (void*)((uintptr_t)p_old_decoded - old_shift);
    p_new_decoded = (void*)((uintptr_t)p_new_decoded - new_shift);
#endif
    if (del_oldmem) {
      lim_free_int(old_metadata_removed? p_old_decoded : p_old_encoded);
    }

    if (split_rem) {
      mchunkptr        remainder;       /* extra space at end of newp */
      unsigned long    remainder_size;  /* its size */

      /* If possible, free extra space in old or extended chunk */

      assert ((unsigned long) (newsize) >= (unsigned long) (nb));

      remainder_size = newsize - nb;

      if (remainder_size < MINSIZE)   /* not enough extra to split off */
        {
          set_head_size (newp, newsize | (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_inuse_bit_at_offset (newp, newsize);
        }
      else   /* split remainder */
        {
          remainder = chunk_at_offset (newp, nb);
          set_head_size (newp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE |
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
          /* Mark remainder as inuse so free() won't complain */
          set_inuse_bit_at_offset (remainder, remainder_size);
          _int_free (av, remainder, 1);
        }
    }

  size_t usable_size = MALLOC_USABLE_SIZE(p_new_decoded);
  assert (usable_size != 0);

  write_lim_trace(size, meta_size, usable_size);

  return encode_and_set_metadata(p_new_decoded, size, meta_size);
}
#else // OPT_LIM_REALLOC
void* lim_realloc(void* p_old_encoded, size_t size){
    size_t meta_size = 0;
    size_t size_old;
    void* p_old_decoded = NULL;
    if (is_encoded_address((uint64_t)p_old_encoded)){
      p_old_decoded = (void*) lim_decode_pointer( (uint64_t) p_old_encoded);
      uint8_t old_encoded_size = get_encoded_size((uint64_t)p_old_encoded);
      size_t old_meta_size = (trace_only) ? 0 : get_metadata_size(old_encoded_size);
      assert (MALLOC_USABLE_SIZE(p_old_decoded) != 0);
      size_old = MALLOC_USABLE_SIZE(p_old_decoded)-old_meta_size; 
      uint64_t p_metadata = get_metadata_address((uint64_t) p_old_decoded, old_encoded_size);
      uint64_t p_after_metadata = p_metadata + old_meta_size;
      size_t bytes_before_metadata = p_metadata - (uint64_t) p_old_decoded;
      assert (bytes_before_metadata <= size_old);
      size_t bytes_after_metadata = size_old - bytes_before_metadata;
      memmove((void*) p_metadata, (void*) p_after_metadata, bytes_after_metadata);
    } else {
      p_old_decoded = p_old_encoded;
      size_old = MALLOC_USABLE_SIZE(p_old_encoded);
    }
    void *p_new_decoded = lim_min_slot_alloc(size, &meta_size, false);
    void *p_new_encoded = encode_and_set_metadata (p_new_decoded, size, meta_size);
#ifdef LIM_NO_ENCODE
    p_new_encoded = reconstruct_encoded_pointer(p_new_encoded);
#endif
    uint8_t new_encoded_size = get_encoded_size((uint64_t)p_new_encoded);
    uint64_t p_metadata = get_metadata_address((uint64_t) p_new_decoded, new_encoded_size);
    size_t bytes_to_copy = min_uint64(size, size_old);
    size_t bytes_before_metadata = min_uint64(bytes_to_copy, (p_metadata - (uint64_t)p_new_decoded));
    assert (bytes_before_metadata <= size);
    size_t bytes_after_metadata = bytes_to_copy - bytes_before_metadata;
    memcpy((void*) p_new_decoded, (void*) p_old_decoded, bytes_before_metadata);
    // For trace-only, don't skip over the metadata region.
    uint64_t starting_point_for_second_chunk = (trace_only) ? (uint64_t)p_new_decoded+bytes_before_metadata
                                            : (uint64_t)p_new_decoded+bytes_before_metadata + meta_size;
    memcpy((void*) (starting_point_for_second_chunk), (void*) ((uint64_t)p_old_decoded+bytes_before_metadata), bytes_after_metadata);
    // The metadata has already been overwritten, so pass the decoded pointer to lim_free to
    // avoid free unnecessarily overwriting the metadata location again:
    lim_free_int(p_old_decoded);

    size_t usable_size = MALLOC_USABLE_SIZE(p_new_decoded);
    write_lim_trace(size, meta_size, usable_size);

#ifdef LIM_NO_ENCODE
    return p_new_decoded;
#else
    return p_new_encoded;
#endif
}
#endif

void lim_free_int(void* p_in){
  void* ptr;
  if (is_encoded_address((uint64_t)p_in)) {
    ptr =  (void*) lim_decode_pointer((uint64_t) p_in);
    uint8_t encoded_size = get_encoded_size((uint64_t) p_in);
    uint8_t* ptr_metadata = (uint8_t*) get_metadata_address((uint64_t) ptr, encoded_size);
    size_t meta_size = get_metadata_size(encoded_size);
#ifdef LIM_CATCH_1B_OVF
    lim_decoded_metadata_t dec_meta = lim_decode_metadata(ptr_metadata, meta_size, get_middle_address((uint64_t)ptr, encoded_size));
    // sanity check for metadata decoding:
    assert(dec_meta.tag_left == dec_meta.tag_right);
    // supply actual first address in allocation to free():
    ptr = (void *)dec_meta.lower_la;
#endif
    void* dst = (void*) ptr_metadata;
#ifdef LIM_NO_ENCODE
    // just in case the reconstructed pointer points outside the current allocation, just touch the memory, don't actually change it:
    memmove(dst, dst, meta_size);
#else
    __asm__ __volatile__("rep stosb" : "+D"(dst), "+c"(meta_size) : "a"(0) : "cc", "memory");
#endif
  } else {
    ptr = p_in;
  }
  REAL_FREE(ptr);
  return;
}

void lim_free(void* p_in){
#ifdef LIM_NO_ENCODE
  p_in = reconstruct_encoded_pointer(p_in);
#endif
  lim_free_int(p_in);
}

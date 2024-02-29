#ifndef _CC_CC_H_
#define _CC_CC_H_

#include <stddef.h>
#include <stdint.h>
#define _CC_GLOBALS_NO_INCLUDES_
#include "cc_globals.h"
#include "try_box.h"

/* Prevents malloc stat updates that seem to cause deadlock with threading */
#define CC_DISABLE_MEM_STATS_FOR_THREADS

/* Could we have an encrypted stack (i.e., %rsp) at run-time? */
#define CC_MAY_HAVE_C3_ENCODED_STACK

#endif  // _CC_CC_H_
#ifndef _CC_CC_H_
#define _CC_CC_H_
#ifdef CC
#include "cc_globals.h"

/* Prevents malloc stat updates that seem to cause deadlock with threading */
#define CC_DISABLE_MEM_STATS_FOR_THREADS

#endif // CC
#endif // _CC_CC_H_
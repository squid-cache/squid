/*
 * $Id: stub_memaccount.c,v 1.5 2001/02/07 18:56:51 hno Exp $
 */

/* Stub function for programs not implementing statMemoryAccounted */
#include "config.h"
#include "util.h"
int
statMemoryAccounted(void)
{
    return -1;
}

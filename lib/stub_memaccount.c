/*
 * $Id: stub_memaccount.c,v 1.6 2003/01/23 00:37:02 robertc Exp $
 */

/* Stub function for programs not implementing statMemoryAccounted */
#include "config.h"
#include "util.h"
int
statMemoryAccounted(void)
{
    return -1;
}

/*
 * $Id: stub_memaccount.c,v 1.4 1999/05/04 21:20:42 wessels Exp $
 */

/* Stub function for programs not implementing statMemoryAccounted */
#include <config.h>
int
statMemoryAccounted(void)
{
    return -1;
}

/*
 * $Id: Stack.c,v 1.3 1998/02/26 17:49:54 wessels Exp $
 *
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Stack is a (void*) stack with fixed capacity with limited accounting.
 * Errors are handled with asserts.
 */


/*
 * To-do:
 *    - stack that grows as needed if a given delta is non zero
 */


#if 0

Synopsis(void)
{

    /*
     * creating a stack that can hold up to objCnt pointers. 
     * If objCnt is zero, the stack is always full (disabled)
     */
    Stack *s1 = stackCreate(objCnt);
    Stack *s2 = stackCreate(objCnt * 2);

    /*
     * pop/push works as expected; it is OK to push a null pointer
     */
    if (!s2->is_full && s1->count)
	stackPush(s2, stackPop(s1));

    /* destroying a stack */
    stackDestroy(s1);
}

#endif /* Synopsis */

#include "config.h"
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#include "util.h"
#include "Stack.h"

/* performance hack instead of non-ANSI inline function */
#define stackIsFull(s) (s->count >= s->capacity)

Stack *
stackCreate(size_t capacity)
{
    Stack *s = xcalloc(1, sizeof(Stack));
    s->buf = capacity > 0 ? xcalloc(capacity, sizeof(void *)) : NULL;
    s->capacity = capacity;
    s->count = 0;
    s->is_full = stackIsFull(s);
    /* other members are set to 0 in calloc */
    return s;
}

void
stackDestroy(Stack * s)
{
    assert(s);
    /* could also warn if some objects are left */
    if (s->buf)
	xfree(s->buf);
    xfree(s);
}

void *
stackPop(Stack * s)
{
    void *popped;
    assert(s);
    assert(s->count);
    popped = s->buf[--s->count];
    s->is_full = stackIsFull(s);
    s->pop_count++;		/* might overflow eventually, but ok */
    return popped;
}

void
stackPush(Stack * s, void *obj)
{
    assert(s);
    assert(!s->is_full);
    s->buf[s->count++] = obj;
    s->is_full = stackIsFull(s);
    s->push_count++;		/* might overflow eventually, but ok */
}

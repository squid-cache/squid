/*
 * $Id: Stack.c,v 1.4 1998/03/03 00:30:57 rousskov Exp $
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
 * Stack is a (void*) stack with unlimited capacity and limited accounting.
 */


#include "config.h"
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#include "util.h"
#include "Stack.h"

static void stackGrow(Stack * s, int min_capacity);

Stack *
stackCreate()
{
    Stack *s = xmalloc(sizeof(Stack));
    stackInit(s);
    return s;
}

void
stackInit(Stack * s)
{
    assert(s);
    memset(s, 0, sizeof(Stack));
}

void
stackClean(Stack * s)
{
    assert(s);
    /* could also warn if some objects are left */
    xfree(s->items);
    s->items = NULL;
}

void
stackDestroy(Stack * s)
{
    assert(s);
    stackClean(s);
    xfree(s);
}

void *
stackPop(Stack * s)
{
    assert(s);
    assert(s->count);
    return s->items[--s->count];
}

void
stackPush(Stack * s, void *obj)
{
    assert(s);
    if (s->count >= s->capacity)
	stackGrow(s, s->count+1);
    s->items[s->count++] = obj;
}

/* if you are going to push a known and large number of items, call this first */
void
stackPrePush(Stack * s, int push_count)
{
    assert(s);
    if (s->count + push_count > s->capacity)
	stackGrow(s, s->count + push_count);
}

/* grows internal buffer to satisfy required minimal capacity */
static void
stackGrow(Stack * s, int min_capacity)
{
    static const int min_delta = 16;
    int delta;
    assert(s->capacity < min_capacity);
    delta = min_capacity;
    /* make delta a multiple of min_delta */
    delta += min_delta-1;
    delta /= min_delta;
    delta *= min_delta;
    /* actual grow */
    assert(delta > 0);
    s->capacity += delta;
    s->items = s->items ?
	xrealloc(s->items, s->capacity * sizeof(void*)) :
	xmalloc(s->capacity * sizeof(void*));
    /* reset, just in case */
    memset(s->items+s->count, 0, (s->capacity-s->count) * sizeof(void*));
}

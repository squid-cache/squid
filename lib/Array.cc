/*
 * $Id: Array.cc,v 1.4 1999/05/04 21:20:36 wessels Exp $
 *
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

/*
 * Array is an array of (void*) items with unlimited capacity
 *
 * Array grows when arrayAppend() is called and no space is left
 * Currently, array does not have an interface for deleting an item because
 *     we do not need such an interface yet.
 */


#include "config.h"
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#include "util.h"
#include "Array.h"

static void arrayGrow(Array * a, int min_capacity);

Array *
arrayCreate()
{
    Array *a = xmalloc(sizeof(Array));
    arrayInit(a);
    return a;
}

void
arrayInit(Array * a)
{
    assert(a);
    memset(a, 0, sizeof(Array));
}

void
arrayClean(Array * a)
{
    assert(a);
    /* could also warn if some objects are left */
    xfree(a->items);
    a->items = NULL;
}

void
arrayDestroy(Array * a)
{
    assert(a);
    arrayClean(a);
    xfree(a);
}

void
arrayAppend(Array * a, void *obj)
{
    assert(a);
    if (a->count >= a->capacity)
	arrayGrow(a, a->count + 1);
    a->items[a->count++] = obj;
}

/* if you are going to append a known and large number of items, call this first */
void
arrayPreAppend(Array * a, int app_count)
{
    assert(a);
    if (a->count + app_count > a->capacity)
	arrayGrow(a, a->count + app_count);
}

/* grows internal buffer to satisfy required minimal capacity */
static void
arrayGrow(Array * a, int min_capacity)
{
    const int min_delta = 16;
    int delta;
    assert(a->capacity < min_capacity);
    delta = min_capacity;
    /* make delta a multiple of min_delta */
    delta += min_delta - 1;
    delta /= min_delta;
    delta *= min_delta;
    /* actual grow */
    assert(delta > 0);
    a->capacity += delta;
    a->items = a->items ?
	xrealloc(a->items, a->capacity * sizeof(void *)) :
         xmalloc(a->capacity * sizeof(void *));
    /* reset, just in case */
    memset(a->items + a->count, 0, (a->capacity - a->count) * sizeof(void *));
}

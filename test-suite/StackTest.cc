
/*
 * $Id$
 *
 * DEBUG: section 19    Store Memory Primitives
 * AUTHOR: Robert Collins
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 * Copyright (c) 2003  Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "Stack.h"

int
main(int argc, char **argv)
{
    Stack<int> aStack;
    assert (aStack.size() == 0);
    aStack.push_back(2);
    assert (aStack.size() == 1);
    assert (aStack.top() == 2);
    assert (aStack.pop() == 2);
    assert (aStack.size() == 0);
    Stack<> oldStack;
    assert (oldStack.size() == 0);
    oldStack.push_back(&aStack);
    assert (oldStack.size() == 1);
    assert (oldStack.top() == &aStack);
    assert (oldStack.pop() == &aStack);
    assert (oldStack.size() == 0);
    return 0;
}

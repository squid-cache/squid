
/*
 * $Id: debug.cc,v 1.2 2003/07/08 22:38:50 robertc Exp $
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
#include "stmem.h"
#include "mem_node.h"
#include <iostream>

class StreamTest {
  public:
    std::ostream &serialise(std::ostream &);
    int const getAnInt() const;
    char const *getACString() const;
};

std::ostream &operator << (std::ostream &aStream, StreamTest &anObject)
{
    return anObject.serialise(aStream);
}

std::ostream&
StreamTest::serialise(std::ostream &aStream)
{
    aStream << "stream test";
    return aStream;
}

int const
StreamTest::getAnInt() const
{
    return 5;
}

char const *
StreamTest::getACString() const
{
    return "ThisIsAStreamTest";
}

int
main (int argc, char *argv)
{
    Debug::Levels[1] = 8;
    debugs (1,1,"test" << "string");
    debugs (1,9,"dont show this" << "string");
    debugs (1,1,"test" << "string");
    debugs (1,1,"test" << "string");
    if (true)
	debugs(1,9,"this won't compile if the macro is broken.");
    else
	debugs(1,1,"bar");
    StreamTest aStreamObject;
    StreamTest *streamPointer (&aStreamObject);
    debugs(1,1,aStreamObject);
    debugs(1,1,streamPointer->getAnInt() << " " << aStreamObject.getACString());
    return 0;
}

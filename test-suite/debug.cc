/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 19    Store Memory Primitives */

#include "squid.h"
#include "Debug.h"
#include "mem_node.h"
#include "stmem.h"

class StreamTest
{
public:
    std::ostream &serialise(std::ostream &);
    int getAnInt() const;
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

int
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
main(int argc, char **argv)
{
    Debug::Levels[1] = 8;
    debugs (1,1,"test" << "string");
    debugs (1,9,"do not show this" << "string");
    debugs (1,1,"test" << "string");
    debugs (1,1,"test" << "string");
    if (true)
        debugs(1,9,"this won't compile if the macro is broken.");
    else
        debugs(1, DBG_IMPORTANT,"bar");
    StreamTest aStreamObject;
    StreamTest *streamPointer (&aStreamObject);
    debugs(1, DBG_IMPORTANT,aStreamObject);
    debugs(1, DBG_IMPORTANT,streamPointer->getAnInt() << " " << aStreamObject.getACString());
    return 0;
}


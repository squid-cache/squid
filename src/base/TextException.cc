/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "Debug.h"
#include "util.h"

TextException::TextException()
{
    message=NULL;
    theFileName=NULL;
    theLineNo=0;
    theId=0;
}

TextException::TextException(const TextException& right) :
    message((right.message?xstrdup(right.message):NULL)), theFileName(right.theFileName), theLineNo(right.theLineNo), theId(right.theId)
{
}

TextException::TextException(const char *aMsg, const char *aFileName, int aLineNo, unsigned int anId):
    message(aMsg?xstrdup(aMsg):NULL), theFileName(aFileName), theLineNo(aLineNo), theId(anId)
{}

TextException::~TextException() throw()
{
    if (message) xfree(message);
}

TextException& TextException::operator=(const TextException &right)
{
    if (this==&right) return *this;
    if (message) xfree(message);
    message=(right.message?xstrdup(right.message):NULL);
    theFileName=right.theFileName;
    theLineNo=right.theLineNo;
    theId=right.theId;
    return *this;
}

const char *TextException::what() const throw()
{
    /// \todo add file:lineno
    return message ? message : "TextException without a message";
}

unsigned int TextException::FileNameHash(const char *fname)
{
    const char *s = NULL;
    unsigned int n = 0;
    unsigned int j = 0;
    unsigned int i = 0;
    s = strrchr(fname, '/');

    if (s)
        ++s;
    else
        s = fname;

    while (*s) {
        ++j;
        n ^= 271 * (unsigned) *s;
        ++s;
    }
    i = n ^ (j * 271);
    /*18bits of a 32 bit integer used  for filename hash (max hash=262143),
      and 14 bits for storing line number (16k max).
      If you change this policy remember to update the FileNameHash function
      in the scripts/calc-must-ids.pl script
    */
    return i % 262143;
}

void Throw(const char *message, const char *fileName, int lineNo, unsigned int id)
{

    // or should we let the exception recepient print the exception instead?

    if (fileName) {
        debugs(0, 3, fileName << ':' << lineNo << ": exception" <<
               (message ? ": " : ".") << (message ? message : ""));
    } else {
        debugs(0, 3, "exception" <<
               (message ? ": " : ".") << (message ? message : ""));
    }

    throw TextException(message, fileName, lineNo, id);
}


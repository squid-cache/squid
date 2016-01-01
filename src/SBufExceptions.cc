/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "OutOfBoundsException.h"
#include "SBuf.h"
#include "SBufExceptions.h"

OutOfBoundsException::OutOfBoundsException(const SBuf &throwingBuf,
        SBuf::size_type &pos,
        const char *aFileName, int aLineNo)
    : TextException(NULL, aFileName, aLineNo),
      theThrowingBuf(throwingBuf),
      accessedPosition(pos)
{
    SBuf explanatoryText("OutOfBoundsException");
    if (aLineNo != -1)
        explanatoryText.appendf(" at line %d", aLineNo);
    if (aFileName != NULL)
        explanatoryText.appendf(" in file %s", aFileName);
    explanatoryText.appendf(" while accessing position %d in a SBuf long %d",
                            pos, throwingBuf.length());
    // we can safely alias c_str as both are local to the object
    //  and will not further manipulated.
    message = xstrndup(explanatoryText.c_str(),explanatoryText.length());
}

OutOfBoundsException::~OutOfBoundsException() throw()
{ }

InvalidParamException::InvalidParamException(const char *aFilename, int aLineNo)
    : TextException("Invalid parameter", aFilename, aLineNo)
{ }

SBufTooBigException::SBufTooBigException(const char *aFilename, int aLineNo)
    : TextException("Trying to create an oversize SBuf", aFilename, aLineNo)
{ }


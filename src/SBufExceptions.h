/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SBUFEXCEPTIONS_H
#define SQUID_SBUFEXCEPTIONS_H

#include "base/TextException.h"

/**
 * Exception raised when call parameters are not valid
 * \todo move to an Exceptions.h?
 */
class InvalidParamException : public TextException
{
public:
    explicit InvalidParamException(const char *aFilename = 0, int aLineNo = -1);
};

/**
 * Exception raised when an attempt to resize a SBuf would cause it to reserve too big
 */
class SBufTooBigException : public TextException
{
public:
    explicit SBufTooBigException(const char *aFilename = 0, int aLineNo = -1);
};

#endif /* SQUID_SBUFEXCEPTIONS_H */


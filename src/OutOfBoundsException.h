#ifndef _SQUID_SRC_OUTOFBOUNDSEXCEPTION_H
#define _SQUID_SRC_OUTOFBOUNDSEXCEPTION_H

#include "base/TextException.h"
#include "SBuf.h"

/**
 * Exception raised when the user is going out of bounds when accessing
 * a char within the SBuf
 */
class OutOfBoundsException : public TextException
{
public:
    OutOfBoundsException(const SBuf &buf, SBuf::size_type &pos, const char *aFileName = 0, int aLineNo = -1);
    virtual ~OutOfBoundsException() throw();

protected:
    SBuf theThrowingBuf;
    SBuf::size_type accessedPosition;
};

#endif /* _SQUID_SRC_OUTOFBOUNDSEXCEPTION_H */

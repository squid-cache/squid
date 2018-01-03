/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IOREQUESTOR_H
#define SQUID_IOREQUESTOR_H

#include "base/RefCount.h"

class ReadRequest;

class WriteRequest;

class IORequestor : public RefCountable
{

public:
    typedef RefCount<IORequestor> Pointer;
    virtual void ioCompletedNotification() = 0;
    virtual void closeCompleted() = 0;
    virtual void readCompleted(const char *buf, int len, int errflag, RefCount<ReadRequest>) = 0;
    virtual void writeCompleted(int errflag, size_t len, RefCount<WriteRequest>) = 0;
};

#endif /* SQUID_IOREQUESTOR_H */


/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_READREQUEST_H
#define SQUID_READREQUEST_H

#include "base/RefCount.h"
#include "cbdata.h"

class ReadRequest : public RefCountable
{

public:
    typedef RefCount<ReadRequest> Pointer;
    ReadRequest(char *buf, off_t offset, size_t len);
    virtual ~ReadRequest() {}

    char *buf;
    off_t offset;
    size_t len;

private:
    CBDATA_CLASS2(ReadRequest);
};

#endif /* SQUID_READREQUEST_H */


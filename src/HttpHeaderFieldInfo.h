/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHEADERFIELDINFO_H_
#define SQUID_HTTPHEADERFIELDINFO_H_

#include "HttpHeaderFieldStat.h"
#include "SquidString.h"

/// compiled version of HttpHeaderFieldAttrs plus stats. Currently a POD.
class HttpHeaderFieldInfo
{
public:
    HttpHeaderFieldInfo() : id(HDR_ACCEPT), type(ftInvalid) {}

    http_hdr_type id;
    String name;
    field_type type;
    HttpHeaderFieldStat stat;
};

#endif /* SQUID_HTTPHEADERFIELDINFO_H_ */


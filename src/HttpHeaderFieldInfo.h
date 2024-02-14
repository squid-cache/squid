/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTPHEADERFIELDINFO_H
#define SQUID_SRC_HTTPHEADERFIELDINFO_H

#include "http/RegisteredHeaders.h"
#include "HttpHeaderFieldStat.h"
#include "SquidString.h"

/// compiled version of HttpHeaderFieldAttrs plus stats. Currently a POD.
class HttpHeaderFieldInfo
{
public:
    HttpHeaderFieldInfo() : id(Http::HdrType::ACCEPT), type(Http::HdrFieldType::ftInvalid) {}

    Http::HdrType id;
    String name;
    Http::HdrFieldType type;
    HttpHeaderFieldStat stat;
};

#endif /* SQUID_SRC_HTTPHEADERFIELDINFO_H */


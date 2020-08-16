/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID__SRC_HTTP_HEADERFIELD_H
#define _SQUID__SRC_HTTP_HEADERFIELD_H

#include "base/Packable.h"
#include "base/RefCount.h"
#include "http/RegisteredHeaders.h"
#include "sbuf/SBuf.h"
#include "SquidString.h"

namespace Http
{

/// Internal representation of an HTTP header field.
/// see RFC 7230 section 3.2
class HeaderField : public RefCountable
{
    MEMPROXY_CLASS(HeaderField);

public:
    HeaderField(Http::HdrType id, const SBuf &name, const char *value);
    ~HeaderField();
    HeaderField *clone() const;
    void packInto(Packable *p) const;

    Http::HdrType id; ///< Squid internal ID for registered headers
    SBuf name;        ///< HTTP field-name
    String value;     ///< HTTP field-value
};

} // namespace Http

#endif /* _SQUID__SRC_HTTP_HEADERFIELD_H */

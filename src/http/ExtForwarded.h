/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_EXTFORWARDED_H
#define SQUID_SRC_HTTP_EXTFORWARDED_H

#include "http/forward.h"

#include <iosfwd>

class ConfigParser;

namespace Http
{

// settings for the 'Forwarded:' HTTP header extension
// and legacy X-Forwarded-For header
class ExtForwarded
{
public:
    explicit ExtForwarded(ConfigParser &);

    /* Configuration::Component API */
    void dump(std::ostream &) const;

public:
    enum class Mode {
        fwdTransparent,
        fwdDelete,
        xffTruncate,
        xffOn,
        xffOff
    } mode;
};

} // namespace Http

#endif /* SQUID_SRC_HTTP_EXTFORWARDED_H */

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

// GCC v6 requires "reopening" of the namespace here, instead of the usual
// definitions like Configuration::Component<T>::Parse():
// error: specialization of Configuration::Component... in different namespace
// TODO: Refactor to use the usual style after we stop GCC v6 support.
namespace Configuration {

template <>
inline Http::ExtForwarded *
Configuration::Component<Http::ExtForwarded*>::Parse(ConfigParser &parser)
{
    return new Http::ExtForwarded(parser);
}

template <>
inline void
Configuration::Component<Http::ExtForwarded*>::Print(std::ostream &os, Http::ExtForwarded* const & ExtForwarded)
{
    assert(ExtForwarded);
    ExtForwarded->dump(os);
}

template <>
inline void
Configuration::Component<Http::ExtForwarded*>::Free(Http::ExtForwarded * const ExtForwarded)
{
    delete ExtForwarded;
}

} // namespace Configuration

#endif /* SQUID_SRC_HTTP_EXTFORWARDED_H */

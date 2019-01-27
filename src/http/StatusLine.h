/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTP_STATUSLINE_H
#define SQUID_HTTP_STATUSLINE_H

#include "http/ProtocolVersion.h"
#include "http/StatusCode.h"
#include "SquidString.h"

class Packable;
class String;

namespace Http
{

/**
 * Holds the values parsed from an HTTP reply status line.
 *
 * For example: HTTP/1.1 200 OK
 */
class StatusLine
{
public:
    /// reset this status-line back to empty state
    void init();

    /// reset this status-line back to Internal Server Error state
    void clean();

    /// set this status-line to the given values
    /// when reason is NULL the default message text for this StatusCode will be used
    /// when reason is not NULL, it must not point to a dynamically allocated value
    void set(const AnyP::ProtocolVersion &newVersion, Http::StatusCode newStatus, const char *newReason = NULL);

    /// reset the reason phrase to its default status code-derived value
    void resetReason() { reason_ = nullptr; }

    /// retrieve the status code for this status line
    Http::StatusCode status() const { return status_; }

    /// retrieve the reason string for this status line
    const char *reason() const;

    /// pack fields into a Packable object
    void packInto(Packable *) const;

    /**
     * Parse a buffer and fill internal structures;
     * \return true on success, false otherwise
     */
    bool parse(const String &protoPrefix, const char *start, const char *end);

public:
    /* public, read only */

    /**
     * By rights protocol name should be a constant "HTTP", with no need for this field to exist.
     * However there are protocols which violate HTTP by sending their own custom formats
     * back with other protocol names (ICY streaming format being the current major problem).
     */
    // XXX: protocol is part of AnyP::ProtocolVersion. We should be able to use version.protocol instead now.
    AnyP::ProtocolType protocol;

    AnyP::ProtocolVersion version;     ///< breakdown of protocol version label: (HTTP/ICY) and (0.9/1.0/1.1)

private:
    /// status code. ie 100 ... 200 ... 404 ... 599
    Http::StatusCode status_;

    /// points to a _constant_ string (default or supplied), never free()d
    const char *reason_;
};

} // namespace Http

#endif /* SQUID_HTTP_STATUSLINE_H */


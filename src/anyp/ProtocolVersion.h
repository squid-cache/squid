/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ANYP_PROTOCOLVERSION_H
#define SQUID_ANYP_PROTOCOLVERSION_H

#include "anyp/ProtocolType.h"

#include <ostream>

namespace AnyP
{

/**
 * Stores a protocol version label.
 * For example HTTP/1.1 or ICY/1.0 or FTP/2.0
 */
class ProtocolVersion
{

public:
    // BUG: major() and minor() are macros.
    //      we can't use a fast constructor syntax without renaming them globally
    ProtocolVersion() : protocol(PROTO_NONE) {
        major = 0;
        minor = 0;
    }

    ProtocolVersion(ProtocolType which, unsigned int aMajor, unsigned int aMinor) : protocol(which) {
        major = aMajor;
        minor = aMinor;
    }

    ProtocolType protocol; ///< which protocol this version is for
    unsigned int major;    ///< major version number
    unsigned int minor;    ///< minor version number

    /// whether the version is "known" (e.g., has been parsed or explicitly set)
    explicit operator bool() const { return protocol != PROTO_NONE; }

    bool operator==(const ProtocolVersion& that) const {
        if (this->protocol != that.protocol)
            return false;

        if (this->major != that.major)
            return false;

        if (this->minor != that.minor)
            return false;

        return true;
    }

    bool operator!=(const ProtocolVersion& that) const {
        return (((this->protocol != that.protocol) || this->major != that.major) || (this->minor != that.minor));
    }

    bool operator <(const ProtocolVersion& that) const {
        if (this->protocol != that.protocol)
            return false; // throw?

        return (this->major < that.major ||
                (this->major == that.major && this->minor < that.minor));
    }

    bool operator >(const ProtocolVersion& that) const {
        if (this->protocol != that.protocol)
            return false; // throw?

        return (this->major > that.major ||
                (this->major == that.major && this->minor > that.minor));
    }

    bool operator <=(const ProtocolVersion& that) const {
        if (this->protocol != that.protocol)
            return false; // throw?

        return !(*this > that);
    }

    bool operator >=(const ProtocolVersion& that) const {
        if (this->protocol != that.protocol)
            return false; // throw?

        return !(*this < that);
    }
};

inline std::ostream &
operator << (std::ostream &os, const AnyP::ProtocolVersion &v)
{
    return (os << AnyP::ProtocolType_str[v.protocol] << '/' << v.major << '.' << v.minor);
}

} // namespace AnyP

#endif /* SQUID_ANYP_PROTOCOLVERSION_H */


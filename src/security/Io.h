/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_IO_H
#define SQUID_SRC_SECURITY_IO_H

#include "comm/forward.h"
#include "security/ErrorDetail.h"
#include "security/forward.h"

namespace Security {

/// a summary a TLS I/O operation outcome
class IoResult: public RefCountable {
public:
    typedef RefCount<IoResult> Pointer;

    /// all possible outcome cases
    typedef enum { ioSuccess, ioWantRead, ioWantWrite, ioError } Category;

    explicit IoResult(const Category aCategory): category(aCategory) {}
    explicit IoResult(const ErrorDetailPointer &anErrorDetail): errorDetail(anErrorDetail) {}
    IoResult(const IoResult &aRes) = default;

    /// convenience wrapper to detect successful I/O outcome; implies !wantsIo()
    bool successful() const { return category == ioSuccess; }

    /// convenience wrapper to detect whether more I/O is needed
    bool wantsIo() const { return category == ioWantRead || category == ioWantWrite; }

    void print(std::ostream &os) const;

    ErrorDetailPointer errorDetail; ///< ioError case details (or nil)

    Category category = ioError; ///< primary outcome classification

    /* the data members below facilitate human-friendly debugging */
    const char *errorDescription = nullptr; ///< a brief description of an error
    bool important = false; ///< whether the error was serious/unusual
};

inline std::ostream &
operator <<(std::ostream &os, const IoResult &result)
{
    result.print(os);
    return os;
}

/// accept a TLS connection over the specified to-Squid transport connection
IoResult Accept(Comm::Connection &transport);

/// establish a TLS connection over the specified from-Squid transport connection
IoResult Connect(Comm::Connection &transport);

/// clear any errors that a TLS library has accumulated in its global storage
void ForgetErrors();

} // namespace Security

#endif /* SQUID_SRC_SECURITY_IO_H */


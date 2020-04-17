/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_IO_H
#define SQUID_SRC_SECURITY_IO_H

#include "security/forward.h"
#include "ssl/ErrorDetail.h" // XXX: this should be Security::ErrorDetail

namespace Security {

/// a summary a TLS I/O operation outcome
class IoResult {
public:
    /// all possible outcome cases
    typedef enum { ioSuccess, ioWantRead, ioWantWrite, ioError } Category;

    explicit IoResult(const Category aCategory): category(aCategory) {}
    explicit IoResult(const Ssl::ErrorDetail::Pointer &anErrorDetail): errorDetail(anErrorDetail) {}

    Ssl::ErrorDetail::Pointer errorDetail; ///< ioError case details (or nil)

    Category category = ioError; ///< primary outcome classification

    /* the data members below facilitate human-friendly debugging */
    const char *errorDescription = nullptr; ///< a brief description of an error
    bool important = false; ///< whether the error was serious/unusual
};

/// analyses the given TLS I/O call outcome and TLS connection state
/// handles alert logging and reaching supposedly unreachable I/O code
IoResult InterpretIo(Security::SessionPointer::element_type *connection, int rawResult, int xerrno);

} // namespace Security

#endif /* SQUID_SRC_SECURITY_IO_H */

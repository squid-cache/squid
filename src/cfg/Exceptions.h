/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_CFG_EXCEPTIONS_H
#define SQUID__SRC_CFG_EXCEPTIONS_H

#include "sbuf/SBuf.h"

#include <stdexcept>

namespace Cfg
{

/**
 * Helper class to distinguish serious parsing errors which need
 * Administrative attention before Squid can operate.
 */
class FatalError : public std::exception
{
public:
    /// NP: use ToSBuf(...) if the error message is complex
    explicit FatalError(const SBuf &m) :
        message(m)
    {}
    explicit FatalError(const char *m) :
        message(m)
    {}

    /* std::exception API */
    const char *what() const throw() override;

public:
    /// the error message text to display
    SBuf message;
};

} // namespace Cfg

#endif /* SQUID__SRC_CFG_EXCEPTIONS_H */

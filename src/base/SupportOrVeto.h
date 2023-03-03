/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_SUPPORTORVETO_H
#define SQUID_SRC_BASE_SUPPORTORVETO_H

#include <optional>

/// a boolean flag that is false by default and becomes permanently false if vetoed
class SupportOrVeto
{
public:
    /// either the current explicit decision or, by default, false
    bool decision() const { return decision_.value_or(false); }

    /// \copydoc decision()
    operator bool() const { return decision(); }

    /// Makes (or keeps) decision() true in the absence of veto() calls.
    /// No effect if veto() has been called.
    void support() { if (!decision_) decision_ = true; }

    /// makes decision() false regardless of past or future support() calls
    void veto() { decision_ = false; }

private:
    /// current decision (if any)
    std::optional<bool> decision_;
};

#endif /* SQUID_SRC_BASE_SUPPORTORVETO_H */


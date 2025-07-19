/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DELAYID_H
#define SQUID_SRC_DELAYID_H

#if USE_DELAY_POOLS

#include "base/forward.h"
#include "DelayIdComposite.h"

class ClientHttpRequest;
class HttpReply;

/// \ingroup DelayPoolsAPI
class DelayId
{

public:
    static DelayId DelayClient(ClientHttpRequest *, HttpReply *reply = nullptr);
    DelayId ();
    DelayId (unsigned short);
    ~DelayId ();
    unsigned short pool() const;
    DelayIdComposite::Pointer compositePosition();
    DelayIdComposite::Pointer const compositePosition() const;
    void compositePosition(const DelayIdComposite::Pointer &);
    bool operator == (DelayId const &rhs) const;

    /// Whether we may delay reading. This operator is meant to be used as an
    /// optimization that helps avoid more expensive bytesWanted() computations.
    /// \retval false if bytesWanted() called with a positive maximum limit
    /// parameter will never return zero
    operator bool() const;

    int bytesWanted(int min, int max) const;
    void bytesIn (int qty);
    void setNoDelay(bool const);
    void delayRead(const AsyncCallPointer &);

private:
    unsigned short pool_;
    DelayIdComposite::Pointer compositeId;
    bool markedAsNoDelay;
};

#endif /* USE_DELAY_POOLS */
#endif /* SQUID_SRC_DELAYID_H */


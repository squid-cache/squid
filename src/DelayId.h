/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DELAYID_H
#define SQUID_DELAYID_H

#if USE_DELAY_POOLS

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
    void compositePosition(DelayIdComposite::Pointer );
    bool operator == (DelayId const &rhs) const;
    operator bool() const;
    int bytesWanted(int min, int max) const;
    void bytesIn (int qty);
    void setNoDelay(bool const);
    void delayRead(DeferredRead const &);

private:
    unsigned short pool_;
    DelayIdComposite::Pointer compositeId;
    bool markedAsNoDelay;
};

#endif /* USE_DELAY_POOLS */
#endif /* SQUID_DELAYID_H */


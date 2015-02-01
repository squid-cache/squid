/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLDESTINATIONIP_H
#define SQUID_ACLDESTINATIONIP_H
#include "acl/Checklist.h"
#include "acl/Ip.h"
#include "ipcache.h"

class DestinationIPLookup : public ACLChecklist::AsyncState
{

public:
    static DestinationIPLookup *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

private:
    static DestinationIPLookup instance_;
    static IPH LookupDone;
};

class ACLDestinationIP : public ACLIP
{

public:
    MEMPROXY_CLASS(ACLDestinationIP);

    ACLDestinationIP(): ACLIP(ACLDestinationIP::SupportedFlags) {}
    virtual char const *typeString() const;
    virtual int match(ACLChecklist *checklist);

    virtual ACL *clone()const;

    static ACLFlag SupportedFlags[];
private:
    static Prototype RegistryProtoype;
    static ACLDestinationIP RegistryEntry_;
};

MEMPROXY_CLASS_INLINE(ACLDestinationIP);

#endif /* SQUID_ACLDESTINATIONIP_H */


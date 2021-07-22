/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Client-side Routines */

#ifndef SQUID__SRC_SERVERS_PP2SERVER_H
#define SQUID__SRC_SERVERS_PP2SERVER_H

#include "acl/ChecklistFiller.h"
#include "servers/Server.h"

/**
 * Manage PROXYv2 client connections
 */
class Pp2Server : public ::Server, public Acl::ChecklistFiller
{
public:
    Pp2Server(const MasterXactionPointer &xact): ::Server(xact) {}
    virtual ~Pp2Server() {}

    /* AsyncJob API */
    virtual void start();
#if 0
    virtual bool doneAll() const;
    virtual void swanSong();
#endif

    /* ChecklistFiller API */
    virtual void fillChecklist(ACLFilledChecklist &) const;

    /* ::Server API */
    virtual bool shouldCloseOnEof() const { return true; }
    virtual bool handleReadData();
    virtual void afterClientRead() { assert(doneAll()); }
    virtual void receivedFirstByte() {}
protected:
    virtual void terminateAll(const Error &, const LogTagsErrors &);

private:
    bool proxyProtocolError(const char *);
    bool proxyProtocolValidateClient();
    bool parseProxyProtocolHeader();
};

#endif /* SQUID__SRC_SERVERS_PP2SERVER_H */


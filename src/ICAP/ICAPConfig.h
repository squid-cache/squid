
/*
 * $Id: ICAPConfig.h,v 1.16 2007/06/28 15:28:59 rousskov Exp $
 *
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_ICAPCONFIG_H
#define SQUID_ICAPCONFIG_H

#include "event.h"
#include "ICAPServiceRep.h"

class acl_access;

class ConfigParser;

class ICAPClass
{

public:
    String key;
    acl_access *accessList;

    Vector<ICAPServiceRep::Pointer> services;

    ICAPClass() : key(NULL), accessList(NULL) {};

    int prepare();
};

class ICAPAccessCheck
{

public:
    typedef void ICAPAccessCheckCallback(ICAPServiceRep::Pointer match, void *data);
    ICAPAccessCheck(ICAP::Method, ICAP::VectPoint, HttpRequest *, HttpReply *, ICAPAccessCheckCallback *, void *);
    ~ICAPAccessCheck();

private:
    ICAP::Method method;
    ICAP::VectPoint point;
    HttpRequest *req;
    HttpReply *rep;
    ICAPAccessCheckCallback *callback;
    void *callback_data;
    ACLChecklist *acl_checklist;
    Vector<String> candidateClasses;
    String matchedClass;
    void do_callback();
    ICAPServiceRep::Pointer findBestService(ICAPClass *c, bool preferUp);

public:
    void check();
    void checkCandidates();
    static void ICAPAccessCheckCallbackWrapper(int, void*);
    static EVH ICAPAccessCheckCallbackEvent;

private:
    CBDATA_CLASS2(ICAPAccessCheck);
};

class ICAPConfig
{

public:

    int onoff;
    int preview_enable;
    int preview_size;
    time_t connect_timeout_raw;
    time_t io_timeout_raw;
    int default_options_ttl;
    int send_client_ip;
    int send_client_username;
    int reuse_connections;
    int service_failure_limit;
    int service_revival_delay;
    char* client_username_header;
    int client_username_encode;

    Vector<ICAPServiceRep::Pointer> services;
    Vector<ICAPClass*> classes;

    ICAPConfig() {};

    ~ICAPConfig();

    time_t connect_timeout(bool bypassable) const;
    time_t io_timeout(bool bypassable) const;

    void parseICAPService(void);
    void freeICAPService(void);
    void dumpICAPService(StoreEntry *, const char *) const;
    ICAPServiceRep::Pointer findService(const String&);
    ICAPClass * findClass(const String& key);

    void parseICAPClass(void);
    void freeICAPClass(void);
    void dumpICAPClass(StoreEntry *, const char *) const;

    void parseICAPAccess(ConfigParser &parser);
    void freeICAPAccess(void);
    void dumpICAPAccess(StoreEntry *, const char *) const;

private:
    ICAPConfig(const ICAPConfig &); // unsupported
    ICAPConfig &operator =(const ICAPConfig &); // unsupported
};

extern ICAPConfig TheICAPConfig;

#endif /* SQUID_ICAPCONFIG_H */

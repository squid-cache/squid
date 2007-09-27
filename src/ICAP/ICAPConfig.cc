
/*
 * $Id: ICAPConfig.cc,v 1.20 2007/09/27 15:31:15 rousskov Exp $
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

#include "squid.h"

#include "ConfigParser.h"
#include "ACL.h"
#include "Store.h"
#include "Array.h"	// really Vector
#include "ICAPConfig.h"
#include "ICAPServiceRep.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "ACLChecklist.h"
#include "wordlist.h"

ICAPConfig TheICAPConfig;

ICAPServiceRep::Pointer
ICAPConfig::findService(const String& key)
{
    Vector<ICAPServiceRep::Pointer>::iterator iter = services.begin();

    while (iter != services.end()) {
        if ((*iter)->key == key)
            return *iter;

        ++iter;
    }

    return NULL;
}

ICAPClass *
ICAPConfig::findClass(const String& key)
{
    if (!key.size())
        return NULL;

    Vector<ICAPClass*>::iterator iter = classes.begin();

    while (iter != classes.end()) {
        if ((*iter)->key == key)
            return *iter;

        ++iter;
    }

    return NULL;
}

int
ICAPClass::prepare()
{
    int found = 0;
    wordlist *service_names = NULL;
    wordlist *iter;

    ConfigParser::ParseString(&key);
    ConfigParser::ParseWordList(&service_names);

    if (service_names && service_names->next) {
        debugs(3,0, "WARNING: Multiple ICAP services per icap_class are " <<
            "not yet supported. See Squid bug #2087.");
    }

    for (iter = service_names; iter; iter = iter->next) {
        ICAPServiceRep::Pointer match = TheICAPConfig.findService(iter->key);

        if (match != NULL) {
            found = 1;
            services += match;
        }
    }

    return found;
};

// ================================================================================ //

CBDATA_CLASS_INIT(ICAPAccessCheck);

ICAPAccessCheck::ICAPAccessCheck(ICAP::Method aMethod,
                                 ICAP::VectPoint aPoint,
                                 HttpRequest *aReq,
                                 HttpReply *aRep,
                                 ICAPAccessCheckCallback *aCallback,
                                 void *aCallbackData)
{
    method = aMethod;
    point = aPoint;

    req = HTTPMSGLOCK(aReq);
    rep = aRep ? HTTPMSGLOCK(aRep) : NULL;

    callback = aCallback;

    callback_data = cbdataReference(aCallbackData);

    candidateClasses.clean();

    matchedClass.clean();

    acl_checklist = NULL;

    debugs(93, 5, "ICAPAccessCheck constructed for " << ICAP::methodStr(method) << " " << ICAP::vectPointStr(point));
}

ICAPAccessCheck::~ICAPAccessCheck()
{
    HTTPMSGUNLOCK(req);
    HTTPMSGUNLOCK(rep);
}

/*
 * Walk the ICAPAccess list and find all classes that have at least
 * one service with matching method and vectoring point.
 */
void
ICAPAccessCheck::check()
{
    debugs(93, 3, "ICAPAccessCheck::check");
    Vector<ICAPClass*>::iterator ci;

    for (ci = TheICAPConfig.classes.begin(); ci != TheICAPConfig.classes.end(); ++ci) {

        /*
         * We only find the first matching service because we only need
         * one matching service to justify ACL-checking a class.  We might
         * use other services belonging to the class if the first service
         * turns out to be unusable for some reason.
         */
        ICAPClass *c = *ci;
        ICAPServiceRep::Pointer service = findBestService(c, false);
        if (service != NULL) {
            debugs(93, 3, "ICAPAccessCheck::check: class '" << c->key.buf() << "' has candidate service '" << service->key.buf() << "'");
            candidateClasses += c->key;
        }
    }

    checkCandidates();
}

void
ICAPAccessCheck::checkCandidates()
{
    while (!candidateClasses.empty()) {
        // It didn't really match yet, but we use the name anyway.
        matchedClass = candidateClasses.shift();
        ICAPClass *theClass = TheICAPConfig.findClass(matchedClass);

        if (theClass == NULL)
            // class apparently went away (reconfigure)
            continue;

        // XXX we don't have access to conn->rfc931 here.
        acl_checklist = aclChecklistCreate(theClass->accessList, req, dash_str);

        acl_checklist->nonBlockingCheck(ICAPAccessCheckCallbackWrapper, this);

        return;
    }

    /*
     * when there are no canidates, set matchedClass to NULL string
     * and call the wrapper with answer = 1
     */
    debugs(93, 3, "ICAPAccessCheck::check: NO candidates or matches found");

    matchedClass.clean();

    ICAPAccessCheckCallbackWrapper(1, this);

    return;
}

void
ICAPAccessCheck::ICAPAccessCheckCallbackWrapper(int answer, void *data)
{
    debugs(93, 5, "ICAPAccessCheckCallbackWrapper: answer=" << answer);
    ICAPAccessCheck *ac = (ICAPAccessCheck*)data;

    if (ac->matchedClass.size()) {
        debugs(93, 5, "ICAPAccessCheckCallbackWrapper matchedClass = " << ac->matchedClass.buf());
    }

    if (!answer) {
        ac->checkCandidates();
        return;
    }

    /*
     * We use an event here to break deep function call sequences
     */
    eventAdd("ICAPAccessCheckCallbackEvent",
             ICAPAccessCheckCallbackEvent,
             ac,
             0.0,
             0,
             true);
}

void
ICAPAccessCheck::ICAPAccessCheckCallbackEvent(void *data)
{
    debugs(93, 5, "ICAPAccessCheckCallbackEvent");
    ICAPAccessCheck *ac = (ICAPAccessCheck*)data;
    ac->do_callback();
    delete ac;
}

void
ICAPAccessCheck::do_callback()
{
    debugs(93, 3, "ICAPAccessCheck::do_callback");

    if (matchedClass.size()) {
        debugs(93, 3, "ICAPAccessCheck::do_callback matchedClass = " << matchedClass.buf());
    }

    void *validated_cbdata;
    if (!cbdataReferenceValidDone(callback_data, &validated_cbdata)) {
        debugs(93,3,HERE << "do_callback: callback_data became invalid, skipping");
        return;
    }

    ICAPServiceRep::Pointer service = NULL;
    if (ICAPClass *c = TheICAPConfig.findClass(matchedClass)) {
        service = findBestService(c, true);
        if (service != NULL)
            debugs(93,3,HERE << "do_callback: with service " << service->uri);
        else
            debugs(93,3,HERE << "do_callback: no " << matchedClass << " service");
    } else {
        debugs(93,3,HERE << "do_callback: no " << matchedClass << " class");
    }

    callback(service, validated_cbdata);
}

ICAPServiceRep::Pointer
ICAPAccessCheck::findBestService(ICAPClass *c, bool preferUp) {

    const char *what = preferUp ? "up " : "";
    debugs(93,7,HERE << "looking for the first matching " << 
        what << "service in class " << c->key);

    ICAPServiceRep::Pointer secondBest;

    Vector<ICAPServiceRep::Pointer>::iterator si;
    for (si = c->services.begin(); si != c->services.end(); ++si) {
        ICAPServiceRep::Pointer service = *si;

        if (method != service->method)
            continue;

        if (point != service->point)
            continue;

        // sending a message to a broken service is likely to cause errors
        if (service->bypass && service->broken())
            continue;

        if (service->up()) {
            // sending a message to a service that does not want it is useless
            // note that we cannot check wantsUrl for service that is not "up"
            // note that even essential services are skipped on unwanted URLs!
            if (!service->wantsUrl(req->urlpath))
                continue;
        } else {
            if (!secondBest)
                secondBest = service;
            if (preferUp) {
                // the caller asked for an "up" service and we can bypass this one
                if (service->bypass)
                    continue;
                debugs(93,5,HERE << "cannot skip an essential down service");
                what = "down-but-essential ";
            }
        }

        debugs(93,5,HERE << "found first matching " <<
            what << "service in class " << c->key <<
            ": " << service->key);

        return service;
    }

    if (secondBest != NULL) {
        what = "down ";
        debugs(93,5,HERE << "found first matching " <<
            what << "service in class " << c->key <<
            ": " << secondBest->key);
        return secondBest;
    }

    debugs(93,5,HERE << "found no matching " << 
        what << "services in class " << c->key);
    return ICAPServiceRep::Pointer();
}

// ================================================================================ //

void
ICAPConfig::parseICAPService()
{
    ICAPServiceRep::Pointer S = new ICAPServiceRep();

    if (S->configure(S))
        services += S;
    else
        S->invalidate();
};

void
ICAPConfig::freeICAPService()
{
    services.clean();
};

void
ICAPConfig::dumpICAPService(StoreEntry *entry, const char *name) const
{
    typedef Vector<ICAPServiceRep::Pointer>::const_iterator VI;

    for (VI i = services.begin(); i != services.end(); ++i) {
        const ICAPServiceRep::Pointer &r = *i;
        storeAppendPrintf(entry, "%s %s_%s %s %d %s\n", name, r->key.buf(),
                          r->methodStr(), r->vectPointStr(), r->bypass, r->uri.buf());
    }
};

void
ICAPConfig::parseICAPClass()
{
    ICAPClass *C = new ICAPClass();

    if (C->prepare()) {
        classes.push_back(C);
    } else {
        delete C;
    }
};

void
ICAPConfig::freeICAPClass()
{
    classes.clean();
};

void
ICAPConfig::dumpICAPClass(StoreEntry *entry, const char *name) const
{
    Vector<ICAPClass*>::const_iterator i = classes.begin();

    while (i != classes.end()) {
        storeAppendPrintf(entry, "%s %s\n", name, (*i)->key.buf());
        ++i;
    }
};

void
ICAPConfig::parseICAPAccess(ConfigParser &parser)
{
    String aKey;
    ConfigParser::ParseString(&aKey);
    ICAPClass *theClass = TheICAPConfig.findClass(aKey);

    if (theClass == NULL)
        fatalf("Did not find ICAP class '%s' referenced on line %d\n",
               aKey.buf(), config_lineno);

    aclParseAccessLine(parser, &theClass->accessList);
};

void
ICAPConfig::freeICAPAccess()
{
    (void) 0;
};

void
ICAPConfig::dumpICAPAccess(StoreEntry *entry, const char *name) const
{
    LOCAL_ARRAY(char, nom, 64);

    Vector<ICAPClass*>::const_iterator i = classes.begin();

    while (i != classes.end()) {
        snprintf(nom, 64, "%s %s", name, (*i)->key.buf());
        dump_acl_access(entry, nom, (*i)->accessList);
        ++i;
    }
};

ICAPConfig::~ICAPConfig()
{

    // invalidate each service so that it can be deleted when refcount=0
    Vector<ICAPServiceRep::Pointer>::iterator si;

    for (si = services.begin(); si != services.end(); ++si)
        (*si)->invalidate();

    classes.clean();

};

time_t ICAPConfig::connect_timeout(bool bypassable) const
{
    if (connect_timeout_raw > 0)
        return connect_timeout_raw; // explicitly configured

    return bypassable ? Config.Timeout.peer_connect : Config.Timeout.connect;
}

time_t ICAPConfig::io_timeout(bool) const
{
    if (io_timeout_raw > 0)
        return io_timeout_raw; // explicitly configured
    // TODO: provide a different default for an ICAP transaction that 
    // can still be bypassed
    return Config.Timeout.read; 
}

ICAPConfig::ICAPConfig(const ICAPConfig &)
{
    assert(false); // unsupported
}

ICAPConfig &ICAPConfig::operator =(const ICAPConfig &)
{
    assert(false); // unsupported
    return *this;
}

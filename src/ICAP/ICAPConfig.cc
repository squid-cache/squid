
/*
 * $Id: ICAPConfig.cc,v 1.6 2006/02/17 18:11:00 wessels Exp $
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

ICAPConfig TheICAPConfig;

ICAPServiceRep::Pointer
ICAPConfig::findService(const String& key)
{
    Vector<ICAPServiceRep::Pointer>::iterator iter = services.begin();

    while (iter != services.end()) {
        if (iter->getRaw()->key == key)
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

    callback_data = aCallbackData;

    candidateClasses.clean();

    matchedClass.clean();

    acl_checklist = NULL;

    debug(93,5)("ICAPAccessCheck constructed for %s %s\n",
                ICAP::methodStr(method),
                ICAP::vectPointStr(point));
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
    debug(93,3)("ICAPAccessCheck::check\n");
    Vector<ICAPClass*>::iterator ci;

    for (ci = TheICAPConfig.classes.begin(); ci != TheICAPConfig.classes.end(); ++ci) {

        ICAPClass *theClass = *ci;

        Vector<ICAPServiceRep::Pointer>::iterator si;

        for (si = theClass->services.begin(); si != theClass->services.end(); ++si) {
            ICAPServiceRep *theService = si->getRaw();

            if (method != theService->method)
                continue;

            if (point != theService->point)
                continue;

            debug(93,3)("ICAPAccessCheck::check: class '%s' has candidate service '%s'\n", theClass->key.buf(), theService->key.buf());

            candidateClasses += theClass->key;

            /*
             * Break here because we only need one matching service
             * to justify ACL-checking a class.  We might use other
             * services belonging to the class if the first service
             * is unavailable, etc.
             */
            break;

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
    debug(93,3)("ICAPAccessCheck::check: NO candidates or matches found\n");

    matchedClass.clean();

    ICAPAccessCheckCallbackWrapper(1, this);

    return;
}

void
ICAPAccessCheck::ICAPAccessCheckCallbackWrapper(int answer, void *data)
{
    debug(93,5)("ICAPAccessCheckCallbackWrapper: answer=%d\n", answer);
    ICAPAccessCheck *ac = (ICAPAccessCheck*)data;

    if (ac->matchedClass.size()) {
        debug(93,5)("ICAPAccessCheckCallbackWrapper matchedClass = %s\n",
                    ac->matchedClass.buf());
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
    debug(93,5)("ICAPAccessCheckCallbackEvent\n");
    ICAPAccessCheck *ac = (ICAPAccessCheck*)data;
    ac->do_callback();
    delete ac;
}

void
ICAPAccessCheck::do_callback()
{
    debug(93,3)("ICAPAccessCheck::do_callback\n");

    if (matchedClass.size()) {
        debug(93,3)("ICAPAccessCheck::do_callback matchedClass = %s\n", matchedClass.buf());
    }

    ICAPClass *theClass = TheICAPConfig.findClass(matchedClass);

    if (theClass == NULL) {
        callback(NULL, callback_data);
        return;
    }

    matchedClass.clean();

    Vector<ICAPServiceRep::Pointer>::iterator i;

    for (i = theClass->services.begin(); i != theClass->services.end(); ++i) {
        ICAPServiceRep *theService = i->getRaw();

        if (method != theService->method)
            continue;

        if (point != theService->point)
            continue;

        callback(*i, callback_data);

        return;
    }

    callback(NULL, callback_data);
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
ICAPConfig::dumpICAPService(StoreEntry *entry, const char *name)
{
    typedef Vector<ICAPServiceRep::Pointer>::iterator VI;

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
ICAPConfig::dumpICAPClass(StoreEntry *entry, const char *name)
{
    Vector<ICAPClass*>::iterator i = classes.begin();

    while (i != classes.end()) {
        storeAppendPrintf(entry, "%s %s\n", name, (*i)->key.buf());
        ++i;
    }
};

void
ICAPConfig::parseICAPAccess()
{
    String aKey;
    ConfigParser::ParseString(&aKey);
    ICAPClass *theClass = TheICAPConfig.findClass(aKey);

    if (theClass == NULL)
        fatalf("Did not find ICAP class '%s' referenced on line %d\n",
               aKey.buf(), config_lineno);

    aclParseAccessLine(&theClass->accessList);
};

void
ICAPConfig::freeICAPAccess()
{
    (void) 0;
};

void
ICAPConfig::dumpICAPAccess(StoreEntry *entry, const char *name)
{
    LOCAL_ARRAY(char, nom, 64);

    Vector<ICAPClass*>::iterator i = classes.begin();

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

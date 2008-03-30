
/*
 * $Id: ICAPConfig.cc,v 1.21 2008/02/12 23:12:45 rousskov Exp $
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
 */

#include "squid.h"
#include "structs.h"

#include "ConfigParser.h"
#include "ACL.h"
#include "Store.h"
#include "Array.h"	// really Vector
#include "HttpRequest.h"
#include "HttpReply.h"
#include "ACLChecklist.h"
#include "wordlist.h"
#include "adaptation/Config.h"
#include "adaptation/Service.h"


Adaptation::Config::Classes &
Adaptation::Config::AllClasses()
{
    static Classes TheClasses;
    return TheClasses;
}

Adaptation::Class *
Adaptation::Config::FindClass(const String& key)
{
	if (!key.size())
		return NULL;

    typedef Classes::iterator SI;
    for (SI i = AllClasses().begin(); i != AllClasses().end(); ++i) {
        if ((*i)->key == key)
            return *i;
    }

    return NULL;
}

Adaptation::Config::Services &
Adaptation::Config::AllServices()
{
    static Services TheServices;
    return TheServices;
}

Adaptation::ServicePointer
Adaptation::Config::FindService(const String& key)
{
debugs(1,1, HERE << "looking for " << key << " among " << AllServices().size() << " services");
    typedef Services::iterator SI;
    for (SI i = AllServices().begin(); i != AllServices().end(); ++i) {
debugs(1,1, HERE << "\tcompare: " << key << " ? " << (*i)->cfg().key);
        if ((*i)->cfg().key == key)
            return *i;
    }
debugs(1,1, HERE << "not found " << key << " among " << AllServices().size() << " services");

    return NULL;
}

void
Adaptation::Config::AddService(ServicePointer s)
{
    AllServices().push_back(s);
}

void
Adaptation::Config::AddClass(Class *c)
{
    AllClasses().push_back(c);
}


Adaptation::Class::Class(): key(NULL), accessList(NULL), service_names(NULL)
{
    wordlistDestroy(&service_names);
}

Adaptation::Class::~Class()
{
    wordlistDestroy(&service_names);
}

int
Adaptation::Class::prepare()
{
    ConfigParser::ParseString(&key);
    ConfigParser::ParseWordList(&service_names);

    if (service_names && service_names->next) {
        debugs(3,0, "WARNING: Multiple  services per icap_class are " <<
            "not yet supported. See Squid bug #2087.");
        // TODO: fail on failures
    }

    return 1;
}

void
Adaptation::Class::finalize()
{
   for (wordlist *iter = service_names; iter; iter = iter->next) {
       ServicePointer match = Config::FindService(iter->key);
       if (match != NULL)
           services += match;
   }
}

// ================================================================================ //

cbdata_type Adaptation::AccessCheck::CBDATA_AccessCheck = CBDATA_UNKNOWN;

Adaptation::AccessCheck::AccessCheck(Method aMethod,
                                 VectPoint aPoint,
                                 HttpRequest *aReq,
                                 HttpReply *aRep,
                                 AccessCheckCallback *aCallback,
                                 void *aCallbackData): AsyncJob("AccessCheck"), done(FALSE)
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

    debugs(93, 5, "AccessCheck constructed for " << methodStr(method) << " " << vectPointStr(point));
}

Adaptation::AccessCheck::~AccessCheck()
{
    HTTPMSGUNLOCK(req);
    HTTPMSGUNLOCK(rep);
}

/*
 * Walk the Access list and find all classes that have at least
 * one service with matching method and vectoring point.
 */
void
Adaptation::AccessCheck::check()
{
    debugs(93, 3, "Adaptation::AccessCheck::check");

    typedef Config::Classes::iterator CI;
    for (CI ci = Config::AllClasses().begin(); ci != Config::AllClasses().end(); ++ci) {

        /*
         * We only find the first matching service because we only need
         * one matching service to justify ACL-checking a class.  We might
         * use other services belonging to the class if the first service
         * turns out to be unusable for some reason.
         */
        Class *c = *ci;
        ServicePointer service = findBestService(c, false);
        if (service != NULL) {
            debugs(93, 3, "Adaptation::AccessCheck::check: class '" << c->key.buf() << "' has candidate service '" << service->cfg().key.buf() << "'");
            candidateClasses += c->key;
        }
    }

    checkCandidates();
}

void
Adaptation::AccessCheck::checkCandidates()
{
    while (!candidateClasses.empty()) {
        // It didn't really match yet, but we use the name anyway.
        matchedClass = candidateClasses.shift();
        Class *c = Config::FindClass(matchedClass);

        if (!c) // class apparently went away (reconfigure)
            continue;

        // XXX we don't have access to conn->rfc931 here.
        acl_checklist = aclChecklistCreate(c->accessList, req, dash_str);

        acl_checklist->nonBlockingCheck(AccessCheckCallbackWrapper, this);

        return;
    }

    /*
     * when there are no canidates, set matchedClass to NULL string
     * and call the wrapper with answer = 1
     */
    debugs(93, 3, "Adaptation::AccessCheck::check: NO candidates or matches found");

    matchedClass.clean();

    AccessCheckCallbackWrapper(1, this);

    return;
}

void
Adaptation::AccessCheck::AccessCheckCallbackWrapper(int answer, void *data)
{
    debugs(93, 5, "AccessCheckCallbackWrapper: answer=" << answer);
    AccessCheck *ac = (AccessCheck*)data;

    if (ac->matchedClass.size()) {
        debugs(93, 5, "AccessCheckCallbackWrapper matchedClass = " << ac->matchedClass.buf());
    }

    if (!answer) {
        ac->checkCandidates();
        return;
    }

    /*
     * We use an event here to break deep function call sequences
     */
    CallJobHere(93, 5, ac, Adaptation::AccessCheck::do_callback);
}

#if 0
void
Adaptation::AccessCheck::AccessCheckCallbackEvent(void *data)
{
    debugs(93, 5, "AccessCheckCallbackEvent");
    AccessCheck *ac = (AccessCheck*)data;
    ac->do_callback();
    delete ac;
}
#endif

void
Adaptation::AccessCheck::do_callback()
{
    debugs(93, 3, "Adaptation::AccessCheck::do_callback");

    if (matchedClass.size()) {
        debugs(93, 3, "Adaptation::AccessCheck::do_callback matchedClass = " << matchedClass.buf());
    }

    void *validated_cbdata;
    if (!cbdataReferenceValidDone(callback_data, &validated_cbdata)) {
        debugs(93,3,HERE << "do_callback: callback_data became invalid, skipping");
        return;
    }

    ServicePointer service = NULL;
    if (Class *c = Config::FindClass(matchedClass)) {
        service = findBestService(c, true);
        if (service != NULL)
            debugs(93,3,HERE << "do_callback: with service " << service->cfg().uri);
        else
            debugs(93,3,HERE << "do_callback: no " << matchedClass << " service");
    } else {
        debugs(93,3,HERE << "do_callback: no " << matchedClass << " class");
    }

    callback(service, validated_cbdata);
    done = TRUE;
}

Adaptation::ServicePointer
Adaptation::AccessCheck::findBestService(Class *c, bool preferUp) {

    const char *what = preferUp ? "up " : "";
    debugs(93,7,HERE << "looking for the first matching " << 
        what << "service among " << c->services.size() <<
        " services in class " << c->key);

    ServicePointer secondBest;

    Vector<ServicePointer>::iterator si;
    for (si = c->services.begin(); si != c->services.end(); ++si) {
        ServicePointer service = *si;

        if (method != service->cfg().method)
            continue;

        if (point != service->cfg().point)
            continue;

        // sending a message to a broken service is likely to cause errors
        if (service->cfg().bypass && service->broken())
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
                if (service->cfg().bypass)
                    continue;
                debugs(93,5,HERE << "cannot skip an essential down service");
                what = "down-but-essential ";
            }
        }

        debugs(93,5,HERE << "found first matching " <<
            what << "service in class " << c->key <<
            ": " << service->cfg().key);

        return service;
    }

    if (secondBest != NULL) {
        what = "down ";
        debugs(93,5,HERE << "found first matching " <<
            what << "service in class " << c->key <<
            ": " << secondBest->cfg().key);
        return secondBest;
    }

    debugs(93,5,HERE << "found no matching " << 
        what << "services in class " << c->key);
    return ServicePointer();
}

// ================================================================================ //

void
Adaptation::Config::parseService()
{
    ServiceConfig *cfg = new ServiceConfig;
    cfg->parse();
    serviceConfigs.push_back(cfg);
}

void
Adaptation::Config::freeService()
{
    // XXX: leaking Services and ServiceConfigs?
}

void
Adaptation::Config::dumpService(StoreEntry *entry, const char *name) const
{
    typedef Services::iterator SCI;
    for (SCI i = AllServices().begin(); i != AllServices().end(); ++i) {
        const ServiceConfig &cfg = (*i)->cfg();
        storeAppendPrintf(entry, "%s %s_%s %s %d %s\n", name, cfg.key.buf(),
            cfg.methodStr(), cfg.vectPointStr(), cfg.bypass, cfg.uri.buf());
    }
}

void
Adaptation::Config::finalize()
{
    // create service reps from service configs
    typedef Vector<ServiceConfig*>::const_iterator VISCI;
    const Vector<ServiceConfig*> &configs = serviceConfigs;
    debugs(93,3, "Found " << configs.size() << " service configs.");
    for (VISCI ci = configs.begin(); ci != configs.end(); ++ci) {
        ServicePointer s = createService(**ci);
        if (s != NULL)
            AddService(s);
    }

    debugs(93,1, "Initialized " << configs.size() <<
        " message adaptation services.");
}

void
Adaptation::Config::Finalize()
{
    // link classes with the service reps they use
    typedef Classes::iterator CI;
    for (CI ci = AllClasses().begin(); ci != AllClasses().end(); ++ci) {
        Class *c = *ci;
        c->finalize(); // TODO: fail on failures
    }

    debugs(93,2, "Initialized " << AllClasses().size() <<
        " message adaptation service classes.");
}

void
Adaptation::Config::parseClass()
{
    Class *C = new Class();

    if (C->prepare()) {
        AddClass(C);
    } else {
        delete C;
    }
};

void
Adaptation::Config::freeClass()
{
    // XXX: leaking Classes here?
}

void
Adaptation::Config::dumpClass(StoreEntry *entry, const char *name) const
{
    typedef Classes::iterator CI;
    for (CI i = AllClasses().begin(); i != AllClasses().end(); ++i)
        storeAppendPrintf(entry, "%s %s\n", name, (*i)->key.buf());
}

void
Adaptation::Config::parseAccess(ConfigParser &parser)
{
    String aKey;
    ConfigParser::ParseString(&aKey);
    Class *c = FindClass(aKey);

    if (!c)
        fatalf("Did not find  class '%s' referenced on line %d\n",
               aKey.buf(), config_lineno);

    aclParseAccessLine(parser, &c->accessList);
};

void
Adaptation::Config::freeAccess()
{
    (void) 0;
}

void
Adaptation::Config::dumpAccess(StoreEntry *entry, const char *name) const
{
    LOCAL_ARRAY(char, nom, 64);

    typedef Classes::iterator CI;
    for (CI i = AllClasses().begin(); i != AllClasses().end(); ++i) {
        snprintf(nom, 64, "%s %s", name, (*i)->key.buf());
        dump_acl_access(entry, nom, (*i)->accessList);
	}
}

Adaptation::Config::Config()
{
    // XXX: should we init members?
}

Adaptation::Config::~Config()
{

    // invalidate each service so that it can be deleted when refcount=0
    typedef Services::iterator SCI;
    for (SCI i = AllServices().begin(); i != AllServices().end(); ++i)
        (*i)->invalidate();

    AllServices().clean();

    while (!AllClasses().empty()) {
		delete AllClasses().back();
		AllClasses().pop_back();
	}
}

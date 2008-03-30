#ifndef SQUID_ADAPTATION__CONFIG_H
#define SQUID_ADAPTATION__CONFIG_H

#include "event.h"
#include "AsyncCall.h"
#include "adaptation/Elements.h"

class acl_access;
class ConfigParser;

template <class C>
class RefCount;

namespace Adaptation {

class Service;
class ServiceConfig;
class Class;

typedef RefCount<Service> ServicePointer;

class Class
{

public:
    String key;
    acl_access *accessList;

    Vector<ServicePointer> services;

    Class();
    ~Class();

    int prepare();
    void finalize();

private:
    wordlist *service_names;
};

class AccessCheck: public virtual AsyncJob
{

public:
    typedef void AccessCheckCallback(ServicePointer match, void *data);
    AccessCheck(Method, VectPoint, HttpRequest *, HttpReply *, AccessCheckCallback *, void *);
    ~AccessCheck();

private:
    Method method;
    VectPoint point;
    HttpRequest *req;
    HttpReply *rep;
    AccessCheckCallback *callback;
    void *callback_data;
    ACLChecklist *acl_checklist;
    Vector<String> candidateClasses;
    String matchedClass;
    void do_callback();
    ServicePointer findBestService(Class *c, bool preferUp);
    bool done;

public:
    void check();
    void checkCandidates();
    static void AccessCheckCallbackWrapper(int, void*);
#if 0
    static EVH AccessCheckCallbackEvent;
#endif
//AsyncJob virtual methods
    virtual bool doneAll() const { return AsyncJob::doneAll() && done;}

private:
    CBDATA_CLASS2(AccessCheck);
};

class Config
{
public:
	static ServicePointer FindService(const String &key);
	static Class *FindClass(const String &key);
    static void AddService(ServicePointer s);
	static void AddClass(Class *c);
	static void Finalize();

	friend class AccessCheck;

public:

    int onoff;
    int send_client_ip;
    int send_client_username;
    int service_failure_limit;
    int service_revival_delay;

    Vector<ServiceConfig*> serviceConfigs;

    Config();
    virtual ~Config();

    void parseService(void);
    void freeService(void);
    void dumpService(StoreEntry *, const char *) const;
    ServicePointer findService(const String&);
    Class * findClass(const String& key);

    void parseClass(void);
    void freeClass(void);
    void dumpClass(StoreEntry *, const char *) const;

    void parseAccess(ConfigParser &parser);
    void freeAccess(void);
    void dumpAccess(StoreEntry *, const char *) const;

    void finalize();

protected:
    // TODO: use std::hash_map<string, ...> instead
    typedef Vector<Adaptation::ServicePointer> Services;
    typedef Vector<Adaptation::Class*> Classes;
    static Services &AllServices();
    static Classes &AllClasses();

private:
    Config(const Config &); // unsupported
    Config &operator =(const Config &); // unsupported

    virtual ServicePointer createService(const ServiceConfig &cfg) = 0;
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__CONFIG_H */

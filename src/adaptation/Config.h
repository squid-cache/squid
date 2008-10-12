#ifndef SQUID_ADAPTATION__CONFIG_H
#define SQUID_ADAPTATION__CONFIG_H

#include "event.h"
#include "AsyncCall.h"
#include "adaptation/Elements.h"

class acl_access;
class ConfigParser;

template <class C>
class RefCount;

namespace Adaptation
{

class Service;
class ServiceConfig;
class Class;

typedef RefCount<Service> ServicePointer;

class ServiceGroup;
class AccessRule;

class Config
{
public:
    static void Finalize(bool enable);

    static void ParseServiceSet(void);
    static void FreeServiceSet(void);
    static void DumpServiceSet(StoreEntry *, const char *);

    static void ParseAccess(ConfigParser &parser);
    static void FreeAccess(void);
    static void DumpAccess(StoreEntry *, const char *);

    friend class AccessCheck;

public:
    static bool Enabled; // true if at least one adaptation mechanism is

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

    virtual void finalize();

private:
    Config(const Config &); // unsupported
    Config &operator =(const Config &); // unsupported

    virtual ServicePointer createService(const ServiceConfig &cfg) = 0;
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__CONFIG_H */

#ifndef SQUID_ADAPTATION__CONFIG_H
#define SQUID_ADAPTATION__CONFIG_H

#include "event.h"
#include "base/AsyncCall.h"
#include "adaptation/forward.h"
#include "adaptation/Elements.h"

class acl_access;
class ConfigParser;

namespace Adaptation
{

class Config
{
public:
    static void Finalize(bool enable);

    static void ParseServiceSet(void);
    static void ParseServiceChain(void);

    static void ParseAccess(ConfigParser &parser);
    static void FreeAccess(void);
    static void DumpAccess(StoreEntry *, const char *);

    friend class AccessCheck;

public:
    static bool Enabled; // true if at least one adaptation mechanism is

    // these are global squid.conf options, documented elsewhere
    static char *masterx_shared_name; // global TODO: do we need TheConfig?
    static int service_iteration_limit;
    static int send_client_ip;
    static int send_username;
    static int use_indirect_client;

    // Options below are accessed via Icap::TheConfig or Ecap::TheConfig
    // TODO: move ICAP-specific options to Icap::Config and add TheConfig
    int onoff;
    int service_failure_limit;
    time_t oldest_service_failure;
    int service_revival_delay;

    typedef Vector<ServiceConfigPointer> ServiceConfigs;
    ServiceConfigs serviceConfigs;

    Config();
    virtual ~Config();

    void parseService(void);
    void freeService(void);
    void dumpService(StoreEntry *, const char *) const;
    ServicePointer findService(const String&);

    virtual void finalize();

protected:
    /// creates service configuration object that will parse and keep cfg info
    virtual ServiceConfig *newServiceConfig() const;

private:
    Config(const Config &); // unsupported
    Config &operator =(const Config &); // unsupported

    virtual ServicePointer createService(const ServiceConfigPointer &cfg) = 0;

    static void ParseServiceGroup(ServiceGroupPointer group);
    static void FreeServiceGroups(void);
    static void DumpServiceGroups(StoreEntry *, const char *);
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__CONFIG_H */

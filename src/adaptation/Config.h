/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ADAPTATION__CONFIG_H
#define SQUID_ADAPTATION__CONFIG_H

#include "acl/forward.h"
#include "adaptation/Elements.h"
#include "adaptation/forward.h"
#include "base/AsyncCall.h"
#include "event.h"
#include "Notes.h"
#include "SquidString.h"

class ConfigParser;
class HttpRequest;
class HttpReply;

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

    static Notes metaHeaders; ///< The list of configured meta headers

    static bool needHistory; ///< HttpRequest adaptation history should recorded

    typedef std::vector<ServiceConfigPointer> ServiceConfigs;
    ServiceConfigs serviceConfigs;

    Config();
    virtual ~Config();

    void parseService(void);
    void freeService(void);
    void dumpService(StoreEntry *, const char *) const;
    ServiceConfigPointer findServiceConfig(const String&);

    /**
     * Creates and starts the adaptation services. In the case the adaptation
     * mechanism is disabled then removes any reference to the services from
     * access rules and service groups, and returns false.
     * \return true if the services are ready and running, false otherwise
     */
    virtual bool finalize();

protected:
    /// Removes any reference to the services  from configuration
    virtual void clear();

    /// creates service configuration object that will parse and keep cfg info
    virtual ServiceConfig *newServiceConfig() const;

    /// Removes the given service from all service groups.
    void removeService(const String& service);

    /// Removes access rules of the given service or group
    void removeRule(const String& id);

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


#ifndef SQUID_ADAPTATION__CONFIG_H
#define SQUID_ADAPTATION__CONFIG_H

#include "event.h"
#include "acl/Gadgets.h"
#include "base/AsyncCall.h"
#include "adaptation/forward.h"
#include "adaptation/Elements.h"
#include "SquidString.h"

class acl_access;
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
    static void ParseMetaHeader(ConfigParser &parser);
    static void FreeMetaHeader();
    static void DumpMetaHeader(StoreEntry *, const char *);

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

    /**
     * Used to store meta headers. The meta headers are custom
     * ICAP request headers or ECAP options used to pass custom
     * transaction-state related meta information to a service.
     */
    class MetaHeader: public RefCountable
    {
    public:
        typedef RefCount<MetaHeader> Pointer;
        /// Stores a value for the meta header.
        class Value: public RefCountable
        {
        public:
            typedef RefCount<Value> Pointer;
            String value; ///< a header value
            ACLList *aclList; ///< The access list used to determine if this value is valid for a request
            explicit Value(const String &aVal) : value(aVal), aclList(NULL) {}
            ~Value();
        };
        typedef Vector<Value::Pointer> Values;

        explicit MetaHeader(const String &aName): name(aName) {}

        /**
         * Adds a value to the meta header and returns a  pointer to the
         * related Value object.
         */
        Value::Pointer addValue(const String &value);

        /**
         * Walks through the  possible values list of the  meta and selects
         * the first value which matches the given HttpRequest and HttpReply
         * or NULL if none matches.
         */
        const char *match(HttpRequest *request, HttpReply *reply);
        String name; ///< The meta header name
        Values values; ///< The possible values list for the meta header
    };
    typedef Vector<MetaHeader::Pointer> MetaHeaders;
    static MetaHeaders metaHeaders; ///< The list of configured meta headers

    /**
     * Adds a header to the meta headers list and returns a pointer to the
     * related metaHeaders object. If the header name already exists in list,
     * returns a pointer to the existing object.
     */
    static MetaHeader::Pointer addMetaHeader(const String &header);

    typedef Vector<ServiceConfigPointer> ServiceConfigs;
    ServiceConfigs serviceConfigs;

    Config();
    virtual ~Config();

    void parseService(void);
    void freeService(void);
    void dumpService(StoreEntry *, const char *) const;
    ServicePointer findService(const String&);

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

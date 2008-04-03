#ifndef SQUID_ADAPTATION__SERVICE_GROUPS_H
#define SQUID_ADAPTATION__SERVICE_GROUPS_H

#include "adaptation/forward.h"

namespace Adaptation {

// Interface for grouping adaptation services together.
// Specific groups differ in how the first and the next services are selected
class ServiceGroup
{
public:
    typedef Vector<String> Store;
    typedef Store::iterator iterator;
    typedef String Id;

    // Information sufficient to iterate services stored in the group,
    // grouped together to simplify initial/sequentialServices interfaces.
    // The iterators point back to 
    struct Loop {
        Loop(const iterator &b, const iterator &e): begin(b), end(e) {}
        iterator begin;
        iterator end;
    };

public:
    ServiceGroup(const String &aKind);
    virtual ~ServiceGroup();

    virtual void parse();
    virtual void finalize(); // called after all are parsed

    virtual Loop initialServices() = 0;
    // TODO: virtual Loop sequentialServices() = 0;

public:
    String kind;
    Id id;
    Store services;
};

// a group of equivalent services; one service per set is usually used
class ServiceSet: public ServiceGroup
{
public:
    ServiceSet();
    virtual Loop initialServices();
};

// corner case: a group consisting of one service
class SingleService: public ServiceGroup
{
public:
    SingleService(const String &aServiceKey);
    virtual Loop initialServices();
};

// TODO: a group of services that must be used one after another
// class ServiceChain: public ServiceGroup


typedef Vector<Adaptation::ServiceGroup*> Groups;
extern Groups &AllGroups();
extern ServiceGroup *FindGroup(const ServiceGroup::Id &id);


} // namespace Adaptation

#endif /* SQUID_ADAPTATION__SERVICE_GROUPS_H */


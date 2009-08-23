#ifndef SQUID_ADAPTATION__SERVICE_GROUPS_H
#define SQUID_ADAPTATION__SERVICE_GROUPS_H

#include "SquidString.h"
#include "Array.h"
#include "RefCount.h"
#include "adaptation/Elements.h"
#include "adaptation/forward.h"

namespace Adaptation
{

// Interface for grouping adaptation services together.
// Specific groups differ in how the first and the next services are selected
class ServiceGroup: public RefCountable
{
public:
    typedef RefCount<ServiceGroup> Pointer;

    typedef Vector<String> Store;
    typedef String Id;
    typedef unsigned int Pos; // Vector<>::poistion_type
    friend class ServicePlan;

public:
    ServiceGroup(const String &aKind, bool areAllServicesSame);
    virtual ~ServiceGroup();

    virtual void parse();
    virtual void finalize(); // called after all are parsed

    bool wants(const ServiceFilter &filter) const;

protected:
    ///< whether this group has a service at the specified pos
    bool has(const Pos pos) const {
        // does not check that the service at pos still exists
        return pos < services.size(); // unsigned pos is never negative
    }

    /// these methods control group iteration; used by ServicePlan

    /// find next to try after failure, starting with pos
    bool findReplacement(const ServiceFilter &filter, Pos &pos) const;
    /// find next to link after success, starting with pos
    bool findLink(const ServiceFilter &filter, Pos &pos) const;

private:
    ServicePointer at(const Pos pos) const;
    bool findService(const ServiceFilter &filter, Pos &pos) const;

    void checkUniqueness(const Pos checkedPos) const;
    void finalizeMsg(const char *msg, const String &culprit, bool error) const;

public:
    String kind;
    Id id;
    Store services;

    Method method; /// based on the first added service
    VectPoint point; /// based on the first added service

    const bool allServicesSame; // whether we can freely substitute services
};

// a group of equivalent services; one service per set is usually used
class ServiceSet: public ServiceGroup
{
public:
    ServiceSet();

protected:
    virtual bool replace(Pos &pos) const { return has(++pos); }
    virtual bool advance(Pos &pos) const { return false; }
};

// corner case: a group consisting of one service
class SingleService: public ServiceGroup
{
public:
    SingleService(const String &aServiceKey);

protected:
    virtual bool replace(Pos &pos) const { return false; }
    virtual bool advance(Pos &pos) const { return false; }
};

/// a group of services that must be used one after another
class ServiceChain: public ServiceGroup
{
public:
    ServiceChain();

protected:
    virtual bool replace(Pos &pos) const { return false; }
    virtual bool advance(Pos &pos) const { return has(++pos); }
};

/// a temporary service chain built upon another service request
class DynamicServiceChain: public ServiceChain
{
public:
    DynamicServiceChain(const String &srvcs, const ServiceGroupPointer prev);
};


/** iterates services stored in a group; iteration is not linear because we
    need to both replace failed services and advance to the next chain link */
class ServicePlan
{
public:
    typedef unsigned int Pos; // Vector<>::poistion_type

public:
    ServicePlan();
    explicit ServicePlan(const ServiceGroupPointer &g, const ServiceFilter &filter);

    ///< true iff there are no more services planned
    bool exhausted() const { return atEof; }

    /// returns nil if the plan is complete
    ServicePointer current() const; ///< current service
    ServicePointer replacement(const ServiceFilter &filter); ///< next to try after failure
    ServicePointer next(const ServiceFilter &filter); ///< next in chain after success

    std::ostream &print(std::ostream &os) const;

private:
    ServiceGroupPointer group; ///< the group we are iterating
    Pos pos; ///< current service position within the group
    bool atEof; ///< cached information for better performance
};

inline
std::ostream &operator <<(std::ostream &os, const ServicePlan &p)
{
    return p.print(os);
}

typedef Vector<ServiceGroupPointer> Groups;
extern Groups &AllGroups();
extern ServiceGroupPointer FindGroup(const ServiceGroup::Id &id);


} // namespace Adaptation

#endif /* SQUID_ADAPTATION__SERVICE_GROUPS_H */


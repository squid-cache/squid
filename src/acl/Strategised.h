/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLSTRATEGISED_H
#define SQUID_ACLSTRATEGISED_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/FilledChecklist.h"
#include "acl/Strategy.h"

template <class M>
class ACLStrategised : public ACL
{
    MEMPROXY_CLASS(ACLStrategised);

public:
    typedef M MatchType;

    ~ACLStrategised();
    ACLStrategised(ACLData<MatchType> *, ACLStrategy<MatchType> *, char const *, const ACLFlag flags[] = ACLFlags::NoFlags);
    ACLStrategised (ACLStrategised const &);
    ACLStrategised &operator= (ACLStrategised const &);

    virtual char const *typeString() const;
    virtual bool requiresRequest() const {return matcher->requiresRequest();}

    virtual bool requiresReply() const {return matcher->requiresReply();}

    virtual void prepareForUse() { data->prepareForUse();}

    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    virtual int match (M const &);
    virtual SBufList dump() const;
    virtual bool empty () const;
    virtual bool valid () const;
    virtual ACL *clone()const;

private:
    ACLData<MatchType> *data;
    char const *type_;
    ACLStrategy<MatchType> *matcher;
};

/* implementation follows */

template <class MatchType>
ACLStrategised<MatchType>::~ACLStrategised()
{
    delete data;
}

template <class MatchType>
ACLStrategised<MatchType>::ACLStrategised(ACLData<MatchType> *newData, ACLStrategy<MatchType> *theStrategy, char const *theType, const ACLFlag flgs[]) : ACL(flgs), data (newData), type_(theType), matcher(theStrategy) {}

template <class MatchType>
ACLStrategised<MatchType>::ACLStrategised (ACLStrategised const &old) : data (old.data->clone()), type_(old.type_), matcher (old.matcher)
{}

template <class MatchType>
ACLStrategised<MatchType> &
ACLStrategised<MatchType>::operator= (ACLStrategised const &rhs)
{
    data = rhs.data->clone();
    type_ = rhs.type_;
    matcher = rhs.matcher;
    return *this;
}

template <class MatchType>
char const *
ACLStrategised<MatchType>::typeString() const
{
    return type_;
}

template <class MatchType>
void
ACLStrategised<MatchType>::parse()
{
    data->parse();
}

template <class MatchType>
bool
ACLStrategised<MatchType>::empty() const
{
    return data->empty();
}

template <class MatchType>
int
ACLStrategised<MatchType>::match(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = dynamic_cast<ACLFilledChecklist*>(cl);
    assert(checklist);
    return matcher->match(data, checklist, flags);
}

template <class MatchType>
int
ACLStrategised<MatchType>::match(MatchType const &toFind)
{
    return data->match(toFind);
}

template <class MatchType>
SBufList
ACLStrategised<MatchType>::dump() const
{
    return data->dump();
}

template <class MatchType>
bool
ACLStrategised<MatchType>::valid () const
{
    return matcher->valid();
}

template <class MatchType>
ACL *
ACLStrategised<MatchType>::clone() const
{
    return new ACLStrategised(*this);
}

#endif /* SQUID_ACLSTRATEGISED_H */


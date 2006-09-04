
/*
 * $Id: ACLStrategised.h,v 1.11 2006/09/03 21:05:20 hno Exp $
 *
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

#ifndef SQUID_ACLSTRATEGISED_H
#define SQUID_ACLSTRATEGISED_H
#include "ACL.h"
#include "ACLData.h"
#include "ACLStrategy.h"

template <class M>

class ACLStrategised : public ACL
{

public:
    typedef M MatchType;
    void *operator new(size_t);
    void operator delete(void *);

    ~ACLStrategised();
    ACLStrategised(ACLData<MatchType> *, ACLStrategy<MatchType> *, char const *);
    ACLStrategised (ACLStrategised const &);
    ACLStrategised &operator= (ACLStrategised const &);

    virtual char const *typeString() const;
    virtual bool requiresRequest() const {return matcher->requiresRequest();}

    virtual bool requiresReply() const {return matcher->requiresReply();}

    virtual void prepareForUse() { data->prepareForUse();}

    virtual void parse();
    virtual int match(ACLChecklist *checklist);
    virtual int match (M const &);
    virtual wordlist *dump() const;
    virtual bool empty () const;
    virtual bool valid () const;
    virtual ACL *clone()const;

private:
    static MemAllocator *Pool;
    ACLData<MatchType> *data;
    char const *type_;
    ACLStrategy<MatchType> *matcher;
};

/* implementation follows */

template <class MatchType>
MemAllocator *ACLStrategised<MatchType>::Pool = NULL;

template <class MatchType>
void *
ACLStrategised<MatchType>::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (ACLStrategised<MatchType>));

    if (!Pool)
        Pool = memPoolCreate("ACLStrategised", sizeof (ACLStrategised<MatchType>));

    return Pool->alloc();
}

template <class MatchType>
void
ACLStrategised<MatchType>::operator delete (void *address)
{
    Pool->free(address);
}

template <class MatchType>
ACLStrategised<MatchType>::~ACLStrategised()
{
    delete data;
}

template <class MatchType>
ACLStrategised<MatchType>::ACLStrategised(ACLData<MatchType> *newData, ACLStrategy<MatchType> *theStrategy, char const *theType) : data (newData), type_(theType), matcher(theStrategy) {}

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
ACLStrategised<MatchType>::match(ACLChecklist *checklist)
{
    return matcher->match(data, checklist);
}

template <class MatchType>
int
ACLStrategised<MatchType>::match(MatchType const &toFind)
{
    return data->match(toFind);
}

template <class MatchType>
wordlist *
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

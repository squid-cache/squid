/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include <iostream>

class CallCounter
{
public:
    CallCounter();
    void recordNew();
    void recordDelete();
    size_t news() const;
    size_t deletes() const;
private:
    size_t _news, _deletes;
};

CallCounter::CallCounter() : _news(0), _deletes(0) {}

void CallCounter::recordNew() { ++_news;}
void CallCounter::recordDelete() { ++_deletes;}
size_t CallCounter::news() const {return _news;}
size_t CallCounter::deletes() const {return _deletes;}

class BaseVirtual
{
public:
    void *operator new (size_t);
    void operator delete (void *);
    virtual ~BaseVirtual();
    static void DeleteABase(BaseVirtual *aBase);
    static CallCounter Calls;
};

CallCounter BaseVirtual::Calls;

void *
BaseVirtual::operator new(size_t byteCount)
{
    Calls.recordNew();
    return ::operator new (byteCount);
}

void
BaseVirtual::operator delete(void *address)
{
    Calls.recordDelete();
    ::operator delete (address);
}

void
BaseVirtual::DeleteABase(BaseVirtual *aBase)
{
    delete aBase;
}

BaseVirtual::~BaseVirtual() {}

class ChildVirtual : public BaseVirtual
{
public:
    void *operator new (size_t);
    void operator delete (void *);
    virtual ~ChildVirtual();
    static CallCounter Calls;
};

CallCounter ChildVirtual::Calls;

void *
ChildVirtual::operator new(size_t byteCount)
{
    Calls.recordNew();
    return ::operator new (byteCount);
}

void
ChildVirtual::operator delete(void *address)
{
    Calls.recordDelete();
    ::operator delete (address);
}

ChildVirtual::~ChildVirtual() {}

int
main(int argc, char **argv)
{
    assert (BaseVirtual::Calls.news() == 0);
    assert (BaseVirtual::Calls.deletes() == 0);
    assert (ChildVirtual::Calls.news() == 0);
    assert (ChildVirtual::Calls.deletes() == 0);
    BaseVirtual *aBase = new ChildVirtual;
    assert (BaseVirtual::Calls.news() == 0);
    assert (BaseVirtual::Calls.deletes() == 0);
    assert (ChildVirtual::Calls.news() == 1);
    assert (ChildVirtual::Calls.deletes() == 0);
    BaseVirtual::DeleteABase(aBase);
    assert (BaseVirtual::Calls.news() == 0);
    assert (BaseVirtual::Calls.deletes() == 0);
    assert (ChildVirtual::Calls.news() == 1);
    assert (ChildVirtual::Calls.deletes() == 1);
    // deleting NULL works.
    BaseVirtual::DeleteABase(NULL);
    assert (BaseVirtual::Calls.news() == 0);
    assert (BaseVirtual::Calls.deletes() == 0);
    assert (ChildVirtual::Calls.news() == 1);
    assert (ChildVirtual::Calls.deletes() == 1);
    return 0;
}


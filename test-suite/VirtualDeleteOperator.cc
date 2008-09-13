
/*
 * $Id: VirtualDeleteOperator.cc,v 1.2 2004/08/15 17:41:28 robertc Exp $
 *
 * AUTHOR: Robert Collins
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
 * Copyright (c) 2003  Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include <iostream>

class CallCounter {
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

class BaseVirtual {
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

BaseVirtual::~BaseVirtual(){}

class ChildVirtual : public BaseVirtual {
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

ChildVirtual::~ChildVirtual(){}

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

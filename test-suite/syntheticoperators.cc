
/*
 * $Id: syntheticoperators.cc,v 1.1 2003/07/10 01:31:51 robertc Exp $
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
#include "stmem.h"
#include "mem_node.h"
#include <iostream>

class HasExplicit {
  public:
    HasExplicit();
    ~HasExplicit();
    HasExplicit(HasExplicit const &);
    HasExplicit &operator=(HasExplicit const &);
    static int const &Instances();
    static int const &Assignments();
    static void Assignments(int const &);
  private:
    static void AddInstance();
    static void RemoveInstance();
    static void Assignment();
    static int Instances_;
    static int Assignments_;
};

int HasExplicit::Instances_(0);
int HasExplicit::Assignments_(0);

HasExplicit::HasExplicit() {
    AddInstance();
}

HasExplicit::~HasExplicit() {
    RemoveInstance();
}

HasExplicit::HasExplicit(HasExplicit const &) {
    AddInstance();
}

HasExplicit &
HasExplicit::operator= (HasExplicit const &) {
    Assignment();
    return *this;
}

void
HasExplicit::AddInstance()
{
    ++Instances_;
}

void
HasExplicit::RemoveInstance()
{
    --Instances_;
}

void
HasExplicit::Assignment()
{
    ++Assignments_;
}

int const &
HasExplicit::Instances()
{
    return Instances_;
}

int const &
HasExplicit::Assignments()
{
    return Assignments_;
}

void
HasExplicit::Assignments(int const &newValue)
{
    Assignments_ = newValue;
}

void
CheckHasExplicitWorks()
{
    assert (HasExplicit::Instances() == 0);
    HasExplicit *one = new HasExplicit;
    assert (HasExplicit::Instances() == 1);
    HasExplicit *two = new HasExplicit;
    assert (HasExplicit::Instances() == 2);
    *two = *one;
    assert (HasExplicit::Instances() == 2);
    assert (HasExplicit::Assignments() == 1);
    *two = *one;
    assert (HasExplicit::Instances() == 2);
    assert (HasExplicit::Assignments() == 2);
    HasExplicit *three = new HasExplicit(*two);
    assert (HasExplicit::Instances() == 3);
    delete three;
    assert (HasExplicit::Instances() == 2);
    delete one;
    assert (HasExplicit::Instances() == 1);
    delete two;
    assert (HasExplicit::Instances() == 0);
    HasExplicit::Assignments(0);
    assert (HasExplicit::Assignments() == 0);
}

class SyntheticOwnsExplicit {
  public:
    HasExplicit aMember;
};

void
CheckSyntheticWorks()
{
    assert (HasExplicit::Instances() == 0);
    assert (HasExplicit::Assignments() == 0);
    SyntheticOwnsExplicit *one = new SyntheticOwnsExplicit;
    assert (HasExplicit::Instances() == 1);
    SyntheticOwnsExplicit *two = new SyntheticOwnsExplicit;
    assert (HasExplicit::Instances() == 2);
    *two = *one;
    assert (HasExplicit::Instances() == 2);
    assert (HasExplicit::Assignments() == 1);
    *two = *one;
    assert (HasExplicit::Instances() == 2);
    assert (HasExplicit::Assignments() == 2);
    SyntheticOwnsExplicit *three = new SyntheticOwnsExplicit(*two);
    assert (HasExplicit::Instances() == 3);
    delete three;
    assert (HasExplicit::Instances() == 2);
    delete one;
    assert (HasExplicit::Instances() == 1);
    delete two;
    assert (HasExplicit::Instances() == 0);
    HasExplicit::Assignments(0);
    assert (HasExplicit::Assignments() == 0);
}

int
main (int argc, char *argv)
{
    CheckHasExplicitWorks();
    CheckSyntheticWorks();
    return 0;
}

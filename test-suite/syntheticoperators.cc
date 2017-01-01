/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mem_node.h"
#include "stmem.h"

#include <iostream>

class HasExplicit
{
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

HasExplicit::HasExplicit()
{
    AddInstance();
}

HasExplicit::~HasExplicit()
{
    RemoveInstance();
}

HasExplicit::HasExplicit(HasExplicit const &)
{
    AddInstance();
}

HasExplicit &
HasExplicit::operator= (HasExplicit const &)
{
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

class SyntheticOwnsExplicit
{
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
main(int argc, char **argv)
{
    CheckHasExplicitWorks();
    CheckSyntheticWorks();
    return 0;
}



/*
 * $Id: refcount.cc,v 1.4 2003/08/04 22:14:58 robertc Exp $
 *
 * DEBUG: section xx    Refcount allocator
 * AUTHOR:  Robert Collins
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
 */

#include "squid.h"
#include "RefCount.h"

class _ToRefCount :public RefCountable
{

public:
    _ToRefCount () {++Instances;}

    ~_ToRefCount() {--Instances;}

    int someMethod()
    {
        if (!this)
            exit(1);

        return 1;
    }

    static int Instances;

private:
};

typedef RefCount<_ToRefCount> ToRefCount;

/* Must be zero at the end for the test to pass. */
int _ToRefCount::Instances = 0;

class AlsoRefCountable : public RefCountable, public _ToRefCount
{

public:
    typedef RefCount<AlsoRefCountable> Pointer;

    int doSomething() { if (!this)
            exit (1); return 1;}
};

int
main (int argc, char **argv)
{
    {
        ToRefCount anObject(new _ToRefCount);
        anObject->someMethod();
        anObject = anObject;
        ToRefCount objectTwo (anObject);
        anObject = objectTwo;
        {
            ToRefCount anotherObject(new _ToRefCount);
            anObject = anotherObject;
        }

        {
            ToRefCount aForthObject (anObject);
            anObject = ToRefCount(NULL);
            aForthObject->someMethod();
            aForthObject = NULL;
        }
    }

    /* Test creating an object, using it , and then making available as a
     * refcounted one:
     */
    {
        _ToRefCount *aPointer = new _ToRefCount;
        aPointer->someMethod();
        ToRefCount anObject(aPointer);
    }
    /* standalone pointers should be usable */
    {
        ToRefCount anObject;
    }
    /* Can we check pointers for equality */
    {
        ToRefCount anObject;
        ToRefCount anotherObject(new _ToRefCount);

        if (anObject == anotherObject)
            exit (1);

        anotherObject = NULL;

        if (!(anObject == anotherObject))
            exit (1);
    }
    /* Can we get the pointer for a const object */
    {
        ToRefCount anObject (new _ToRefCount);
        ToRefCount const aConstObject (anObject);
        _ToRefCount const *aPointer = aConstObject.getRaw();

        if (aPointer != anObject.getRaw())
            exit (2);
    }
    /* Can we get a refcounted pointer from a const object */
    {
        _ToRefCount const * aPointer = new _ToRefCount;
        ToRefCount anObject (aPointer);
    }
    /* Can we get a pointer to nonconst from a nonconst refcounter */
    {
        ToRefCount anObject (new _ToRefCount);
        _ToRefCount *aPointer = anObject.getRaw();
        aPointer = NULL;
    }
    /* Create a doubley inheriting refcount instance,
     * cast to a single inheritance instance,
     * then hope :}
     */
    {
        ToRefCount aBaseObject;
        {
            AlsoRefCountable::Pointer anObject (new AlsoRefCountable);
            aBaseObject = anObject.getRaw();
        }
    }
    return _ToRefCount::Instances == 0 ? 0 : 1;
}

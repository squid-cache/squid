/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section --    Refcount allocator */

#include "squid.h"
#include "base/RefCount.h"

// XXX: upgrade these tests to CPPUnit testing framework

class _ToRefCount : public RefCountable
{
public:
    _ToRefCount () {++Instances;}
    ~_ToRefCount() {--Instances;}

    int someMethod() {
        if (!Instances)
            exit(1);

        return 1;
    }

    static int Instances;
};

typedef RefCount<_ToRefCount> ToRefCount;

/* Must be zero at the end for the test to pass. */
int _ToRefCount::Instances = 0;

class AlsoRefCountable : public RefCountable, public _ToRefCount
{
public:
    typedef RefCount<AlsoRefCountable> Pointer;

    int doSomething() {
        if (!Instances)
            exit (1);
        return 1;
    }
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
        if (aPointer == NULL)
            exit(3);
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


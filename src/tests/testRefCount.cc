/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section --    Refcount allocator */

#include "squid.h"
#include "base/RefCount.h"
#include "testRefCount.h"
#include "unitTestMain.h"

CPPUNIT_TEST_SUITE_REGISTRATION( testRefCount );

class _ToRefCount : public RefCountable
{
public:
    _ToRefCount () {++Instances;}
    ~_ToRefCount() {--Instances;}

    int someMethod() {
        if (!Instances)
            return 0;

        return 1;
    }

    static int Instances;
};

typedef RefCount<_ToRefCount> ToRefCount;

int _ToRefCount::Instances = 0;

class AlsoRefCountable : public RefCountable, public _ToRefCount
{
public:
    typedef RefCount<AlsoRefCountable> Pointer;

    int doSomething() {
        if (!Instances)
            return 0;
        return 1;
    }
};

void
testRefCount::testCountability()
{
    {
        CPPUNIT_ASSERT_EQUAL(0, _ToRefCount::Instances);
        ToRefCount anObject(new _ToRefCount);
        CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
        CPPUNIT_ASSERT_EQUAL(1, anObject->someMethod());
        anObject = anObject;
        CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
        ToRefCount objectTwo (anObject);
        anObject = objectTwo;
        CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
        {
            ToRefCount anotherObject(new _ToRefCount);
            anObject = anotherObject;
            CPPUNIT_ASSERT_EQUAL(2, _ToRefCount::Instances);
        }

        {
            ToRefCount aForthObject (anObject);
            CPPUNIT_ASSERT_EQUAL(2, _ToRefCount::Instances);
            anObject = ToRefCount(nullptr);
            CPPUNIT_ASSERT_EQUAL(2, _ToRefCount::Instances);
            CPPUNIT_ASSERT_EQUAL(1, aForthObject->someMethod());
            aForthObject = nullptr;
        }
        CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
    }
    CPPUNIT_ASSERT_EQUAL(0, _ToRefCount::Instances);
}

void
testRefCount::testObjectToRefCounted()
{
    /* Test creating an object, using it , and then making available as a
     * refcounted one:
     */
    CPPUNIT_ASSERT_EQUAL(0, _ToRefCount::Instances);
    _ToRefCount *aPointer = new _ToRefCount;
    CPPUNIT_ASSERT_EQUAL(1, aPointer->someMethod());
    ToRefCount anObject(aPointer);
    CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
}

void
testRefCount::testStandalonePointer()
{
    /* standalone pointers should be usable */
    ToRefCount anObject;
    CPPUNIT_ASSERT_EQUAL(0, _ToRefCount::Instances);
}

void
testRefCount::testCheckPointers()
{
    /* Can we check pointers for equality */
    ToRefCount anObject;
    CPPUNIT_ASSERT_EQUAL(0, _ToRefCount::Instances);
    ToRefCount anotherObject(new _ToRefCount);

    CPPUNIT_ASSERT(anObject != anotherObject);

    CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
    anotherObject = nullptr;

    CPPUNIT_ASSERT_EQUAL(anObject, anotherObject);
    CPPUNIT_ASSERT_EQUAL(0, _ToRefCount::Instances);
}

void
testRefCount::testPointerConst()
{
    /* Can we get the pointer for a const object */
    CPPUNIT_ASSERT_EQUAL(0, _ToRefCount::Instances);
    ToRefCount anObject (new _ToRefCount);
    ToRefCount const aConstObject (anObject);
    _ToRefCount const *aPointer = aConstObject.getRaw();

    CPPUNIT_ASSERT(aPointer == anObject.getRaw());
    CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
}

void testRefCount::testRefCountFromConst()
{
    /* Can we get a refcounted pointer from a const object */
    CPPUNIT_ASSERT_EQUAL(0, _ToRefCount::Instances);
    _ToRefCount const * aPointer = new _ToRefCount;
    ToRefCount anObject (aPointer);

    CPPUNIT_ASSERT(aPointer == anObject.getRaw());
    CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
}

void
testRefCount::testPointerFromRefCounter()
{
    /* Can we get a pointer to nonconst from a nonconst refcounter */
    CPPUNIT_ASSERT_EQUAL(0, _ToRefCount::Instances);
    ToRefCount anObject (new _ToRefCount);
    CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
    _ToRefCount *aPointer = anObject.getRaw();
    CPPUNIT_ASSERT(aPointer != nullptr);
    CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
}

void
testRefCount::testDoubleInheritToSingleInherit()
{

    CPPUNIT_ASSERT_EQUAL(0, _ToRefCount::Instances);
    /* Create a doubley inheriting refcount instance,
     * cast to a single inheritance instance,
     * then hope :}
     */
    ToRefCount aBaseObject;
    {
        AlsoRefCountable::Pointer anObject (new AlsoRefCountable);
        aBaseObject = anObject.getRaw();
        CPPUNIT_ASSERT_EQUAL(1, anObject->doSomething());
        CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
    }
    CPPUNIT_ASSERT_EQUAL(1, _ToRefCount::Instances);
}

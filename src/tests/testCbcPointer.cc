/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section --    CbcPointer */

#include "squid.h"
#include "base/CbcPointer.h"
#include "compat/cppunit.h"
#include "unitTestMain.h"

class TestCbcPointer : public CPPUNIT_NS::TestFixture
{
    CPPUNIT_TEST_SUITE(TestCbcPointer);
    CPPUNIT_TEST(testConstruction);
    CPPUNIT_TEST(testLogicOperators);
    CPPUNIT_TEST(testCounting);
    CPPUNIT_TEST_SUITE_END();

protected:
    void testConstruction();
    void testLogicOperators();
    void testCounting();
};
CPPUNIT_TEST_SUITE_REGISTRATION( TestCbcPointer );

class Blob
{
    CBDATA_CLASS(Blob);
public:
    Blob() { ++Instances; }
    ~Blob() { --Instances; }

    static int Instances;
};
CBDATA_CLASS_INIT(Blob);

int Blob::Instances = 0;

void
TestCbcPointer::testConstruction()
{
    Blob *nil = nullptr;
    {
        // default nil
        CbcPointer<Blob> empty;
        CPPUNIT_ASSERT_EQUAL(nil, empty.raw());
        CPPUNIT_ASSERT_EQUAL(false, empty.set());
        CPPUNIT_ASSERT_EQUAL(nil, empty.get());
        // destruct of default-nil
    }

    {
        // explicit nil
        CbcPointer<Blob> empty(nullptr);
        CPPUNIT_ASSERT_EQUAL(nil, empty.raw());
        CPPUNIT_ASSERT_EQUAL(false, empty.set());
        CPPUNIT_ASSERT_EQUAL(nil, empty.get());
        // destruct of explicit-nil
    }

    {
        auto expect = new Blob;
        // construction from a raw pointer
        CbcPointer<Blob> ptr(expect);
        CPPUNIT_ASSERT_EQUAL(expect, ptr.raw());
        CPPUNIT_ASSERT_EQUAL(true, ptr.set());
        CPPUNIT_ASSERT_EQUAL(expect, ptr.get());

        // invalidated by delete operator
        delete ptr.get();
        // memory should remain valid while ptr is set
        CPPUNIT_ASSERT_EQUAL(static_cast<void*>(expect), expect->toCbdata());
        CPPUNIT_ASSERT_EQUAL(expect, ptr.raw());
        CPPUNIT_ASSERT_EQUAL(true, ptr.set());
        CPPUNIT_ASSERT_EQUAL(nil, ptr.get());
        // destruct of dirty Pointer
    }

    // copy and move construction are checked in testCounting()
}

void
TestCbcPointer::testLogicOperators()
{
    // nil pointer semantics
    {
        CbcPointer<Blob> ptr;
        CbcPointer<Blob> other;
        CPPUNIT_ASSERT_EQUAL(static_cast<Blob *>(nullptr), ptr.valid());
        CPPUNIT_ASSERT_EQUAL(true, !ptr);
        CPPUNIT_ASSERT(other == ptr);
    }

    // valid pointer semantics
    {
        auto expect = new Blob;
        CbcPointer<Blob> ptr(expect);
        CbcPointer<Blob> same(expect);
        CbcPointer<Blob> other;
        CPPUNIT_ASSERT_EQUAL(expect, ptr.valid());
        CPPUNIT_ASSERT_EQUAL(false, !ptr);
        CPPUNIT_ASSERT(same == ptr);
        // TODO: missing operator !=()
        CPPUNIT_ASSERT(!(other == ptr));
        // CbcPointer does not invalidate on destruct. prevent a leak
        delete expect;
    }

    // invalid pointer semantics
    {
        auto expect = new Blob;
        CbcPointer<Blob> ptr(expect);
        CbcPointer<Blob> same(expect);
        CbcPointer<Blob> other;
        delete expect; // invalidates
        CPPUNIT_ASSERT_EQUAL(static_cast<Blob *>(nullptr), ptr.valid());
        CPPUNIT_ASSERT_EQUAL(true, !ptr);
        CPPUNIT_ASSERT(same == ptr);
        // TODO: missing operator !=()
        CPPUNIT_ASSERT(!(other == ptr));
    }
}

void
TestCbcPointer::testCounting()
{
    // check no leaks from earlier tests
    CPPUNIT_ASSERT_EQUAL(0, Blob::Instances);

    // counting with nil pointer should never allocate
    {
        const CbcPointer<Blob> empty;
        CPPUNIT_ASSERT_EQUAL(0, Blob::Instances);

        // copying nil should not allocate
        CbcPointer<Blob> copyable(empty);
        CPPUNIT_ASSERT_EQUAL(0, Blob::Instances);
        copyable = empty;
        CPPUNIT_ASSERT_EQUAL(0, Blob::Instances);

        // moving nil should not allocate
        CbcPointer<Blob> moveable(std::move(copyable));
        CPPUNIT_ASSERT_EQUAL(0, Blob::Instances);
        moveable = std::move(copyable);
        CPPUNIT_ASSERT_EQUAL(0, Blob::Instances);
    }

    {
        const CbcPointer<Blob> one(new Blob);
        CPPUNIT_ASSERT(one.valid() != nullptr);
        CPPUNIT_ASSERT_EQUAL(1, Blob::Instances);

        // copy should not allocate
        CbcPointer<Blob> copyable(one);
        CPPUNIT_ASSERT(copyable.valid() != nullptr);
        CPPUNIT_ASSERT_EQUAL(1, Blob::Instances);
        copyable = one;
        CPPUNIT_ASSERT(copyable.valid() != nullptr); // no change
        CPPUNIT_ASSERT_EQUAL(1, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(one, copyable);
        copyable = copyable;
        CPPUNIT_ASSERT(copyable.valid() != nullptr); // no change
        CPPUNIT_ASSERT_EQUAL(1, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(one, copyable);

        // move should not allocate
        CbcPointer<Blob> moveable(std::move(copyable));
        CPPUNIT_ASSERT(copyable.valid() == nullptr); // moved away
        CPPUNIT_ASSERT(moveable.valid() != nullptr);
        CPPUNIT_ASSERT_EQUAL(1, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(one, moveable);
        copyable = one; // reset for next test
        moveable = std::move(copyable);
        CPPUNIT_ASSERT(copyable.valid() == nullptr); // moved away
        CPPUNIT_ASSERT(moveable.valid() != nullptr);
        CPPUNIT_ASSERT_EQUAL(1, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(one, moveable);
        moveable = std::move(moveable);
        CPPUNIT_ASSERT(moveable.valid() != nullptr); // no change
        CPPUNIT_ASSERT_EQUAL(1, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(one, moveable);

        copyable = one; // reset for next test
        CPPUNIT_ASSERT(copyable.valid() != nullptr);
        // clear() must not deallocate
        copyable.clear();
        CPPUNIT_ASSERT(copyable.valid() == nullptr);
        CPPUNIT_ASSERT(moveable.valid() != nullptr);
        CPPUNIT_ASSERT_EQUAL(1, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(false, !moveable); // still valid

        // delete with 2 active references should deallocate
        delete one.raw();
        CPPUNIT_ASSERT_EQUAL(0, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(true, !moveable); // now invalid
    }

    {
        const CbcPointer<Blob> one(new Blob);
        const CbcPointer<Blob> two(new Blob);
        CPPUNIT_ASSERT(one.valid() != nullptr);
        CPPUNIT_ASSERT(two.valid() != nullptr);
        CPPUNIT_ASSERT(one.raw() != two.raw()); // paranoia
        CPPUNIT_ASSERT_EQUAL(2, Blob::Instances);

        // copy should not allocate
        CbcPointer<Blob> copyable(one);
        CPPUNIT_ASSERT(copyable.valid() != nullptr);
        CPPUNIT_ASSERT_EQUAL(one, copyable);
        CPPUNIT_ASSERT_EQUAL(2, Blob::Instances);
        copyable = two;
        CPPUNIT_ASSERT(copyable.valid() != nullptr);
        CPPUNIT_ASSERT_EQUAL(2, Blob::Instances);
        CPPUNIT_ASSERT(copyable.raw() != one.raw());
        CPPUNIT_ASSERT_EQUAL(two, copyable);
        copyable = copyable;
        CPPUNIT_ASSERT(copyable.valid() != nullptr);
        CPPUNIT_ASSERT_EQUAL(2, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(two, copyable);

        // move should not allocate
        CbcPointer<Blob> moveable(std::move(copyable));
        CPPUNIT_ASSERT(copyable.valid() == nullptr); // moved away
        CPPUNIT_ASSERT(moveable.valid() != nullptr);
        CPPUNIT_ASSERT_EQUAL(2, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(two, moveable);
        copyable = one; // reset for next test
        moveable = std::move(copyable);
        CPPUNIT_ASSERT(copyable.valid() == nullptr); // moved away
        CPPUNIT_ASSERT(moveable.valid() != nullptr);
        CPPUNIT_ASSERT_EQUAL(2, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(one, moveable);
        moveable = std::move(moveable);
        CPPUNIT_ASSERT(moveable.valid() != nullptr); // no change
        CPPUNIT_ASSERT_EQUAL(2, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(one, moveable);

        copyable = one; // reset for next test
        CPPUNIT_ASSERT(copyable.valid() != nullptr);
        // clear() must not deallocate
        copyable.clear();
        CPPUNIT_ASSERT(copyable.valid() == nullptr);
        CPPUNIT_ASSERT(moveable.valid() != nullptr);
        CPPUNIT_ASSERT_EQUAL(2, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(false, !moveable); // still valid

        // delete with 2 active references should deallocate
        CPPUNIT_ASSERT_EQUAL(one, moveable);
        delete one.raw();
        CPPUNIT_ASSERT_EQUAL(1, Blob::Instances);
        CPPUNIT_ASSERT_EQUAL(true, !moveable); // now invalid
        delete two.raw();
        CPPUNIT_ASSERT_EQUAL(0, Blob::Instances);
    }
}

#include "squid.h"
#include "Mem.h"
#include "testStore.h"
#include "testStoreEntryStream.h"
#include "Store.h"
#include "StoreEntryStream.h"

#include <iomanip>

#include <cppunit/TestAssert.h>

CPPUNIT_TEST_SUITE_REGISTRATION( testStoreEntryStream );

/* class that captures various call data for test analysis */

class CapturingStoreEntry : public StoreEntry
{

public:
    MEMPROXY_CLASS(CapturingStoreEntry);

    CapturingStoreEntry() : _buffer_calls(0), _flush_calls(0) {}

    String _appended_text;
    int _buffer_calls;
    int _flush_calls;

    virtual void buffer()
    {
        _buffer_calls += 1;
    }

    virtual void flush()
    {
        _flush_calls += 1;
    }

    virtual void append(char const * buf, int len)
    {
        _appended_text.append(buf, len);
    }
};

MEMPROXY_CLASS_INLINE(CapturingStoreEntry);


/* init memory pools */

struct Initer
{
    Initer() {Mem::Init();}
};

static Initer ensure_mempools;

void
testStoreEntryStream::testGetStream()
{
    /* Setup a store root so we can create a StoreEntry */
    StorePointer aStore (new TestStore);
    Store::Root(aStore);

    CapturingStoreEntry * anEntry = new CapturingStoreEntry();
    {
        StoreEntryStream stream(anEntry);
        CPPUNIT_ASSERT_EQUAL(1, anEntry->_buffer_calls);
        CPPUNIT_ASSERT_EQUAL(0, anEntry->_flush_calls);
        stream << "some text" << std::setw(4) << "!";
        CPPUNIT_ASSERT_EQUAL(1, anEntry->_buffer_calls);
        CPPUNIT_ASSERT_EQUAL(0, anEntry->_flush_calls);
        stream.flush();
        CPPUNIT_ASSERT_EQUAL(1, anEntry->_buffer_calls);
        CPPUNIT_ASSERT_EQUAL(1, anEntry->_flush_calls);
        CPPUNIT_ASSERT_EQUAL(String("some text   !"), anEntry->_appended_text);
    }

    delete anEntry;

    Store::Root(NULL);
}

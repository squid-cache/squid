#ifndef SQUID_TESTS_CAPTURINGSTORE_ENTRY_H
#define SQUID_TESTS_CAPTURINGSTORE_ENTRY_H

#include "Mem.h"
#include "Store.h"

/* class that captures various call data for test analysis */

class CapturingStoreEntry : public StoreEntry
{

public:
    MEMPROXY_CLASS(CapturingStoreEntry);

    CapturingStoreEntry() : _buffer_calls(0), _flush_calls(0) {}

    String _appended_text;
    int _buffer_calls;
    int _flush_calls;

    virtual void buffer() {
        _buffer_calls += 1;
    }

    virtual void flush() {
        _flush_calls += 1;
    }

    virtual void append(char const * buf, int len) {
        _appended_text.append(buf, len);
    }
};

MEMPROXY_CLASS_INLINE(CapturingStoreEntry);

#endif

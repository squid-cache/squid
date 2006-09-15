

#include "squid.h"
#include "MemBuf.h"
#include "BodyReader.h"

BodyReader::BodyReader(size_t len, BodyReadFunc *r, BodyAbortFunc *a, BodyKickFunc *k, void *d) :
        _remaining(len), _available(0),
        read_func(r), abort_func(a), kick_func(k), read_func_data(d),
        read_callback(NULL), read_callback_data(NULL)
{
    theBuf.init(4096, 65536);
    debugs(32,3,HERE << this << " " << "created new BodyReader for content-length " << len);
    bytes_read = 0;
}

BodyReader::~BodyReader()
{
    if (_remaining && abort_func)
        abort_func(read_func_data, _remaining);

    if (callbackPending())
        doCallback();

}

void
BodyReader::read(CBCB *callback, void *cbdata)
{
    assert(_remaining || theBuf.contentSize());
    debugs(32,3,HERE << this << " " << "remaining = " << _remaining);
    debugs(32,3,HERE << this << " " << "available = " << _available);

    if (read_callback == NULL) {
        read_callback = callback;
        read_callback_data = cbdataReference(cbdata);
    } else {
        assert(read_callback == callback);
        assert(read_callback_data == cbdata);
    }

    if ((_available == 0) && (theBuf.contentSize() == 0)) {
        debugs(32,3,HERE << this << " " << "read: no body data available, saving callback pointers");

        if (kick_func)
            kick_func(read_func_data);

        return;
    }

    debugs(32,3,HERE << this << " " << "read_func=" << read_func);
    debugs(32,3,HERE << this << " " << "data=" << read_func_data);
    size_t size = theBuf.potentialSpaceSize();

    debugs(32, 3, "BodyReader::read: available: " << _available << ", size " << size << ", remaining: " << _remaining);

    if (size > _available)
        size = _available;

    if (size > _remaining)
	size = _remaining;

    if (size > 0) {
        debugs(32,3,HERE << this << " " << "calling read_func for " << size << " bytes");

        size_t nread = read_func(read_func_data, theBuf, size);

        if (nread > 0) {
            _available -= nread;
            reduce_remaining(nread);
        } else {
            debugs(32,3,HERE << this << " " << "Help, read_func() ret " << nread);
        }
    }

    if (theBuf.contentSize() > 0) {
        debugs(32,3,HERE << this << " have " << theBuf.contentSize() << " bytes in theBuf, calling back");
        doCallback();
    }
}

void
BodyReader::notify(size_t now_available)
{
    debugs(32,3,HERE << this << " " << "old available = " << _available);
    debugs(32,3,HERE << this << " " << "now_available = " << now_available);
    _available = now_available;

    if (!callbackPending()) {
        debugs(32,3,HERE << this << " " << "no callback pending, nothing to do");
        return;
    }

    debugs(32,3,HERE << this << " " << "have data and pending callback, calling read()");

    read(read_callback, read_callback_data);
}

bool
BodyReader::callbackPending()
{
    return read_callback ? true : false;
}

/*
 * doCallback
 *
 * Execute the read callback if there is a function registered
 * and the read_callback_data is still valid.
 */
bool
BodyReader::doCallback()
{
    CBCB *t_callback = read_callback;
    void *t_cbdata;

    if (t_callback == NULL)
        return false;

    read_callback = NULL;

    if (!cbdataReferenceValidDone(read_callback_data, &t_cbdata))
        return false;

    debugs(32,3,HERE << this << " doing callback, theBuf size = " << theBuf.contentSize());

    t_callback(theBuf, t_cbdata);

    return true;
}

bool
BodyReader::consume(size_t size)
{
    debugs(32,3,HERE << this << " BodyReader::consume consuming " << size);

    if (theBuf.contentSize() < (mb_size_t) size) {
        debugs(0,0,HERE << this << "BodyReader::consume failed");
        debugs(0,0,HERE << this << "BodyReader::consume size = " << size);
        debugs(0,0,HERE << this << "BodyReader::consume contentSize() = " << theBuf.contentSize());
        return false;
    }

    theBuf.consume(size);

    if (callbackPending() && _available > 0) {
        debugs(32,3,HERE << this << " " << "data avail and pending callback, calling read()");
        read(read_callback, read_callback_data);
    }

    return true;
}

void
BodyReader::reduce_remaining(size_t size)
{
    assert(size <= _remaining);
    _remaining -= size;
}

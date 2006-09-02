
#ifndef SQUID_BODY_READER_H
#define SQUID_BODY_READER_H

typedef void CBCB (MemBuf &mb, void *data);
typedef size_t BodyReadFunc (void *, MemBuf &mb, size_t size);
typedef void BodyAbortFunc (void *, size_t);
typedef void BodyKickFunc (void *);

class BodyReader : public RefCountable
{

public:
    typedef RefCount<BodyReader> Pointer;
    BodyReader(size_t len, BodyReadFunc *r, BodyAbortFunc *a, BodyKickFunc *k, void *d);
    ~BodyReader();
    void read(CBCB *, void *);
    void notify(size_t now_available);
    size_t remaining() { return _remaining; }

    bool callbackPending();
    bool consume(size_t size);

    int bytes_read;

    /* reduce the number of bytes that the BodyReader is looking for.
     * Will trigger an assertion if it tries to reduce below zero
     */
    void reduce_remaining(size_t size);

private:
    size_t _remaining;
    size_t _available;
    MemBuf theBuf;

    /*
     * These are for interacting with things that
     * "provide" body content.  ie, ConnStateData and
     * ICAPReqMod after adapation.
     */
    BodyReadFunc *read_func;
    BodyAbortFunc *abort_func;
    BodyKickFunc *kick_func;
    void *read_func_data;

    /*
     * These are for interacting with things that
     * "consume" body content. ie, HttpStateData and
     * ICAPReqMod before adaptation.
     */
    CBCB *read_callback;
    void *read_callback_data;
    bool doCallback();
};

#endif

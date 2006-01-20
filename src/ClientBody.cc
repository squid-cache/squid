#include "squid.h"
#include "client_side.h"
#include "ClientBody.h"
#include "HttpRequest.h"


ClientBody::ClientBody(ConnStateData::Pointer & aConn, HttpRequest *Request) : conn(aConn), request(NULL), buf (NULL), bufsize(0), callback(NULL), cbdata(NULL)
{
    request = requestLink(Request);
}

ClientBody::~ClientBody()
{
    if (cbdata)
        cbdataReferenceDone(cbdata);

    requestUnlink(request);

    conn = NULL; 	// refcounted
}

/* Called by clientReadRequest to process body content */
void
ClientBody::process()
{

    debug(33, 2) ("clientBody::process: start FD %d body_size=%lu in.notYetUsed=%lu cb=%p req=%p\n",
                  conn->fd,
                  (unsigned long int) conn->body_size_left,
                  (unsigned long int) conn->in.notYetUsed,
                  callback,
                  request);

    if (conn->in.notYetUsed)
        processBuffer();
    else
        conn->readSomeData();
}

void
ClientBody::processBuffer()
{
    /* Some sanity checks... */
    assert(conn->body_size_left > 0);
    assert(conn->in.notYetUsed > 0);
    assert(callback != NULL);
    assert(buf != NULL);
    /* How much do we have to process? */
    size_t size = conn->in.notYetUsed;

    if (size > conn->body_size_left)    /* only process the body part */
        size = conn->body_size_left;

    if (size > bufsize)      /* don't copy more than requested */
        size = bufsize;

    xmemcpy(buf, conn->in.buf, size);

    conn->body_size_left -= size;

    /* Move any remaining data */
    conn->in.notYetUsed -= size;

    if (conn->in.notYetUsed > 0)
        xmemmove(conn->in.buf, conn->in.buf + size, conn->in.notYetUsed);

    /* Remove request link if this is the last part of the body, as
     * clientReadRequest automatically continues to process next request */
    if (conn->body_size_left <= 0 && request != NULL)
        request->body_connection = NULL;

    request->flags.body_sent = 1;

    doCallback(size);

    debug(33, 2) ("ClientBody::process: end FD %d size=%lu body_size=%lu in.notYetUsed=%lu cb=%p req=%p\n",
                  conn->fd, (unsigned long int)size, (unsigned long int) conn->body_size_left,
                  (unsigned long) conn->in.notYetUsed, callback, request);
}

void
ClientBody::init(char *Buf, size_t Bufsize, CBCB *Callback, void *Cbdata)
{
    buf = Buf;
    bufsize = Bufsize;
    callback = Callback;
    cbdata = cbdataReference(Cbdata);
}

void
ClientBody::doCallback(size_t theSize)
{
    char *theBuf = buf;
    CBCB *theCallback = callback;
    void *theCbdata = cbdata;

    buf = NULL;
    bufsize = 0;
    callback = NULL;
    cbdata = NULL;

    void *someCbdata;

    if (cbdataReferenceValidDone(theCbdata, &someCbdata))
        theCallback(theBuf, theSize, someCbdata);
}

void
ClientBody::negativeCallback()
{
    doCallback((size_t)-1);
}

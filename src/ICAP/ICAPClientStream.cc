


#include "squid.h"
#include "ICAPClient.h"
#include "clientStream.h"
#include "client_side_reply.h"
#include "HttpHeader.h"
#include "HttpReply.h"

struct _junk
{
    clientStreamNode *node;
    clientHttpRequest *http;
    HttpReply *rep;
    StoreIOBuffer *receivedData;
};

static EVH someEvent;


/*
 * This callback is called for each incoming data chunk.
 * Note receivedData only gives us the message body, not
 * the headers
 */
void
icapclientProcessStream(clientStreamNode *thisNode, clientHttpRequest *http, HttpReply *rep, StoreIOBuffer receivedData)
{
    assert (thisNode != NULL);
    assert (cbdataReferenceValid (thisNode));

    debug(0,0)("This is icapclientProcessStream\n");
    debug(0,0)("\tthisNode=%p\n", thisNode);
    debug(0,0)("\thttp=%p\n", http);
    debug(0,0)("\trep=%p\n", rep);
    //debug(0,0)("\trep->content_length=%d\n", rep->content_length);
    char *foo;
    foo = new char[receivedData.length+1];
    xstrncpy(foo, receivedData.data, receivedData.length+1);
    *(foo+receivedData.length) = '\0';
    debug(0,0)("{%s}\n", foo);

    struct _junk *j = (struct _junk *) xcalloc(1, sizeof(*j));
    j->node = thisNode;
    j->http = http;
    j->rep = rep;
    j->receivedData = &receivedData;

    eventAdd("someEvent", someEvent, j, 5.0, 0, 0);

}

void
icapclientStreamRead(clientStreamNode *thisNode, clientHttpRequest *http)
{
    debug(0,0)("This is icapclientStreamRead\n");

    /* pass data through untouched */
    clientStreamNode *next = thisNode->next();
    clientStreamRead (thisNode, http, next->readBuffer);
    return;
}

void
icapclientStreamDetach(clientStreamNode *thisNode, clientHttpRequest *http)
{
    debug(0,0)("This is icapclientStreamDetach\n");
}

clientStream_status_t
icapclientStreamStatus(clientStreamNode *thisNode, clientHttpRequest *http)
{
    debug(0,0)("This is icapclientStreamStatus\n");

    /* pass data through untouched */
    return clientStreamStatus (thisNode, http);

    return STREAM_NONE;
}

static void
someEvent(void *foo)
{
    debug(0,0)("this is someEvent\n");

    struct _junk *j = (struct _junk *) foo;


    if (NULL != j->rep) {
        httpHeaderPutExt(&j->rep->header, "X-foo", "bar-bar");
    }

    if (NULL == j->node->data.getRaw()) {
        /* first call; setup our state */
    }

    /* pass data through untouched */
    clientStreamCallback (j->node, j->http, j->rep, *j->receivedData);

    free(j);

}

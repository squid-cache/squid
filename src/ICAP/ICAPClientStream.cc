


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

    debugs(0, 0, "This is icapclientProcessStream");
    debugs(0, 0, "\tthisNode=" << thisNode);
    debugs(0, 0, "\thttp=" << http);
    debugs(0, 0, "\trep=" << rep);
    debugs(0, 0, "\trep->content_length=" << rep->content_length);
    char *foo;
    foo = new char[receivedData.length+1];
    xstrncpy(foo, receivedData.data, receivedData.length+1);
    *(foo+receivedData.length) = '\0';
    debugs(0, 0, "{" << foo << "}");

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
    debugs(0, 0, "This is icapclientStreamRead");

    /* pass data through untouched */
    clientStreamNode *next = thisNode->next();
    clientStreamRead (thisNode, http, next->readBuffer);
    return;
}

void
icapclientStreamDetach(clientStreamNode *thisNode, clientHttpRequest *http)
{
    debugs(0, 0, "This is icapclientStreamDetach");
}

clientStream_status_t
icapclientStreamStatus(clientStreamNode *thisNode, clientHttpRequest *http)
{
    debugs(0, 0, "This is icapclientStreamStatus");

    /* pass data through untouched */
    return clientStreamStatus (thisNode, http);

    return STREAM_NONE;
}

static void
someEvent(void *foo)
{
    debugs(0, 0, "this is someEvent");

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

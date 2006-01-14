#ifndef SQUID_CLIENTBODY_H
#define SQUID_CLIETNBODY_H

class ClientBody
{

public:
    ClientBody (ConnStateData::Pointer &, HttpRequest *);
    ~ClientBody();
    void process();
    void processBuffer();
    void init(char *, size_t, CBCB *, void *);
bool hasCallback() const { return callback ? true : false; };

    void doCallback(size_t);
    void negativeCallback();
    HttpRequest * getRequest() { return request; };

private:
    ConnStateData::Pointer conn;
    HttpRequest *request;
    char *buf;
    size_t bufsize;
    CBCB *callback;
    void *cbdata;
};


#endif

/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#ifndef SQUID_IPC_ASYNCUDSOP_H
#define SQUID_IPC_ASYNCUDSOP_H


#include "SquidString.h"
#include "CommCalls.h"


namespace Ipc
{


typedef enum {mtNone = 0, mtRegister} MessageType;

/**
   This one contains a registration info
*/
struct StrandData
{
    int   kidId;
    pid_t pid;
};

/**
  This class contains data is used by UdsSender/UdsReceiver.
*/
class Message
{
public:
    Message();
    Message(MessageType messageType, int kidId, pid_t pid);

public:
    MessageType type() const;
    const StrandData& strand() const;
    char*  rawData();
    size_t size();

private:
    struct {
        MessageType messageType;
        StrandData  strand;
    } data;
};

/**
  UdsOp implements common async UDS operation.
*/
class UdsOp: public AsyncJob
{
private:
    UdsOp(const UdsOp&); // not implemented
    UdsOp& operator= (const UdsOp&); // not implemented

public:
    UdsOp(const String& pathAddr, bool bind = true);
    virtual ~UdsOp();

protected:
    /// return an endpoint for communication, use fd() instead of fd_
    int fd();
    virtual bool doneAll() const;
    void setTimeout(AsyncCall::Pointer& timeoutHandler, int aTimeout);

private:
    struct sockaddr_un setAddr(const String& pathAddr);

private:
    struct sockaddr_un addr;
    int  options;
    int  fd_;
};

/**
  Implement async write operation for UDS
*/
class UdsSender: public UdsOp
{
private:
    UdsSender(const UdsSender&); // not implemented
    UdsSender& operator= (const UdsSender&); // not implemented

public:
    UdsSender(const String& pathAddr, const Message& aMessage);

public:
    /// start writing data
    virtual void start();

private:
    /// update retries counter and check
    bool retry();
    /// schedule writing
    void write();
    void noteWrite(const CommIoCbParams& params);
    void noteTimeout(const CommTimeoutCbParams& params);

private:
    Message message;
    int retries;
    int timeout;

    CBDATA_CLASS2(UdsSender);
};


void SendMessage(const String& toAddress, const Message& message);


}

#endif /* SQUID_IPC_ASYNCUDSOP_H */

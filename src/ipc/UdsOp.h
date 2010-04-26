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


typedef enum { mtNone = 0, mtRegistration } MessageType;

/// Strand registration information
struct StrandData
{
    int kidId;
    pid_t pid;
};

/// information sent or received during IPC
class Message
{
public:
    Message();
    Message(MessageType messageType, int kidId, pid_t pid);

    /// raw, type-independent access
    int type() const { return data.messageType; }
    char *raw() { return reinterpret_cast<char*>(&data); }
    const char *raw() const { return reinterpret_cast<const char*>(&data); }
    size_t size() const { return sizeof(data); }

    /// type-dependent access
    const StrandData& strand() const;

private:
    struct Data {
        int messageType;
        StrandData strand;
        // TODO: redesign to better handle many type-specific datas like strand
    } data; ///< everything being sent or received
};

/// code shared by unix-domain socket senders (e.g., UdsSender or Coordinator)
/// and receivers (e.g. Port or Coordinator)
class UdsOp: public AsyncJob
{
public:
    UdsOp(const String &pathAddr);
    virtual ~UdsOp();

protected:
    virtual void timedout() {} ///< called after setTimeout() if timed out

    int fd(); ///< creates if needed and returns raw UDS socket descriptor

    /// call timedout() if no UDS messages in a given number of seconds
    void setTimeout(int seconds, const char *handlerName);
    void clearTimeout(); ///< remove previously set timeout, if any

	void setOptions(int newOptions); ///< changes socket options

private:
    /// Comm timeout callback; calls timedout()
    void noteTimeout(const CommTimeoutCbParams &p);

    /// configures addr member
    struct sockaddr_un setAddr(const String &pathAddr);

private:
    struct sockaddr_un addr; ///< UDS address
    int options; ///< UDS options
    int fd_; ///< UDS descriptor

private:
    UdsOp(const UdsOp &); // not implemented
    UdsOp &operator= (const UdsOp &); // not implemented
};

// XXX: move UdsSender code to UdsSender.{cc,h}
/// attempts to send an IPC message a few times, with a timeout
class UdsSender: public UdsOp
{
public:
    UdsSender(const String& pathAddr, const Message& aMessage);

protected:
    virtual void start(); // UdsOp (AsyncJob) API
    virtual bool doneAll() const; // UdsOp (AsyncJob) API
    virtual void timedout(); // UdsOp API

private:
    void write(); ///< schedule writing
    void wrote(const CommIoCbParams& params); ///< done writing or error

private:
    Message message; ///< what to send
    int retries; ///< how many times to try after a write error
    int timeout; ///< total time to send the message
    bool writing; ///< whether Comm started and did not finish writing

    CBDATA_CLASS2(UdsSender);

private:
    UdsSender(const UdsSender&); // not implemented
    UdsSender& operator= (const UdsSender&); // not implemented
};


void SendMessage(const String& toAddress, const Message& message);


}

#endif /* SQUID_IPC_ASYNCUDSOP_H */

/*
 * DEBUG: section 09    File Transfer Protocol (FTP)
 *
 */

#ifndef SQUID_FTP_SERVER_H
#define SQUID_FTP_SERVER_H

#include "Server.h"

class String;
namespace Ftp {

extern const char *const crlf;

/// common code for FTP server control and data channels
/// does not own the channel descriptor, which is managed by FtpStateData
class FtpChannel
{
public:
    /// called after the socket is opened, sets up close handler
    void opened(const Comm::ConnectionPointer &conn, const AsyncCall::Pointer &aCloser);

    /** Handles all operations needed to properly close the active channel FD.
     * clearing the close handler, clearing the listen socket properly, and calling comm_close
     */
    void close();

    void forget(); /// remove the close handler, leave connection open

    void clear(); ///< just drops conn and close handler. does not close active connections.

    Comm::ConnectionPointer conn; ///< channel descriptor

    /** A temporary handle to the connection being listened on.
     * Closing this will also close the waiting Data channel acceptor.
     * If a data connection has already been accepted but is still waiting in the event queue
     * the callback will still happen and needs to be handled (usually dropped).
     */
    Comm::ConnectionPointer listenConn;

    AsyncCall::Pointer opener; ///< Comm opener handler callback.
private:
    AsyncCall::Pointer closer; ///< Comm close handler callback
};

/// Base class for FTP over HTTP and FTP Gateway server state.
class ServerStateData: public ::ServerStateData
{
public:
    ServerStateData(FwdState *fwdState);
    virtual ~ServerStateData();

    virtual void failed(err_type error = ERR_NONE, int xerrno = 0);
    virtual void timeout(const CommTimeoutCbParams &io);
    virtual const Comm::ConnectionPointer & dataConnection() const;
    virtual void abortTransaction(const char *reason);
    void writeCommand(const char *buf);

    /// extracts remoteAddr from PASV response, validates it,
    /// sets data address details, and returns true on success
    bool handlePasvReply(Ip::Address &remoteAddr);
    bool handleEpsvReply(Ip::Address &remoteAddr);

    bool sendEprt();
    bool sendPort();
    bool sendPassive();
    void connectDataChannel();
    bool openListenSocket();
    virtual void maybeReadVirginBody();
    void switchTimeoutToDataChannel();

    // \todo: optimize ctrl and data structs member order, to minimize size
    /// FTP control channel info; the channel is opened once per transaction
    struct CtrlChannel: public FtpChannel {
        char *buf;
        size_t size;
        size_t offset;
        wordlist *message;
        char *last_command;
        char *last_reply;
        int replycode;
    } ctrl;

    /// FTP data channel info; the channel may be opened/closed a few times
    struct DataChannel: public FtpChannel {
        MemBuf *readBuf;
        char *host;
        unsigned short port;
        bool read_pending;

        void addr(const Ip::Address &addr); ///< import host and port
    } data;

    enum {
        BEGIN,
        SENT_USER,
        SENT_PASS,
        SENT_TYPE,
        SENT_MDTM,
        SENT_SIZE,
        SENT_EPRT,
        SENT_PORT,
        SENT_EPSV_ALL,
        SENT_EPSV_1,
        SENT_EPSV_2,
        SENT_PASV,
        SENT_CWD,
        SENT_LIST,
        SENT_NLST,
        SENT_REST,
        SENT_RETR,
        SENT_STOR,
        SENT_QUIT,
        READING_DATA,
        WRITING_DATA,
        SENT_MKDIR,
        SENT_FEAT,
        SENT_PWD,
        SENT_CDUP,
        SENT_DATA_REQUEST, // LIST, NLST or RETR requests..
        SENT_COMMAND, // General command
        END
    } ftp_state_t;

    int state;
    char *old_request;
    char *old_reply;

protected:
    virtual void start();

    void initReadBuf();
    virtual void closeServer();
    virtual bool doneWithServer() const;
    virtual Http::StatusCode failedHttpStatus(err_type &error);
    void ctrlClosed(const CommCloseCbParams &io);
    void scheduleReadControlReply(int buffered_ok);
    void readControlReply(const CommIoCbParams &io);
    virtual void handleControlReply();
    void writeCommandCallback(const CommIoCbParams &io);
    static CNCB dataChannelConnected;
    virtual void dataChannelConnected(const Comm::ConnectionPointer &conn, Comm::Flag status, int xerrno) = 0;
    void dataRead(const CommIoCbParams &io);
    void dataComplete();
    AsyncCall::Pointer dataCloser();
    virtual void dataClosed(const CommCloseCbParams &io);

    // sending of the request body to the server
    virtual void sentRequestBody(const CommIoCbParams &io);
    virtual void doneSendingRequestBody();

private:
    bool parseControlReply(size_t &bytesUsed);

    CBDATA_CLASS2(ServerStateData);
};

/// parses and validates "A1,A2,A3,A4,P1,P2" IP,port sequence
bool ParseIpPort(const char *buf, const char *forceIp, Ip::Address &addr);
/// parses and validates EPRT "<d><net-prt><d><net-addr><d><tcp-port><d>" proto,ip,port sequence
bool ParseProtoIpPort(const char *buf, Ip::Address &addr);
/// parses a ftp quoted quote-escaped path
const char *unescapeDoubleQuoted(const char *quotedPath);
/// Return true if the FTP command takes as parameter a pathname
bool hasPathParameter(const String &cmd);
}; // namespace Ftp

#endif /* SQUID_FTP_SERVER_H */

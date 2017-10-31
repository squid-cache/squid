/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HAPPYCONNOPENER_H
#define SQUID_HAPPYCONNOPENER_H
#include "base/RefCount.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"

class FwdState;
class CandidatePaths;
typedef RefCount<CandidatePaths> CandidatePathsPointer;

class HappyConnOpener: public AsyncJob
{
    CBDATA_CLASS(HappyConnOpener);
public:
    class Answer
    {
    public:
        Comm::ConnectionPointer conn;
        Comm::Flag ioStatus = Comm::OK;
        const char *host = nullptr;
        int xerrno = 0;
        const char *status = nullptr;
        bool reused = false;
        int n_tries = 0;

        friend std::ostream &operator <<(std::ostream &os, const HappyConnOpener::Answer &answer);
    };

    class CbDialer: public CallDialer {
    public:
        typedef void (FwdState::*Method)(const HappyConnOpener::Answer &);

        virtual ~CbDialer() {}
        CbDialer(Method method, FwdState *fwd): method_(method), fwd_(fwd) {}

        /* CallDialer API */
        virtual bool canDial(AsyncCall &call) {return fwd_.valid();};
        virtual void dial(AsyncCall &call) {((&(*fwd_))->*method_)(answer_);};
        virtual void print(std::ostream &os) const {
            os << '(' << fwd_.get() << "," << answer_ << ')';
        }

        Method method_;
        CbcPointer<FwdState> fwd_;
        HappyConnOpener::Answer answer_;
    };

    typedef CbcPointer<HappyConnOpener> Pointer;

    HappyConnOpener(const CandidatePathsPointer &, const AsyncCall::Pointer &, const time_t fwdStart, int tries);
    ~HappyConnOpener();

    void noteCandidatePath();

    void startConnecting(Comm::ConnectionPointer &);
    void connectDone(const CommConnectCbParams &);
    Comm::ConnectionPointer getCandidatePath();
    void checkForNewConnection();
    bool preconditions();
    bool timeCondition();
    void allowPersistent(bool p) { allowPconn = p; }
    void notRetriable() { retriable_ = false; }
    void setHost(const char *host);
    void callCallback(const Comm::ConnectionPointer &conn, Comm::Flag err, int xerrno, bool reused, const char *msg);

    // AsyncJob API
    virtual void start() override;
    virtual bool doneAll() const override;
    virtual void swanSong() override;

    /// Pops a connection from connection pool if available. If not
    /// checks the peer stand-by connection pool for available connection.
    static Comm::ConnectionPointer PconnPop(const Comm::ConnectionPointer &dest, const char *domain, bool retriable);
    static void PconnPush(Comm::ConnectionPointer &conn, const char *domain);
    static void ConnectionClosed(const Comm::ConnectionPointer &conn);
    static void ManageConnections(void *);
    static bool SystemPreconditions();
public:
    AsyncCall::Pointer callback_; ///< handler to be called on connection completion.
    CandidatePathsPointer dests_;
    struct {
        Comm::ConnectionPointer path;
        Comm::ConnOpener::Pointer connector;
    } master, spare;

    bool allowPconn;
    bool retriable_;
    const char *host_;
    time_t fwdStart_;
    int maxTries;
    int n_tries;
    tos_t useTos;
    nfmark_t useNfmark;
    double lastStart;

    static int SpareConnects;
    static double LastAttempt;
};

std::ostream &operator <<(std::ostream &os, const HappyConnOpener::Answer &answer);

#endif

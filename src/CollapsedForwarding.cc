/*
 * DEBUG: section 17    Request Forwarding
 *
 */

#include "squid.h"
#include "ipc/mem/Segment.h"
#include "ipc/Messages.h"
#include "ipc/Port.h"
#include "ipc/TypedMsgHdr.h"
#include "CollapsedForwarding.h"
#include "SquidConfig.h"
#include "globals.h"
#include "tools.h"

/// shared memory segment path to use for CollapsedForwarding queue
static const char *const ShmLabel = "cf";
/// a single worker-to-worker queue capacity
// TODO: make configurable or compute from squid.conf settings if possible
static const int QueueCapacity = 1024;

std::auto_ptr<CollapsedForwarding::Queue> CollapsedForwarding::queue;

/// IPC queue message
class CollapsedForwardingMsg
{
public:
    CollapsedForwardingMsg(): processId(-1) {}

public:
    int processId; /// ID of sending process
    // XXX: add entry info
};

// CollapsedForwarding

void
CollapsedForwarding::Init()
{
    Must(!queue.get());
    queue.reset(new Queue(ShmLabel, KidIdentifier));
}

void
CollapsedForwarding::NewData(const StoreIOState &sio)
{
    CollapsedForwardingMsg msg;
    msg.processId = KidIdentifier;
    // XXX: copy data from sio

    // TODO: send only to workers who are waiting for data
    // XXX: does not work for non-daemon mode?
    for (int workerId = 1; workerId <= Config.workers; ++workerId) {
        try {
            if (queue->push(workerId, msg))
                Notify(workerId);
        } catch (const Queue::Full &) {
            debugs(17, DBG_IMPORTANT, "Worker collapsed forwarding push queue "
                   "overflow: " << workerId); // TODO: report queue len
            // TODO: grow queue size
        }
    }
}

void
CollapsedForwarding::Notify(const int workerId)
{
    // TODO: Count and report the total number of notifications, pops, pushes.
    debugs(17, 7, HERE << "kid" << workerId);
    Ipc::TypedMsgHdr msg;
    // TODO: add proper message type?
    msg.setType(Ipc::mtCollapsedForwardingNotification);
    msg.putInt(KidIdentifier);
    const String addr = Ipc::Port::MakeAddr(Ipc::strandAddrPfx, workerId);
    Ipc::SendMessage(addr, msg);
}

void
CollapsedForwarding::HandleNewData(const char *const when)
{
    debugs(17, 4, HERE << "popping all " << when);
    CollapsedForwardingMsg msg;
    int workerId;
    int poppedCount = 0;
    while (queue->pop(workerId, msg)) {
        debugs(17, 3, HERE << "collapsed forwarding data message from " <<
               workerId);
        if (workerId != msg.processId) {
            debugs(17, DBG_IMPORTANT, HERE << "mismatching IDs: " << workerId <<
                   " != " << msg.processId);
        }

        // XXX: stop and schedule an async call to continue
        assert(++poppedCount < SQUID_MAXFD);
    }
}

void
CollapsedForwarding::HandleNotification(const Ipc::TypedMsgHdr &msg)
{
    const int from = msg.getInt();
    debugs(17, 7, HERE << "from " << from);
    queue->clearReaderSignal(from);
    HandleNewData("after notification");
}

/// initializes shared queue used by CollapsedForwarding
class CollapsedForwardingRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    CollapsedForwardingRr(): owner(NULL) {}
    virtual ~CollapsedForwardingRr();

protected:
    virtual void create(const RunnerRegistry &);
    virtual void open(const RunnerRegistry &);

private:
    Ipc::MultiQueue::Owner *owner;
};

RunnerRegistrationEntry(rrAfterConfig, CollapsedForwardingRr);

void CollapsedForwardingRr::create(const RunnerRegistry &)
{
    Must(!owner);
    owner = Ipc::MultiQueue::Init(ShmLabel, Config.workers, 1,
                                  sizeof(CollapsedForwardingMsg),
                                  QueueCapacity);
}

void CollapsedForwardingRr::open(const RunnerRegistry &)
{
    if (IamWorkerProcess())
        CollapsedForwarding::Init();
}

CollapsedForwardingRr::~CollapsedForwardingRr()
{
    delete owner;
}

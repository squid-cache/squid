
#include "squid.h"
#include "base/AsyncJobCalls.h"
#include "BodyPipe.h"
#include "TextException.h"

CBDATA_CLASS_INIT(BodyPipe);

// BodySink is a BodyConsumer class which  just consume and drops
// data from a BodyPipe
class BodySink: public BodyConsumer
{
    bool done;
public:
    BodySink():AsyncJob("BodySink"), done(false) {}
    virtual ~BodySink() {}

    virtual void noteMoreBodyDataAvailable(BodyPipe::Pointer bp) {
        size_t contentSize = bp->buf().contentSize();
        bp->consume(contentSize);
    }
    virtual void noteBodyProductionEnded(BodyPipe::Pointer bp) {
        stopConsumingFrom(bp);
        done = true;
    }
    virtual void noteBodyProducerAborted(BodyPipe::Pointer bp) {
        stopConsumingFrom(bp);
        done = true;
    }
    bool doneAll() const {return done && AsyncJob::doneAll();}
    CBDATA_CLASS2(BodySink);
};

CBDATA_CLASS_INIT(BodySink);

// The BodyProducerDialer is an AsyncCall class which used to schedule BodyProducer calls.
// In addition to a normal AsyncCall checks if the BodyProducer is still the producer of
// the BodyPipe passed as argument
class BodyProducerDialer: public UnaryMemFunT<BodyProducer, BodyPipe::Pointer>
{
public:
    typedef UnaryMemFunT<BodyProducer, BodyPipe::Pointer> Parent;

    BodyProducerDialer(const BodyProducer::Pointer &aProducer,
                       Parent::Method aHandler, BodyPipe::Pointer bp):
            Parent(aProducer, aHandler, bp) {}

    virtual bool canDial(AsyncCall &call);
};

// The BodyConsumerDialer is an AsyncCall class which used to schedule BodyConsumer calls.
// In addition to a normal AsyncCall checks if the BodyConsumer is still the reciptient
// of the BodyPipe passed as argument
class BodyConsumerDialer: public UnaryMemFunT<BodyConsumer, BodyPipe::Pointer>
{
public:
    typedef UnaryMemFunT<BodyConsumer, BodyPipe::Pointer> Parent;

    BodyConsumerDialer(const BodyConsumer::Pointer &aConsumer,
                       Parent::Method aHandler, BodyPipe::Pointer bp):
            Parent(aConsumer, aHandler, bp) {}

    virtual bool canDial(AsyncCall &call);
};

bool
BodyProducerDialer::canDial(AsyncCall &call)
{
    if (!Parent::canDial(call))
        return false;

    const BodyProducer::Pointer &producer = job;
    BodyPipe::Pointer pipe = arg1;
    if (!pipe->stillProducing(producer)) {
        debugs(call.debugSection, call.debugLevel, HERE << producer <<
               " no longer producing for " << pipe->status());
        return call.cancel("no longer producing");
    }

    return true;
}

bool
BodyConsumerDialer::canDial(AsyncCall &call)
{
    if (!Parent::canDial(call))
        return false;

    const BodyConsumer::Pointer &consumer = job;
    BodyPipe::Pointer pipe = arg1;
    if (!pipe->stillConsuming(consumer)) {
        debugs(call.debugSection, call.debugLevel, HERE << consumer <<
               " no longer consuming from " << pipe->status());
        return call.cancel("no longer consuming");
    }

    return true;
}


/* BodyProducer */

// inform the pipe that we are done and clear the Pointer
void BodyProducer::stopProducingFor(RefCount<BodyPipe> &pipe, bool atEof)
{
    debugs(91,7, HERE << this << " will not produce for " << pipe <<
           "; atEof: " << atEof);
    assert(pipe != NULL); // be strict: the caller state may depend on this
    pipe->clearProducer(atEof);
    pipe = NULL;
}



/* BodyConsumer */

// inform the pipe that we are done and clear the Pointer
void BodyConsumer::stopConsumingFrom(RefCount<BodyPipe> &pipe)
{
    debugs(91,7, HERE << this << " will not consume from " << pipe);
    assert(pipe != NULL); // be strict: the caller state may depend on this
    pipe->clearConsumer();
    pipe = NULL;
}


/* BodyPipe */

BodyPipe::BodyPipe(Producer *aProducer): theBodySize(-1),
        theProducer(aProducer), theConsumer(0),
        thePutSize(0), theGetSize(0),
        mustAutoConsume(false), abortedConsumption(false), isCheckedOut(false)
{
    // TODO: teach MemBuf to start with zero minSize
    // TODO: limit maxSize by theBodySize, when known?
    theBuf.init(2*1024, MaxCapacity);
    debugs(91,7, HERE << "created BodyPipe" << status());
}

BodyPipe::~BodyPipe()
{
    debugs(91,7, HERE << "destroying BodyPipe" << status());
    assert(!theProducer);
    assert(!theConsumer);
    theBuf.clean();
}

void BodyPipe::setBodySize(uint64_t aBodySize)
{
    assert(!bodySizeKnown());
    assert(thePutSize <= aBodySize);

    // If this assert fails, we need to add code to check for eof and inform
    // the consumer about the eof condition via scheduleBodyEndNotification,
    // because just setting a body size limit may trigger the eof condition.
    assert(!theConsumer);

    theBodySize = aBodySize;
    debugs(91,7, HERE << "set body size" << status());
}

uint64_t BodyPipe::bodySize() const
{
    assert(bodySizeKnown());
    return static_cast<uint64_t>(theBodySize);
}

bool BodyPipe::expectMoreAfter(uint64_t offset) const
{
    assert(theGetSize <= offset);
    return offset < thePutSize || // buffer has more now or
           (!productionEnded() && mayNeedMoreData()); // buffer will have more
}

bool BodyPipe::exhausted() const
{
    return !expectMoreAfter(theGetSize);
}

uint64_t BodyPipe::unproducedSize() const
{
    return bodySize() - thePutSize; // bodySize() asserts that size is known
}

void
BodyPipe::clearProducer(bool atEof)
{
    if (theProducer.set()) {
        debugs(91,7, HERE << "clearing BodyPipe producer" << status());
        theProducer.clear();
        if (atEof) {
            if (!bodySizeKnown())
                theBodySize = thePutSize;
            else if (bodySize() != thePutSize)
                debugs(91,3, HERE << "aborting on premature eof" << status());
        } else {
            // asserta that we can detect the abort if the consumer joins later
            assert(!bodySizeKnown() || bodySize() != thePutSize);
        }
        scheduleBodyEndNotification();
    }
}

size_t
BodyPipe::putMoreData(const char *aBuffer, size_t size)
{
    if (bodySizeKnown())
        size = min((uint64_t)size, unproducedSize());

    const size_t spaceSize = static_cast<size_t>(theBuf.potentialSpaceSize());
    if ((size = min(size, spaceSize))) {
        theBuf.append(aBuffer, size);
        postAppend(size);
        return size;
    }
    return 0;
}

bool
BodyPipe::setConsumerIfNotLate(const Consumer::Pointer &aConsumer)
{
    assert(!theConsumer);
    assert(aConsumer.set()); // but might be invalid

    // TODO: convert this into an exception and remove IfNotLate suffix
    // If there is something consumed already, we are in an auto-consuming mode
    // and it is too late to attach a real consumer to the pipe.
    if (theGetSize > 0) {
        assert(mustAutoConsume);
        return false;
    }

    Must(!abortedConsumption); // did not promise to never consume

    theConsumer = aConsumer;
    debugs(91,7, HERE << "set consumer" << status());
    if (theBuf.hasContent())
        scheduleBodyDataNotification();
    if (!theProducer)
        scheduleBodyEndNotification();

    return true;
}

void
BodyPipe::clearConsumer()
{
    if (theConsumer.set()) {
        debugs(91,7, HERE << "clearing consumer" << status());
        theConsumer.clear();
        // do not abort if we have not consumed so that HTTP or ICAP can retry
        // benign xaction failures due to persistent connection race conditions
        if (consumedSize())
            expectNoConsumption();
    }
}

void
BodyPipe::expectNoConsumption()
{
    Must(!theConsumer);
    if (!abortedConsumption && !exhausted()) {
        AsyncCall::Pointer call= asyncCall(91, 7,
                                           "BodyProducer::noteBodyConsumerAborted",
                                           BodyProducerDialer(theProducer,
                                                              &BodyProducer::noteBodyConsumerAborted, this));
        ScheduleCallHere(call);
        abortedConsumption = true;
    }
}

size_t
BodyPipe::getMoreData(MemBuf &aMemBuffer)
{
    if (!theBuf.hasContent())
        return 0; // did not touch the possibly uninitialized buf

    if (aMemBuffer.isNull())
        aMemBuffer.init();
    const size_t size = min(theBuf.contentSize(), aMemBuffer.potentialSpaceSize());
    aMemBuffer.append(theBuf.content(), size);
    theBuf.consume(size);
    postConsume(size);
    return size; // cannot be zero if we called buf.init above
}

void
BodyPipe::consume(size_t size)
{
    theBuf.consume(size);
    postConsume(size);
}

// In the AutoConsumption  mode the consumer has gone but the producer continues
// producing data. We are using a BodySink BodyConsumer which just discards the produced data.
void
BodyPipe::enableAutoConsumption()
{
    mustAutoConsume = true;
    debugs(91,5, HERE << "enabled auto consumption" << status());
    if (!theConsumer && theBuf.hasContent())
        startAutoConsumption();
}

// start auto consumption by creating body sink
void
BodyPipe::startAutoConsumption()
{
    Must(mustAutoConsume);
    Must(!theConsumer);
    theConsumer = new BodySink;
    debugs(91,7, HERE << "starting auto consumption" << status());
    scheduleBodyDataNotification();
}

MemBuf &
BodyPipe::checkOut()
{
    assert(!isCheckedOut);
    isCheckedOut = true;
    return theBuf;
}

void
BodyPipe::checkIn(Checkout &checkout)
{
    assert(isCheckedOut);
    isCheckedOut = false;
    const size_t currentSize = theBuf.contentSize();
    if (checkout.checkedOutSize > currentSize)
        postConsume(checkout.checkedOutSize - currentSize);
    else if (checkout.checkedOutSize < currentSize)
        postAppend(currentSize - checkout.checkedOutSize);
}

void
BodyPipe::undoCheckOut(Checkout &checkout)
{
    assert(isCheckedOut);
    const size_t currentSize = theBuf.contentSize();
    // We can only undo if size did not change, and even that carries
    // some risk. If this becomes a problem, the code checking out
    // raw buffers should always check them in (possibly unchanged)
    // instead of relying on the automated undo mechanism of Checkout.
    // The code can always use a temporary buffer to accomplish that.
    Must(checkout.checkedOutSize == currentSize);
}

// TODO: Optimize: inform consumer/producer about more data/space only if
// they used the data/space since we notified them last time.

void
BodyPipe::postConsume(size_t size)
{
    assert(!isCheckedOut);
    theGetSize += size;
    debugs(91,7, HERE << "consumed " << size << " bytes" << status());
    if (mayNeedMoreData()) {
        AsyncCall::Pointer call=  asyncCall(91, 7,
                                            "BodyProducer::noteMoreBodySpaceAvailable",
                                            BodyProducerDialer(theProducer,
                                                               &BodyProducer::noteMoreBodySpaceAvailable, this));
        ScheduleCallHere(call);
    }
}

void
BodyPipe::postAppend(size_t size)
{
    assert(!isCheckedOut);
    thePutSize += size;
    debugs(91,7, HERE << "added " << size << " bytes" << status());

    if (mustAutoConsume && !theConsumer && size > 0)
        startAutoConsumption();

    // We should not consume here even if mustAutoConsume because the
    // caller may not be ready for the data to be consumed during this call.
    scheduleBodyDataNotification();

    if (!mayNeedMoreData())
        clearProducer(true); // reached end-of-body
}


void
BodyPipe::scheduleBodyDataNotification()
{
    if (theConsumer.valid()) { // TODO: allow asyncCall() to check this instead
        AsyncCall::Pointer call = asyncCall(91, 7,
                                            "BodyConsumer::noteMoreBodyDataAvailable",
                                            BodyConsumerDialer(theConsumer,
                                                               &BodyConsumer::noteMoreBodyDataAvailable, this));
        ScheduleCallHere(call);
    }
}

void
BodyPipe::scheduleBodyEndNotification()
{
    if (theConsumer.valid()) { // TODO: allow asyncCall() to check this instead
        if (bodySizeKnown() && bodySize() == thePutSize) {
            AsyncCall::Pointer call = asyncCall(91, 7,
                                                "BodyConsumer::noteBodyProductionEnded",
                                                BodyConsumerDialer(theConsumer,
                                                                   &BodyConsumer::noteBodyProductionEnded, this));
            ScheduleCallHere(call);
        } else {
            AsyncCall::Pointer call = asyncCall(91, 7,
                                                "BodyConsumer::noteBodyProducerAborted",
                                                BodyConsumerDialer(theConsumer,
                                                                   &BodyConsumer::noteBodyProducerAborted, this));
            ScheduleCallHere(call);
        }
    }
}

// a short temporary string describing buffer status for debugging
const char *BodyPipe::status() const
{
    static MemBuf outputBuffer;
    outputBuffer.reset();

    outputBuffer.append(" [", 2);

    outputBuffer.Printf("%"PRIu64"<=%"PRIu64, theGetSize, thePutSize);
    if (theBodySize >= 0)
        outputBuffer.Printf("<=%"PRId64, theBodySize);
    else
        outputBuffer.append("<=?", 3);

    outputBuffer.Printf(" %d+%d", (int)theBuf.contentSize(), (int)theBuf.spaceSize());

    outputBuffer.Printf(" pipe%p", this);
    if (theProducer.set())
        outputBuffer.Printf(" prod%p", theProducer.get());
    if (theConsumer.set())
        outputBuffer.Printf(" cons%p", theConsumer.get());

    if (mustAutoConsume)
        outputBuffer.append(" A", 2);
    if (abortedConsumption)
        outputBuffer.append(" !C", 3);
    if (isCheckedOut)
        outputBuffer.append(" L", 2); // Locked

    outputBuffer.append("]", 1);

    outputBuffer.terminate();

    return outputBuffer.content();
}


/* BodyPipeCheckout */

BodyPipeCheckout::BodyPipeCheckout(BodyPipe &aPipe): pipe(aPipe),
        buf(aPipe.checkOut()), offset(aPipe.consumedSize()),
        checkedOutSize(buf.contentSize()), checkedIn(false)
{
}

BodyPipeCheckout::~BodyPipeCheckout()
{
    if (!checkedIn) {
        // Do not pipe.undoCheckOut(*this) because it asserts or throws
        // TODO: consider implementing the long-term solution discussed at
        // http://www.mail-archive.com/squid-dev@squid-cache.org/msg07910.html
        debugs(91,2, HERE << "Warning: cannot undo BodyPipeCheckout");
        pipe.checkIn(*this);
    }
}

void
BodyPipeCheckout::checkIn()
{
    assert(!checkedIn);
    pipe.checkIn(*this);
    checkedIn = true;
}


BodyPipeCheckout::BodyPipeCheckout(const BodyPipeCheckout &c): pipe(c.pipe),
        buf(c.buf), offset(c.offset), checkedOutSize(c.checkedOutSize),
        checkedIn(c.checkedIn)
{
    assert(false); // prevent copying
}

BodyPipeCheckout &
BodyPipeCheckout::operator =(const BodyPipeCheckout &)
{
    assert(false); // prevent assignment
    return *this;
}

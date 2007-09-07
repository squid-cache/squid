
#include "squid.h"
#include "BodyPipe.h"

CBDATA_CLASS_INIT(BodyPipe);

// inform the pipe that we are done and clear the Pointer
void BodyProducer::stopProducingFor(RefCount<BodyPipe> &pipe, bool atEof)
{
	debugs(91,7, HERE << this << " will not produce for " << pipe <<
		"; atEof: " << atEof);
	assert(pipe != NULL); // be strict: the caller state may depend on this
	pipe->clearProducer(atEof);
	pipe = NULL;
}

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
	thePutSize(0), theGetSize(0), theCCallsPending(0), theCCallsToSkip(0),
	mustAutoConsume(false), isCheckedOut(false)
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
	assert(aBodySize >= 0);
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

size_t BodyPipe::unproducedSize() const
{
	return bodySize() - thePutSize; // bodySize() asserts that size is known
}

void
BodyPipe::clearProducer(bool atEof)
{
	if (theProducer) {
		debugs(91,7, HERE << "clearing BodyPipe producer" << status());
		theProducer = NULL;
		if (atEof) {
			if (!bodySizeKnown())
				theBodySize = thePutSize;
			else
			if (bodySize() != thePutSize)
				debugs(91,3, HERE << "aborting on premature eof" << status());
		} else {
			// asserta that we can detect the abort if the consumer joins later
			assert(!bodySizeKnown() || bodySize() != thePutSize);
		}
		scheduleBodyEndNotification();
	}
}

size_t
BodyPipe::putMoreData(const char *buf, size_t size)
{
	if (bodySizeKnown())
		size = XMIN(size, unproducedSize());

	const size_t spaceSize = static_cast<size_t>(theBuf.potentialSpaceSize());
	if ((size = XMIN(size, spaceSize))) {
		theBuf.append(buf, size);
		postAppend(size);
		return size;
	}
	return 0;
}

bool
BodyPipe::setConsumerIfNotLate(Consumer *aConsumer)
{
	assert(!theConsumer);
	assert(aConsumer);

	// TODO: convert this into an exception and remove IfNotLate suffix
	// If there is something consumed already, we are in an auto-consuming mode
	// and it is too late to attach a real consumer to the pipe.
	if (theGetSize > 0) {
		assert(mustAutoConsume);
		return false;
	}

	theConsumer = aConsumer;
	debugs(91,7, HERE << "set consumer" << status());
	if (theBuf.hasContent())
		scheduleBodyDataNotification();
	if (!theProducer)
		scheduleBodyEndNotification();

	return true;
}

// When BodyPipe consumer is gone, all events for that consumer must not
// reach the new consumer (if any). Otherwise, the calls may go out of order
// (if _some_ calls are dropped due to the ultimate destination being 
// temporary NULL). The code keeps track of the number of outstanding
// events and skips that number if consumer leaves. TODO: when AscyncCall
// support is improved, should we just schedule calls directly to consumer?
void
BodyPipe::clearConsumer() {
	if (theConsumer) {
		debugs(91,7, HERE << "clearing consumer" << status());
		theConsumer = NULL;
		theCCallsToSkip = theCCallsPending; // skip all pending consumer calls
		if (consumedSize() && !exhausted())
			AsyncCall(91,5, this, BodyPipe::tellBodyConsumerAborted);
	}
}

size_t
BodyPipe::getMoreData(MemBuf &buf)
{
	if (!theBuf.hasContent())
		return 0; // did not touch the possibly uninitialized buf

	if (buf.isNull())
		buf.init();
	const size_t size = XMIN(theBuf.contentSize(), buf.potentialSpaceSize());
	buf.append(theBuf.content(), size);
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

void
BodyPipe::enableAutoConsumption() {
	mustAutoConsume = true;
	debugs(91,5, HERE << "enabled auto consumption" << status());
	if (!theConsumer && theBuf.hasContent())
		scheduleBodyDataNotification();
}

MemBuf &
BodyPipe::checkOut() {
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
	else
	if (checkout.checkedOutSize < currentSize)
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
	assert(checkout.checkedOutSize == currentSize);
}

// TODO: Optimize: inform consumer/producer about more data/space only if
// they used the data/space since we notified them last time.

void
BodyPipe::postConsume(size_t size) {
	assert(!isCheckedOut);
	theGetSize += size;
	debugs(91,7, HERE << "consumed " << size << " bytes" << status());
	if (mayNeedMoreData())
		AsyncCall(91,5, this, BodyPipe::tellMoreBodySpaceAvailable);
}

void
BodyPipe::postAppend(size_t size) {
	assert(!isCheckedOut);
	thePutSize += size;
	debugs(91,7, HERE << "added " << size << " bytes" << status());

	// We should not consume here even if mustAutoConsume because the
	// caller may not be ready for the data to be consumed during this call.
	scheduleBodyDataNotification();

	if (!mayNeedMoreData())
		clearProducer(true); // reached end-of-body
}


void
BodyPipe::scheduleBodyDataNotification()
{
	if (theConsumer || mustAutoConsume) {
		++theCCallsPending;
		AsyncCall(91,5, this, BodyPipe::tellMoreBodyDataAvailable);
	}
}

void
BodyPipe::scheduleBodyEndNotification()
{
	if (theConsumer) {
		++theCCallsPending;
		if (bodySizeKnown() && bodySize() == thePutSize)
			AsyncCall(91,5, this, BodyPipe::tellBodyProductionEnded);
		else
			AsyncCall(91,5, this, BodyPipe::tellBodyProducerAborted);
	}
}

void BodyPipe::tellMoreBodySpaceAvailable()
{
	if (theProducer != NULL)
		theProducer->noteMoreBodySpaceAvailable(*this);
}

void BodyPipe::tellBodyConsumerAborted()
{
	if (theProducer != NULL)
		theProducer->noteBodyConsumerAborted(*this);
}

void BodyPipe::tellMoreBodyDataAvailable()
{
	if (skipCCall())
		return;

	if (theConsumer != NULL)
		theConsumer->noteMoreBodyDataAvailable(*this);
	else
	if (mustAutoConsume && theBuf.hasContent())
		consume(theBuf.contentSize());
}

void BodyPipe::tellBodyProductionEnded()
{
	if (skipCCall())
		return;

	if (theConsumer != NULL)
		theConsumer->noteBodyProductionEnded(*this);
}

void BodyPipe::tellBodyProducerAborted()
{
	if (skipCCall())
		return;

	if (theConsumer != NULL)
		theConsumer->noteBodyProducerAborted(*this);
}

// skips calls destined for the previous consumer; see BodyPipe::clearConsumer
bool BodyPipe::skipCCall()
{
	assert(theCCallsPending > 0);
	--theCCallsPending;

	if (theCCallsToSkip <= 0)
		return false;

	--theCCallsToSkip;
	debugs(91,5, HERE << "skipped call");
	return true;
}

// a short temporary string describing buffer status for debugging
const char *BodyPipe::status() const
{
    static MemBuf buf;
    buf.reset();

    buf.append(" [", 2);

	buf.Printf("%"PRIu64"<=%"PRIu64, theGetSize, thePutSize);
    if (theBodySize >= 0)
        buf.Printf("<=%"PRId64, theBodySize);
	else
		buf.append("<=?", 3);

	buf.Printf(" %d+%d", (int)theBuf.contentSize(), (int)theBuf.spaceSize());

	buf.Printf(" pipe%p", this);
    if (theProducer)
        buf.Printf(" prod%p", theProducer);
    if (theConsumer)
        buf.Printf(" cons%p", theConsumer);

	if (mustAutoConsume)
		buf.append(" A", 2);
	if (isCheckedOut)
		buf.append(" L", 2); // Locked

    buf.append("]", 1);

    buf.terminate();

    return buf.content();
}


/* BodyPipeCheckout */

BodyPipeCheckout::BodyPipeCheckout(BodyPipe &aPipe): pipe(aPipe),
	buf(aPipe.checkOut()), offset(aPipe.consumedSize()),
	checkedOutSize(buf.contentSize()), checkedIn(false)
{
}

BodyPipeCheckout::~BodyPipeCheckout()
{
	if (!checkedIn)
		pipe.undoCheckOut(*this);
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

#include "config.h"
#if DELAY_POOLS
#include "ClientInfo.h"
#endif
#include "comm/IoCallback.h"
#include "comm/Write.h"
#include "fde.h"
#include "SquidTime.h"
#include "MemBuf.h"

void
Comm::Write(int fd, MemBuf *mb, AsyncCall::Pointer &callback)
{
    Comm::Write(fd, mb->buf, mb->size, callback, mb->freeFunc());
}

void
Comm::Write(int fd, const char *buf, int size, AsyncCall::Pointer &callback, FREE * free_func)
{
    debugs(5, 5, HERE << "FD " << fd << ": sz " << size << ": asynCall " << callback);

    /* Make sure we are open, not closing, and not writing */
    assert(fd_table[fd].flags.open);
    assert(!fd_table[fd].closing());
    Comm::IoCallback *ccb = COMMIO_FD_WRITECB(fd);
    assert(!ccb->active());

    fd_table[fd].writeStart = squid_curtime;
    /* Queue the write */
    ccb->setCallback(IOCB_WRITE, callback, (char *)buf, free_func, size);
    ccb->selectOrQueueWrite();
}

/** Write to FD.
 * This function is used by the lowest level of IO loop which only has access to FD numbers.
 * We have to use the comm iocb_table to map FD numbers to waiting data.
 * Once the write has been concluded we schedule the waiting call with success/fail results.
 */
void
Comm::HandleWrite(int fd, void *data)
{
    Comm::IoCallback *state = static_cast<Comm::IoCallback *>(data);
    int len = 0;
    int nleft;

    assert(state->fd == fd);

    PROF_start(commHandleWrite);
    debugs(5, 5, HERE << "FD " << state->fd << ": off " <<
           (long int) state->offset << ", sz " << (long int) state->size << ".");

    nleft = state->size - state->offset;

#if DELAY_POOLS
    ClientInfo * clientInfo=fd_table[fd].clientInfo;

    if (clientInfo && !clientInfo->writeLimitingActive)
        clientInfo = NULL; // we only care about quota limits here

    if (clientInfo) {
        assert(clientInfo->selectWaiting);
        clientInfo->selectWaiting = false;

        assert(clientInfo->hasQueue());
        assert(clientInfo->quotaPeekFd() == fd);
        clientInfo->quotaDequeue(); // we will write or requeue below

        if (nleft > 0) {
            const int quota = clientInfo->quotaForDequed();
            if (!quota) {  // if no write quota left, queue this fd
                state->quotaQueueReserv = clientInfo->quotaEnqueue(fd);
                clientInfo->kickQuotaQueue();
                PROF_stop(commHandleWrite);
                return;
            }

            const int nleft_corrected = min(nleft, quota);
            if (nleft != nleft_corrected) {
                debugs(5, 5, HERE << "FD " << fd << " writes only " <<
                       nleft_corrected << " out of " << nleft);
                nleft = nleft_corrected;
            }

        }
    }
#endif

    /* actually WRITE data */
    len = FD_WRITE_METHOD(fd, state->buf + state->offset, nleft);
    debugs(5, 5, HERE << "write() returns " << len);

#if DELAY_POOLS
    if (clientInfo) {
        if (len > 0) {
            /* we wrote data - drain them from bucket */
            clientInfo->bucketSize -= len;
            if (clientInfo->bucketSize < 0.0) {
                debugs(5,1, HERE << "drained too much"); // should not happen
                clientInfo->bucketSize = 0;
            }
        }

        // even if we wrote nothing, we were served; give others a chance
        clientInfo->kickQuotaQueue();
    }
#endif

    fd_bytes(fd, len, FD_WRITE);
    statCounter.syscalls.sock.writes++;
    // After each successful partial write,
    // reset fde::writeStart to the current time.
    fd_table[fd].writeStart = squid_curtime;

    if (len == 0) {
        /* Note we even call write if nleft == 0 */
        /* We're done */
        if (nleft != 0)
            debugs(5, DBG_IMPORTANT, "FD " << fd << " write failure: connection closed with " << nleft << " bytes remaining.");

        state->finish(nleft ? COMM_ERROR : COMM_OK, errno);
    } else if (len < 0) {
        /* An error */
        if (fd_table[fd].flags.socket_eof) {
            debugs(50, 2, HERE << "FD " << fd << " write failure: " << xstrerror() << ".");
            state->finish(nleft ? COMM_ERROR : COMM_OK, errno);
        } else if (ignoreErrno(errno)) {
            debugs(50, 9, HERE << "FD " << fd << " write failure: " << xstrerror() << ".");
            state->selectOrQueueWrite();
        } else {
            debugs(50, 2, HERE << "FD " << fd << " write failure: " << xstrerror() << ".");
            state->finish(nleft ? COMM_ERROR : COMM_OK, errno);
        }
    } else {
        /* A successful write, continue */
        state->offset += len;

        if (state->offset < state->size) {
            /* Not done, reinstall the write handler and write some more */
            state->selectOrQueueWrite();
        } else {
            state->finish(nleft ? COMM_OK : COMM_ERROR, errno);
        }
    }

    PROF_stop(commHandleWrite);
}

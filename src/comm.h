#ifndef __COMM_H__
#define __COMM_H__

#include "StoreIOBuffer.h"

typedef void IOFCB(int fd, StoreIOBuffer recievedData, comm_err_t flag, int xerrno, void *data);
typedef void IOWCB(int fd, char *data, size_t len, comm_err_t flag, int xerrno, void *data);
/* fill sb with up to length data from fd */
extern void comm_fill_immediate(int fd, StoreIOBuffer sb, IOFCB *callback, void *data);

class ConnectionDetail;
typedef void IOACB(int fd, int nfd, ConnectionDetail *details, comm_err_t flag, int xerrno, void *data);
extern void comm_accept(int fd, IOACB *handler, void *handler_data);

extern int comm_has_pending_read_callback(int fd);
extern bool comm_has_pending_read(int fd);
extern void comm_read_cancel(int fd, IOCB *callback, void *data);
extern void fdc_open(int fd, unsigned int type, char *desc);
extern int comm_udp_recvfrom(int fd, void *buf, size_t len, int flags,
  struct sockaddr *from, socklen_t *fromlen);
extern int comm_udp_recv(int fd, void *buf, size_t len, int flags);
extern ssize_t comm_udp_send(int s, const void *buf, size_t len, int flags);
extern void comm_accept_setcheckperiod(int fd, int mdelay);

extern void comm_write(int s, const char *buf, size_t len, IOWCB *callback, void *callback_data);

/* Where should this belong? */
class CommIO {
public:
  static inline void NotifyIOCompleted();
  static void ResetNotifications();
  static void Initialise();
private:
  static void NULLFDHandler(int, void *);
  static void FlushPipe();
  static bool Initialised;
  static bool DoneSignalled;
  static int DoneFD;
  static int DoneReadFD;
};

/* Inline code. TODO: make structued approach to inlining */
void
CommIO::NotifyIOCompleted() {
    if (!Initialised)
	Initialise();
    if (!DoneSignalled) {
	DoneSignalled = true;
	write(DoneFD, "!", 1);
    }
};

#endif

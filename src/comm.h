#ifndef __COMM_H__
#define __COMM_H__

#include "StoreIOBuffer.h"

typedef void IOFCB(int fd, StoreIOBuffer recievedData, comm_err_t flag, int xerrno, void *data);
/* fill sb with up to length data from fd */
extern void comm_fill_immediate(int fd, StoreIOBuffer sb, IOFCB *callback, void *data);

extern int comm_has_pending_read_callback(int fd);
extern int comm_has_pending_read(int fd);
extern void comm_read_cancel(int fd, IOCB *callback, void *data);
extern void fdc_open(int fd, unsigned int type, char *desc);

#endif

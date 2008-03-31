#ifndef __COMMIO_H__
#define __COMMIO_H__

#include "fde.h"

class CommIO
{

public:
    static inline void NotifyIOCompleted();
    static void ResetNotifications();
    static void Initialise();
    static void NotifyIOClose();

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
CommIO::NotifyIOCompleted()
{
    if (!Initialised)
        Initialise();

    if (!DoneSignalled) {
        DoneSignalled = true;
        FD_WRITE_METHOD(DoneFD, "!", 1);
    }
};

#endif

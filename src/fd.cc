#include "squid.h"

static void fdUpdateBiggest _PARAMS((int fd, unsigned int status));

static void
fdUpdateBiggest(int fd, unsigned int status)
{
    if (fd < Biggest_FD)
	return;
    assert(fd < Squid_MaxFD);
    if (fd > Biggest_FD) {
	assert(status == FD_OPEN);
	Biggest_FD = fd;
	return;
    }
    /* if we are here, then fd == Biggest_FD */
    assert(status == FD_CLOSE);
    while (fd_table[Biggest_FD].open != FD_OPEN)
	Biggest_FD--;
}

void
fd_close(int fd)
{
    FD_ENTRY *fde = &fd_table[fd];
    if (fde->type == FD_FILE) {
	assert(fde->read_handler == NULL);
	assert(fde->write_handler == NULL);
    }
    fdUpdateBiggest(fd, fde->open = FD_CLOSE);
    memset(fde, '\0', sizeof(FD_ENTRY));
    fde->timeout = 0;
}

void
fd_open(int fd, unsigned int type, const char *desc)
{
    FD_ENTRY *fde = &fd_table[fd];
    assert(fde->open == 0);
    fde->type = type;
    fdUpdateBiggest(fd, fde->open = FD_OPEN);
    if (desc)
	xstrncpy(fde->desc, desc, FD_DESC_SZ);
}

void
fd_note(int fd, const char *s)
{
    FD_ENTRY *fde = &fd_table[fd];
    xstrncpy(fde->desc, s, FD_DESC_SZ);
}

void
fd_bytes(int fd, int len, unsigned int type)
{
    FD_ENTRY *fde = &fd_table[fd];
    if (len < 0)
	return;
    assert(type == FD_READ || type == FD_WRITE);
    if (type == FD_READ)
	fde->bytes_read += len;
    else
	fde->bytes_written += len;
}

void
fdFreeMemory(void)
{
    safe_free(fd_table);
}

void
fdDumpOpen(void)
{
    int i;
    FD_ENTRY *fde;
    for (i = 0; i < Squid_MaxFD; i++) {
	fde = &fd_table[i];
	if (!fde->open)
	    continue;
	if (i == fileno(debug_log))
	    continue;
	debug(5, 1) ("Open FD %4d %s\n", i, fde->desc);
    }
}

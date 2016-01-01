/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PACKER_H
#define SQUID_PACKER_H

/* see Packer.cc for description */
class Packer;

/* a common objPackInto interface; used by debugObj */
typedef void (*ObjPackMethod) (void *obj, Packer * p);

/* append/vprintf's for Packer */
typedef void (*append_f) (void *, const char *buf, int size);
typedef void (*vprintf_f) (void *, const char *fmt, va_list args);

class Packer
{

public:
    /* protected, use interface functions instead */
    append_f append;
    vprintf_f packer_vprintf;
    void *real_handler;     /* first parameter to real append and vprintf */
};

void packerClean(Packer * p);
void packerAppend(Packer * p, const char *buf, int size);
void packerPrintf(Packer * p, const char *fmt,...) PRINTF_FORMAT_ARG2;

#endif /* SQUID_PACKER_H */


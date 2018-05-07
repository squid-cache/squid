/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 52    URN Parsing */

#ifndef SQUID_URN_H_
#define SQUID_URN_H_

class AccessLogEntry;
class HttpRequest;
class StoreEntry;

template <class C> class RefCount;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;

void urnStart(HttpRequest *, StoreEntry *, const AccessLogEntryPointer &ale);

#endif /* SQUID_URN_H_ */


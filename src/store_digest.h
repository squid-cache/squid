/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 71    Store Digest Manager */

#ifndef SQUID_STORE_DIGEST_H_
#define SQUID_STORE_DIGEST_H_

class StoreEntry;

void storeDigestInit(void);
void storeDigestNoteStoreReady(void);
void storeDigestDel(const StoreEntry * entry);
void storeDigestReport(StoreEntry *);

#endif /* SQUID_STORE_DIGEST_H_ */


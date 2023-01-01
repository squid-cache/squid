/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SBUFEXTRAS_H
#define SQUID_SBUFEXTRAS_H

#include "mgr/Action.h"
#include "sbuf/SBuf.h"
#include "StatHist.h"

class StoreEntry;

/// SBuf stats for cachemgr
class SBufStatsAction: public Mgr::Action
{
public:
    /// Mgr::ClassActionCreationHandler for Mgr::RegisterAction()
    static Pointer Create(const Mgr::CommandPointer &cmd);
    static void RegisterWithCacheManager(void);

protected:
    explicit SBufStatsAction(const Mgr::CommandPointer &cmd);
    /* Mgr::Action API */
    void collect() override;
    void dump(StoreEntry* entry) override;

private:
    /* Mgr::Action API */
    void add(const Mgr::Action& action) override;
    void pack(Ipc::TypedMsgHdr& msg) const override;
    void unpack(const Ipc::TypedMsgHdr& msg) override;

    SBufStats sbdata;
    MemBlobStats mbdata;
    StatHist sbsizesatdestruct;
    StatHist mbsizesatdestruct;
};

#endif /* SQUID_SBUFSTATSACTION_H */


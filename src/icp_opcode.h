/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_ICP_OPCODE_H
#define _SQUID_ICP_OPCODE_H

/// \ingroup ServerProtocolICPAPI
enum icp_opcode {
    enumBegin_ = 0,
    ICP_INVALID = enumBegin_,
    ICP_QUERY,
    ICP_HIT,
    ICP_MISS,
    ICP_ERR,
    ICP_SEND,
    ICP_SENDA,
    ICP_DATABEG,
    ICP_DATA,
    ICP_DATAEND,
    ICP_SECHO,
    ICP_DECHO,
    ICP_NOTIFY,
    ICP_INVALIDATE,
    ICP_DELETE,
    ICP_UNUSED15,
    ICP_UNUSED16,
    ICP_UNUSED17,
    ICP_UNUSED18,
    ICP_UNUSED19,
    ICP_UNUSED20,
    ICP_MISS_NOFETCH,
    ICP_DENIED,
    ICP_HIT_OBJ,
    ICP_END,
    enumEnd_ = ICP_END // We misuse ICP_END in stats. Do not do this elsewhere.
};

extern const char *icp_opcode_str[];

#endif /* _SQUID_ICP_OPCODE_H */


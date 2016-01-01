/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HELPER_RESULTCODE_H
#define _SQUID_SRC_HELPER_RESULTCODE_H

namespace Helper
{

/// enumeration value for the helper response 'result' field.
enum ResultCode {
    Unknown,      // no result code received, or unknown result code
    Okay,         // "OK" indicating success/positive result
    Error,        // "ERR" indicating success/negative result
    BrokenHelper, // "BH" indicating failure due to helper internal problems.

    // result codes for backward compatibility with NTLM/Negotiate
    // TODO: migrate to a variant of the above results with kv-pair parameters
    TT
};

} // namespace Helper

#endif /* _SQUID_SRC_HELPER_RESULTCODE_H */


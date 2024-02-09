/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SWAP_LOG_OP_H
#define SQUID_SRC_SWAP_LOG_OP_H

typedef enum {
    SWAP_LOG_NOP,
    SWAP_LOG_ADD,
    SWAP_LOG_DEL,
    SWAP_LOG_VERSION,
    SWAP_LOG_MAX
} swap_log_op;

extern const char *swap_log_op_str[];

#endif /* SQUID_SRC_SWAP_LOG_OP_H */


/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MESSAGESIZES_H
#define SQUID_SRC_MESSAGESIZES_H

/**
 * Counters used to collate the traffic size measurements
 * for a transaction message.
 */
class MessageSizes
{
public:
    /// size of message header block (if any)
    /// including message Request-Line or Start-Line.
    uint64_t header = 0;

    /// total size of payload block(s) excluding transfer encoding overheads
    uint64_t payloadData = 0;

    /// total message size
    uint64_t messageTotal() const {return header + payloadData;}
};

#endif /* SQUID_SRC_MESSAGESIZES_H */


#ifndef SQUID_SRC_MESSAGESIZES_H
#define SQUID_SRC_MESSAGESIZES_H

/**
 * Counters used to collate the traffic size measurements
 * for a transaction message.
 */
class MessageSizes
{
public:
    MessageSizes() : header(0), payloadData(0) {}

    /// size of message header block (if any)
    /// including message Request-Line or Start-Line.
    uint64_t header;

    /// total size of payload block(s) excluding transfer encoding overheads
    uint64_t payloadData;

    /// total message size
    uint64_t messageTotal() const {return header + payloadData;}
};

#endif  /* SQUID_SRC_MESSAGESIZES_H */

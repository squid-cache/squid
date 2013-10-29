#ifndef SQUID_SRC_MESSAGECOUNTERS_H
#define SQUID_SRC_MESSAGECOUNTERS_H

/**
 * Counters used to collate the traffic size measurements
 * for a transaction message.
 */
class MessageCounters
{
public:
    MessageCounters() : headerSz(0), payloadDataSz(0), payloadTeSz(0) {}

    /// size of message header block (if any)
    uint64_t headerSz;

    /// total size of payload block(s) excluding transfer encoding overheads
    uint64_t payloadDataSz;

    /// total size of extra bytes added by transfer encoding
    uint64_t payloadTeSz;

    // total message size
    uint64_t total() const {return headerSz + payloadDataSz + payloadTeSz;}

    /// total payload size including transfer encoding overheads
    uint64_t payloadTotal() const {return payloadDataSz + payloadTeSz;}
};

#endif  /* SQUID_SRC_MESSAGECOUNTERS_H */

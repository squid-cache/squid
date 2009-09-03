#ifndef SQUID_ADAPT_HISTORY_H
#define SQUID_ADAPT_HISTORY_H

#include "RefCount.h"
#include "Array.h"
#include "SquidString.h"

namespace Adaptation
{


/// collects information about adaptations related to a master transaction
class History: public RefCountable
{
public:
    typedef RefCount<Adaptation::History> Pointer;

    History();

    /// record the start of a xact, return xact history ID
    int recordXactStart(const String &serviceId, const timeval &when, bool retrying);

    /// record the end of a xact identified by its history ID
    void recordXactFinish(int hid);

    /// dump individual xaction times to a string
    void allLogString(const char *serviceId, String &buf);

    /// dump xaction times, merging retried and retry times together
    void sumLogString(const char *serviceId, String &buf);

    /// sets or resets a cross-transactional database record
    void updateXxRecord(const char *name, const String &value);

    /// returns true and fills the record fields iff there is a db record
    bool getXxRecord(String &name, String &value) const;

    /// sets or resets next services for the Adaptation::Iterator to notice
    void updateNextServices(const String &services);

    /// returns true, fills the value, and resets iff next services were set
    bool extractNextServices(String &value);

private:
    /// single Xaction stats (i.e., a historical record entry)
    class Entry
    {
    public:
        Entry(const String &serviceId, const timeval &when);
        Entry(); // required by Vector<>

        void stop(); ///< updates stats on transaction end
        int rptm(); ///< returns response time [msec], calculates it if needed

        String service; ///< adaptation service ID
        timeval start; ///< when the xaction was started

    private:
        int theRptm; ///< calculated and cached response time value in msec

    public:
        bool retried; ///< whether the xaction was replaced by another
    };

    typedef Vector<Entry> Entries;
    Entries theEntries; ///< historical record, in the order of xact starts

    // theXx* will become a map<string,string>, but we only support one record
    String theXxName; ///< name part of the cross-transactional database record
    String theXxValue; ///< value part of the cross-xactional database record

    String theNextServices; ///< services Adaptation::Iterator must use next
};

} // namespace Adaptation

#endif

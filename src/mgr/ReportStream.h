/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID__SRC_MGR_REPORTSTREAM_H
#define SQUID__SRC_MGR_REPORTSTREAM_H

#include "base/PackableStream.h"
#include "mgr/forward.h"

namespace Mgr
{

/// interface for Cache Manager report formatters
class ReportStream : public RefCountable, public PackableStream
{
public:
    ReportStream(Packable &buf) : PackableStream(buf) {}

    virtual ReportStream &reportStart(ReportStream &os) { return os; }
    virtual ReportStream &reportEnd(ReportStream &os) { os << std::endl; return os; }

    virtual ReportStream &tableStart(ReportStream &os) { return os; }
    virtual ReportStream &tableEnd(ReportStream &os) { firstRowDone = false; firstCellDone = false; return os; }
    virtual ReportStream &tableRowStart(ReportStream &os) { firstRowDone = true; return os; }
    virtual ReportStream &tableRowEnd(ReportStream &os) { firstCellDone = false; os << std::endl; return os; }
    virtual ReportStream &tableCellStart(ReportStream &os) { firstCellDone = true; return os; }
    virtual ReportStream &tableCellEnd(ReportStream &os) { return os; }
protected:
    bool firstRowDone = false;
    bool firstCellDone = false;
};

/// std::ostream with text/plain formatting for Cache Manager reports
class ReportPlain : public ReportStream
{
public:
    ReportPlain(Packable &buf) : ReportStream(buf) {}

    /* Mgr::ReportStream API */
    ReportStream &tableRowStart(ReportStream &os) override {
        os << ' ';
        return ReportStream::tableRowStart(os);
    }
    ReportStream &tableCellStart(ReportStream &os) override {
        if (firstCellDone)
            os << '\t';
        return ReportStream::tableCellStart(os);
    }
};

/// std::ostream with text/yaml formatting for Cache Manager reports
class ReportYaml : public ReportStream
{
public:
    ReportYaml(Packable &buf) : ReportStream(buf) {}

    /* Mgr::ReportStream API */
    ReportStream &tableRowStart(ReportStream &os) override {
        os << " - [";
        return ReportStream::tableRowStart(os);
    }
    ReportStream &tableRowEnd(ReportStream &os) override {
        os << ']';
        return ReportStream::tableRowEnd(os);
    }
    ReportStream &tableCellStart(ReportStream &os) override {
        if (firstCellDone)
            os << ", ";
        return ReportStream::tableCellStart(os);
    }
};

} // namespace Mgr

#define MGR_IOMANIP(SYMBOL,METHOD) std::ostream &SYMBOL(std::ostream &os) { \
    if (auto s = dynamic_cast<Mgr::ReportStream*>(&os)) s->METHOD(*s); \
    return os; }

inline MGR_IOMANIP(MgrReportStart, reportStart)
inline MGR_IOMANIP(MgrReportEnd, reportEnd)
inline MGR_IOMANIP(MgrTableStart, tableStart)
inline MGR_IOMANIP(MgrTableEnd, tableEnd)
inline MGR_IOMANIP(MgrTableRowStart, tableRowStart)
inline MGR_IOMANIP(MgrTableRowEnd, tableRowEnd)
inline MGR_IOMANIP(MgrTableCellStart, tableCellStart)
inline MGR_IOMANIP(MgrTableCellEnd, tableCellEnd)

#endif /* SQUID__SRC_MGR_REPORTSTREAM_H */

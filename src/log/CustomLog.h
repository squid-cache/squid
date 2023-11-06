/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CUSTOMLOG_H_
#define SQUID_CUSTOMLOG_H_

#include "log/FormattedLog.h"

// TODO: Replace with std::list<FormattedLog> or its wrapper.
/// all same-directive transaction logging rules
/// (e.g., all access_log rules or all icap_log rules)
class CustomLog: public FormattedLog
{
public:
    /// next _log line (if any); maintained by cache_cf.cc
    CustomLog *next = nullptr;
};

#endif /* SQUID_CUSTOMLOG_H_ */


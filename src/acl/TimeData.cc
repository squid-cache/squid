/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/TimeData.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "wordlist.h"

ACLTimeData::ACLTimeData () : weekbits (0), start (0), stop (0), next (NULL) {}

ACLTimeData::ACLTimeData(ACLTimeData const &old) : weekbits(old.weekbits), start (old.start), stop (old.stop), next (NULL)
{
    if (old.next)
        next = (ACLTimeData *)old.next->clone();
}

ACLTimeData&
ACLTimeData::operator=(ACLTimeData const &old)
{
    weekbits = old.weekbits;
    start = old.start;
    stop = old.stop;
    next = NULL;

    if (old.next)
        next = (ACLTimeData *)old.next->clone();

    return *this;
}

ACLTimeData::~ACLTimeData()
{
    if (next)
        delete next;
}

bool
ACLTimeData::match(time_t when)
{
    static time_t last_when = 0;

    static struct tm tm;
    time_t t;

    if (when != last_when) {
        last_when = when;
        memcpy(&tm, localtime(&when), sizeof(struct tm));
    }

    t = (time_t) (tm.tm_hour * 60 + tm.tm_min);
    ACLTimeData *data = this;

    while (data) {
        debugs(28, 3, "aclMatchTime: checking " << t  << " in " <<
               data->start  << "-" << data->stop  << ", weekbits=" <<
               std::hex << data->weekbits);

        if (t >= data->start && t <= data->stop && (data->weekbits & (1 << tm.tm_wday)))
            return 1;

        data = data->next;
    }

    return 0;
}

SBufList
ACLTimeData::dump() const
{
    SBufList sl;
    const ACLTimeData *t = this;

    while (t != NULL) {
        SBuf s;
        s.Printf("%c%c%c%c%c%c%c %02d:%02d-%02d:%02d",
                 t->weekbits & ACL_SUNDAY ? 'S' : '-',
                 t->weekbits & ACL_MONDAY ? 'M' : '-',
                 t->weekbits & ACL_TUESDAY ? 'T' : '-',
                 t->weekbits & ACL_WEDNESDAY ? 'W' : '-',
                 t->weekbits & ACL_THURSDAY ? 'H' : '-',
                 t->weekbits & ACL_FRIDAY ? 'F' : '-',
                 t->weekbits & ACL_SATURDAY ? 'A' : '-',
                 t->start / 60, t->start % 60, t->stop / 60, t->stop % 60);
        sl.push_back(s);
        t = t->next;
    }

    return sl;
}

void
ACLTimeData::parse()
{
    ACLTimeData **Tail;
    long parsed_weekbits = 0;

    for (Tail = &next; *Tail; Tail = &((*Tail)->next));
    ACLTimeData *q = NULL;

    int h1, m1, h2, m2;

    while (char *t = ConfigParser::strtokFile()) {
        if (*t < '0' || *t > '9') {
            /* assume its day-of-week spec */

            while (*t) {
                switch (*t++) {

                case 'S':
                    parsed_weekbits |= ACL_SUNDAY;
                    break;

                case 'M':
                    parsed_weekbits |= ACL_MONDAY;
                    break;

                case 'T':
                    parsed_weekbits |= ACL_TUESDAY;
                    break;

                case 'W':
                    parsed_weekbits |= ACL_WEDNESDAY;
                    break;

                case 'H':
                    parsed_weekbits |= ACL_THURSDAY;
                    break;

                case 'F':
                    parsed_weekbits |= ACL_FRIDAY;
                    break;

                case 'A':
                    parsed_weekbits |= ACL_SATURDAY;
                    break;

                case 'D':
                    parsed_weekbits |= ACL_WEEKDAYS;
                    break;

                case '-':
                    /* ignore placeholder */
                    break;

                default:
                    debugs(28, DBG_CRITICAL, "" << cfg_filename << " line " << config_lineno <<
                           ": " << config_input_line);
                    debugs(28, DBG_CRITICAL, "aclParseTimeSpec: Bad Day '" << *t << "'" );
                    break;
                }
            }
        } else {
            /* assume its time-of-day spec */

            if ((sscanf(t, "%d:%d-%d:%d", &h1, &m1, &h2, &m2) < 4) || (!((h1 >= 0 && h1 < 24) && ((h2 >= 0 && h2 < 24) || (h2 == 24 && m2 == 0)) && (m1 >= 0 && m1 < 60) && (m2 >= 0 && m2 < 60)))) {
                debugs(28, DBG_CRITICAL, "aclParseTimeSpec: Bad time range '" << t << "'");
                self_destruct();

                if (q != this)
                    delete q;

                return;
            }

            if ((parsed_weekbits == 0) && (start == 0) && (stop == 0))
                q = this;
            else
                q = new ACLTimeData;

            q->start = h1 * 60 + m1;

            q->stop = h2 * 60 + m2;

            q->weekbits = parsed_weekbits;

            parsed_weekbits = 0;

            if (q->start > q->stop) {
                debugs(28, DBG_CRITICAL, "aclParseTimeSpec: Reversed time range");
                self_destruct();

                if (q != this)
                    delete q;

                return;
            }

            if (q->weekbits == 0)
                q->weekbits = ACL_ALLWEEK;

            if (q != this) {
                *(Tail) = q;
                Tail = &q->next;
            }
        }
    }

    if (parsed_weekbits) {

        q = new ACLTimeData;

        q->start = 0 * 60 + 0;

        q->stop =  24 * 60 + 0;

        q->weekbits = parsed_weekbits;

        *(Tail) = q;
        Tail = &q->next;
    }
}

bool
ACLTimeData::empty() const
{
    return false;
}

ACLData<time_t> *
ACLTimeData::clone() const
{
    return new ACLTimeData(*this);
}


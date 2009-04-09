/*
 * $Id$
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "acl/TimeData.h"
#include "acl/Checklist.h"
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

        xmemcpy(&tm, localtime(&when), sizeof(struct tm));
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

wordlist *
ACLTimeData::dump()
{
    wordlist *W = NULL;
    char buf[128];
    ACLTimeData *t = this;

    while (t != NULL) {
        snprintf(buf, sizeof(buf), "%c%c%c%c%c%c%c %02d:%02d-%02d:%02d",
                 t->weekbits & ACL_SUNDAY ? 'S' : '-',
                 t->weekbits & ACL_MONDAY ? 'M' : '-',
                 t->weekbits & ACL_TUESDAY ? 'T' : '-',
                 t->weekbits & ACL_WEDNESDAY ? 'W' : '-',
                 t->weekbits & ACL_THURSDAY ? 'H' : '-',
                 t->weekbits & ACL_FRIDAY ? 'F' : '-',
                 t->weekbits & ACL_SATURDAY ? 'A' : '-',
                 t->start / 60, t->start % 60, t->stop / 60, t->stop % 60);
        wordlistAdd(&W, buf);
        t = t->next;
    }

    return W;
}

void
ACLTimeData::parse()
{
    ACLTimeData **Tail;
    long weekbits = 0;

    for (Tail = &next; *Tail; Tail = &((*Tail)->next));
    ACLTimeData *q = NULL;

    int h1, m1, h2, m2;

    char *t = NULL;

    while ((t = strtokFile())) {
        if (*t < '0' || *t > '9') {
            /* assume its day-of-week spec */

            while (*t) {
                switch (*t++) {

                case 'S':
                    weekbits |= ACL_SUNDAY;
                    break;

                case 'M':
                    weekbits |= ACL_MONDAY;
                    break;

                case 'T':
                    weekbits |= ACL_TUESDAY;
                    break;

                case 'W':
                    weekbits |= ACL_WEDNESDAY;
                    break;

                case 'H':
                    weekbits |= ACL_THURSDAY;
                    break;

                case 'F':
                    weekbits |= ACL_FRIDAY;
                    break;

                case 'A':
                    weekbits |= ACL_SATURDAY;
                    break;

                case 'D':
                    weekbits |= ACL_WEEKDAYS;
                    break;

                case '-':
                    /* ignore placeholder */
                    break;

                default:
                    debugs(28, 0, "" << cfg_filename << " line " << config_lineno <<
                           ": " << config_input_line);
                    debugs(28, 0, "aclParseTimeSpec: Bad Day '" << *t << "'" );
                    break;
                }
            }
        } else {
            /* assume its time-of-day spec */

            if ((sscanf(t, "%d:%d-%d:%d", &h1, &m1, &h2, &m2) < 4) || (!((h1 >= 0 && h1 < 24) && ((h2 >= 0 && h2 < 24) || (h2 == 24 && m2 == 0)) && (m1 >= 0 && m1 < 60) && (m2 >= 0 && m2 < 60)))) {
                debugs(28, 0, "aclParseTimeSpec: Bad time range '" << t << "'");
                self_destruct();

                if (q != this)
                    delete q;

                return;
            }

            if ((weekbits == 0) && (start == 0) && (stop == 0))
                q = this;
            else
                q = new ACLTimeData;

            q->start = h1 * 60 + m1;

            q->stop = h2 * 60 + m2;

            q->weekbits = weekbits;

            weekbits = 0;

            if (q->start > q->stop) {
                debugs(28, 0, "aclParseTimeSpec: Reversed time range");
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

    if (weekbits) {

        if ((weekbits == 0) && (start == 0) && (stop == 0))
            q = this;
        else
            q = new ACLTimeData;

        q->start = 0 * 60 + 0;

        q->stop =  24 * 60 + 0;

        q->weekbits = weekbits;

        if (q != this) {
            *(Tail) = q;
            Tail = &q->next;
        }
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

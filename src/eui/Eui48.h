/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_EUI_EUI48_H
#define _SQUID_EUI_EUI48_H

#if USE_SQUID_EUI

/* EUI-48 is 6 bytes. */
#define SZ_EUI48_BUF 6

namespace Ip
{
class Address;
};

#include <cstring>

namespace Eui
{

class Eui48
{

public:
    Eui48() { clear(); }
    bool operator== (const Eui48 &t) const { return memcmp(eui, t.eui, SZ_EUI48_BUF) == 0; }
    bool operator< (const Eui48 &t) const { return memcmp(eui, t.eui, SZ_EUI48_BUF) < 0; }

    const unsigned char *get(void);

    bool set(const char *src, const int len) {
        if (len > SZ_EUI48_BUF) return false;
        if (len < SZ_EUI48_BUF) clear();
        memcpy(eui, src, len);
        return true;
    }

    void clear() { memset(eui, 0, SZ_EUI48_BUF); }

    /**
     * Decode an ascii representation of an EUI-48 ethernet address.
     *
     * \param asc   ASCII representation of an ethernet (MAC) address
     * \param eth   Binary representation of the ethernet address
     * \retval false        Conversion to binary failed. Invalid address
     * \retval true         Conversion completed successfully
     */
    bool decode(const char *asc);

    /**
     * Encode an ascii representation (asc) of an EUI-48 ethernet address.
     *
     * \param buf   Buffer to receive ASCII representation of an ethernet (MAC) address
     * \param len   Length of the buffer space available. Must be >= SZ_EUI48_BUF bytes or the encode will fail.
     * \param eui   Binary representation of the ethernet address
     * \retval false        Conversion to ASCII failed.
     * \retval true         Conversion completed successfully.
     */
    bool encode(char *buf, const int len) const;

    // lookup an EUI-48 / MAC address via ARP
    bool lookup(const Ip::Address &c);

private:
    unsigned char eui[SZ_EUI48_BUF];
};

} // namespace Eui

#endif /* USE_SQUID_EUI */
#endif /* _SQUID_EUI_EUI48_H */


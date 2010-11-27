#ifndef _SQUID_EUI_EUI48_H
#define _SQUID_EUI_EUI48_H

#if USE_SQUID_EUI

/* EUI-48 is 6 bytes. */
#define SZ_EUI48_BUF 6

namespace Ip
{
class Address;
};

#if HAVE_CSTRING
#include <cstring>
#endif

/* memcpy and friends */
#if HAVE_STRING_H
#include <string.h>
#endif

namespace Eui
{

class Eui48
{

public:
    Eui48() { clear(); };
    Eui48(const Eui48 &t) { memcpy(this, &t, sizeof(Eui48)); };
    ~Eui48() {};

    const unsigned char *get(void);

    bool set(const char *src, const int len) {
        if (len > SZ_EUI48_BUF) return false;
        if (len < SZ_EUI48_BUF) clear();
        memcpy(eui, src, len);
        return true;
    };

    void clear() { memset(eui, 0, SZ_EUI48_BUF); };

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
    bool encode(char *buf, const int len);

    // lookup an EUI-48 / MAC address via ARP
    bool lookup(const Ip::Address &c);

private:
    unsigned char eui[SZ_EUI48_BUF];
};

} // namespace Eui

#endif /* USE_SQUID_EUI */
#endif /* _SQUID_EUI_EUI48_H */

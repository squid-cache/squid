/*
 * Compatibility-layer for CMSG_
 */

#ifndef CMSG_H_
#define CMSG_H_

/* mostly windows-specific */
#ifndef CMSG_SPACE
typedef struct  {
        unsigned int    cmsg_len;
        int  cmsg_level;
        int     cmsg_type;
        /* followed by UCHAR cmsg_data[]; */
} cmsghdr;

/* lifted off https://metacpan.org/source/SAMPO/Socket-PassAccessRights-0.03/passfd.c */
#ifndef CMSG_DATA
# define CMSG_DATA(cmsg) ((cmsg)->cmsg_data)
#endif

#ifndef CMSG_NXTHDR
# define CMSG_NXTHDR(mhdr, cmsg) __cmsg_nxthdr (mhdr, cmsg)
#endif

#ifndef CMSG_FIRSTHDR
# define CMSG_FIRSTHDR(mhdr) \
  ((size_t) (mhdr)->msg_controllen >= sizeof ( cmsghdr)        \
   ? ( cmsghdr *) (mhdr)->msg_control : ( cmsghdr *) NULL)
#endif

#ifndef CMSG_ALIGN
# define CMSG_ALIGN(len) (((len) + sizeof (size_t) - 1) \
             & ~(sizeof (size_t) - 1))
#endif

#ifndef CMSG_SPACE
# define CMSG_SPACE(len) (CMSG_ALIGN (len) \
             + CMSG_ALIGN (sizeof ( cmsghdr)))
#endif

#ifndef CMSG_LEN
# define CMSG_LEN(len)   (CMSG_ALIGN (sizeof ( cmsghdr)) + (len))
#endif

struct msghdr {
    void *msg_name;             /* Address to send to/receive from.  */
    socklen_t msg_namelen;      /* Length of address data.  */

    struct iovec *msg_iov;      /* Vector of data to send/receive into.  */
    size_t msg_iovlen;          /* Number of elements in the vector.  */

    void *msg_control;          /* Ancillary data (eg BSD filedesc passing). */
    size_t msg_controllen;      /* Ancillary data buffer length.
                                   !! The type should be socklen_t but the
                                   definition of the kernel is incompatible
                                   with this.  */

    int msg_flags;              /* Flags on received message.  */
};


struct iovec {

};
struct sockaddr_un {
        char sun_path[256];   /* pathname */
};

#endif /* CMSG_SPACE */

#endif /* CMSG_H_ */

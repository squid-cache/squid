
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define OR(A,B) (A ? A : B)

#define ACL_NAME_SZ 32
#define BROWSERNAMELEN 128

#define ACL_SUNDAY	0x01
#define ACL_MONDAY	0x02
#define ACL_TUESDAY	0x04
#define ACL_WEDNESDAY	0x08
#define ACL_THURSDAY	0x10
#define ACL_FRIDAY	0x20
#define ACL_SATURDAY	0x40
#define ACL_ALLWEEK	0x7F
#define ACL_WEEKDAYS	0x3E

#define DefaultDnsChildrenMax		32	/* 32 processes */
#define DefaultRedirectChildrenMax	32	/* 32 processes */
#define MAXHTTPPORTS			12

#define COMM_OK		  (0)
#define COMM_ERROR	 (-1)
#define COMM_NO_HANDLER	 (-2)
#define COMM_NOMESSAGE	 (-3)
#define COMM_TIMEOUT	 (-4)
#define COMM_SHUTDOWN	 (-5)
#define COMM_INPROGRESS  (-6)
#define COMM_ERR_CONNECT (-7)
#define COMM_ERR_DNS     (-8)

#define COMM_NONBLOCKING  (0x1)
#define COMM_NOCLOEXEC	  (0x8)

/* Select types. */
#define COMM_SELECT_READ   (0x1)
#define COMM_SELECT_WRITE  (0x2)
#define MAX_DEBUG_SECTIONS 100

#ifdef HAVE_SYSLOG
#define debug(SECTION, LEVEL) \
        ((_db_level = (LEVEL)) > debugLevels[SECTION]) ? (void) 0 : _db_print
#else
#define debug(SECTION, LEVEL) \
        ((LEVEL) > debugLevels[SECTION]) ? (void) 0 : _db_print
#endif
#define safe_free(x)	if (x) { xxfree(x); x = NULL; }

#define DISK_OK                   (0)
#define DISK_ERROR               (-1)
#define DISK_EOF                 (-2)
#define DISK_FILE_NOT_FOUND      (-5)
#define DISK_NO_SPACE_LEFT       (-6)

#define DNS_FLAG_ALIVE          0x01
#define DNS_FLAG_BUSY           0x02
#define DNS_FLAG_CLOSING        0x04

#define DNS_INBUF_SZ 4096

#define FD_CLOSE_REQUEST	0x02
#define FD_WRITE_DAEMON		0x04
#define FD_WRITE_PENDING	0x08

#define FD_DESC_SZ		64

#define FQDN_BLOCKING_LOOKUP	0x01
#define FQDN_LOOKUP_IF_MISS	0x02
#define FQDN_LOCK_ENTRY		0x04

#define FQDN_MAX_NAMES 5

#define FQDNCACHE_AV_FACTOR 1000

/*  
 *  Here are some good prime number choices.  It's important not to
 *  choose a prime number that is too close to exact powers of 2.
 */
#if 0
#undef  HASH_SIZE 103		/* prime number < 128 */
#undef  HASH_SIZE 229		/* prime number < 256 */
#undef  HASH_SIZE 467		/* prime number < 512 */
#undef  HASH_SIZE 977		/* prime number < 1024 */
#undef  HASH_SIZE 1979		/* prime number < 2048 */
#undef  HASH_SIZE 4019		/* prime number < 4096 */
#undef  HASH_SIZE 6037		/* prime number < 6144 */
#undef  HASH_SIZE 7951		/* prime number < 8192 */
#undef  HASH_SIZE 12149		/* prime number < 12288 */
#undef  HASH_SIZE 16231		/* prime number < 16384 */
#undef  HASH_SIZE 33493		/* prime number < 32768 */
#undef  HASH_SIZE 65357		/* prime number < 65536 */
#endif

#define  HASH_SIZE 7951		/* prime number < 8192 */

#define HTTP_REPLY_FIELD_SZ 128

#define BUF_TYPE_8K 	1
#define BUF_TYPE_MALLOC 2

#define ANONYMIZER_NONE		0
#define ANONYMIZER_STANDARD	1
#define ANONYMIZER_PARANOID	2

#define ERR_MIN ERR_READ_TIMEOUT
#define ERR_MAX ERR_PROXY_DENIED


#define ICP_IDENT_SZ 64
#define IDENT_NONE 0
#define IDENT_PENDING 1
#define IDENT_DONE 2

#define IP_BLOCKING_LOOKUP	0x01
#define IP_LOOKUP_IF_MISS	0x02
#define IP_LOCK_ENTRY		0x04

#define IPCACHE_AV_FACTOR 1000

#define MAX_MIME 4096

/* Mark a neighbor cache as dead if it doesn't answer this many pings */
#define HIER_MAX_DEFICIT  20

/* bitfields for peer->options */
#define NEIGHBOR_PROXY_ONLY 0x01
#define NEIGHBOR_NO_QUERY   0x02
#define NEIGHBOR_DEFAULT_PARENT   0x04
#define NEIGHBOR_ROUNDROBIN   0x08
#define NEIGHBOR_MCAST_RESPONDER 0x10

#define ICP_FLAG_HIT_OBJ     0x80000000ul
#define ICP_FLAG_SRC_RTT     0x40000000ul

#define ICP_COMMON_SZ (sizeof(icp_common_t))
#define ICP_HDR_SZ (sizeof(icp_common_t)+sizeof(u_num32))

#define ICP_OP_HIGHEST (ICP_OP_END - 1)		/* highest valid opcode */

#define ICP_ERROR_MSGLEN	256	/* max size for string, incl '\0' */

/* Version */
#define ICP_VERSION_1		1
#define ICP_VERSION_2		2
#define ICP_VERSION_3		3
#define ICP_VERSION_CURRENT	ICP_VERSION_2

#define DIRECT_NO    0
#define DIRECT_MAYBE 1
#define DIRECT_YES   2

#define OUTSIDE_FIREWALL 0
#define INSIDE_FIREWALL  1
#define NO_FIREWALL      2

#define REDIRECT_AV_FACTOR 1000

#define REDIRECT_NONE 0
#define REDIRECT_PENDING 1
#define REDIRECT_DONE 2

#define REFRESH_ICASE 0x01

#define  CONNECT_PORT        443

#define current_stacksize(stack) ((stack)->top - (stack)->base)

/* logfile status */
#define LOG_ENABLE  1
#define LOG_DISABLE 0

#define SM_PAGE_SIZE 4096
#define DISK_PAGE_SIZE  8192

#define MIN_PENDING 		1
#define MIN_CLIENT 		1

#define BIT_SET(flag, bit) 	((flag) |= (bit))
#define BIT_RESET(flag, bit) 	((flag) &= ~(bit))
#define BIT_TEST(flag, bit) 	((flag) & (bit))

#define EBIT_SET(flag, bit) 	((flag) |= ((1<<bit)))
#define EBIT_RESET(flag, bit) 	((flag) &= ~((1<<bit)))
#define EBIT_TEST(flag, bit) 	((flag) & ((1<<bit)))

/* 
 * KEY_URL              If e->key and e->url point to the same location
 * KEY_CHANGE           If the key for this URL has been changed
 */

#define ENTRY_VALIDATED		(1<<16)
#define READ_DEFERRED		(1<<15)
#define ENTRY_NEGCACHED		(1<<14)
#define HIERARCHICAL 		(1<<13)		/* can we query neighbors? */
#define KEY_PRIVATE 		(1<<12)		/* is the key currently private? */
#define ENTRY_DISPATCHED 	(1<<11)
#define ENTRY_HTML 		(1<<10)
#define KEY_CHANGE 		(1<<9)
#define KEY_URL    		(1<<8)
#define ENTRY_CACHABLE   	(1<<7)
#define REFRESH_REQUEST   	(1<<6)
#define RELEASE_REQUEST 	(1<<5)
#define ABORT_MSG_PENDING 	(1<<4)
#define DELAY_SENDING 		(1<<3)
#define ENTRY_REVALIDATE 	(1<<2)
#define DELETE_BEHIND   	(1<<1)

#define MAX_FILES_PER_DIR (1<<20)

#define MAX_URL  4096
#define MAX_LOGIN_SZ  128

/* bitfields for the flags member */
#define REQ_UNUSED1		0x01
#define REQ_NOCACHE		0x02
#define REQ_IMS			0x04
#define REQ_AUTH		0x08
#define REQ_CACHABLE		0x10
#define REQ_UNUSED2		0x20
#define REQ_HIERARCHICAL	0x40
#define REQ_LOOPDETECT		0x80
#define REQ_PROXY_KEEPALIVE	0x100
#define REQ_PROXYING		0x200
#define REQ_REFRESH		0x400
#define PEER_MAX_ADDRESSES 10
#define RTT_AV_FACTOR      1000

/* flags for peer->mcast.flags */
#define PEER_COUNT_EVENT_PENDING 1
#define PEER_COUNTING		 2
#define ICP_AUTH_SIZE (2)	/* size of authenticator field */
#define ICP_QUERY_SZ (sizeof(icp_query_t))
#define ICP_HIT_SZ (sizeof(icp_hit_t))
#define ICP_MISS_SZ (sizeof(icp_miss_t))
#define ICP_ERROR_SZ (sizeof(icp_error_t))
#define ICP_SEND_SZ (sizeof(icp_send_t))
#define ICP_SENDA_SZ (sizeof(icp_senda_t))
#define ICP_DATAB_SZ (sizeof(icp_datab_t))
#define ICP_DATA_SZ (sizeof(icp_databe_t))
#define ICP_MESSAGE_SZ (sizeof(icp_message_t))
#define ICP_MESSAGE_SZ (sizeof(icp_message_t))

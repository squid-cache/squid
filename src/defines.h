
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

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
#define COMM_NOMESSAGE	 (-3)
#define COMM_TIMEOUT	 (-4)
#define COMM_SHUTDOWN	 (-5)
#define COMM_INPROGRESS  (-6)
#define COMM_ERR_CONNECT (-7)
#define COMM_ERR_DNS     (-8)
#define COMM_ERR_CLOSING (-9)

/* Select types. */
#define COMM_SELECT_READ   (0x1)
#define COMM_SELECT_WRITE  (0x2)
#define MAX_DEBUG_SECTIONS 100

#define COMM_NONBLOCKING	0x01
#define COMM_NOCLOEXEC		0x02
#define COMM_REUSEADDR		0x04

#define debug(SECTION, LEVEL) \
        ((_db_level = (LEVEL)) > debugLevels[SECTION]) ? (void) 0 : _db_print

#define safe_free(x)	if (x) { xxfree(x); x = NULL; }

#define DISK_OK                   (0)
#define DISK_ERROR               (-1)
#define DISK_EOF                 (-2)
#define DISK_NO_SPACE_LEFT       (-6)

#define DNS_INBUF_SZ 4096

#define FD_DESC_SZ		64

#define FQDN_LOOKUP_IF_MISS	0x01
#define FQDN_MAX_NAMES 5

/*  
 *  Here are some good prime number choices.  It's important not to
 *  choose a prime number that is too close to exact powers of 2.
 *
 *  HASH_SIZE 103               // prime number < 128
 *  HASH_SIZE 229               // prime number < 256
 *  HASH_SIZE 467               // prime number < 512
 *  HASH_SIZE 977               // prime number < 1024
 *  HASH_SIZE 1979              // prime number < 2048
 *  HASH_SIZE 4019              // prime number < 4096
 *  HASH_SIZE 6037              // prime number < 6144
 *  HASH_SIZE 7951              // prime number < 8192
 *  HASH_SIZE 12149             // prime number < 12288
 *  HASH_SIZE 16231             // prime number < 16384
 *  HASH_SIZE 33493             // prime number < 32768
 *  HASH_SIZE 65357             // prime number < 65536
 */

#define  DEFAULT_HASH_SIZE 7951	/* prime number < 8192 */

#define HTTP_REPLY_FIELD_SZ 128

#define BUF_TYPE_8K 	1
#define BUF_TYPE_MALLOC 2

#define ANONYMIZER_NONE		0
#define ANONYMIZER_STANDARD	1
#define ANONYMIZER_PARANOID	2

#define ICP_IDENT_SZ 64
#define IDENT_NONE 0
#define IDENT_PENDING 1
#define IDENT_DONE 2

#define IP_LOOKUP_IF_MISS	0x01

#define MAX_MIME 4096

/* Mark a neighbor cache as dead if it doesn't answer this many pings */
#define HIER_MAX_DEFICIT  20

#define ICP_FLAG_HIT_OBJ     0x80000000ul
#define ICP_FLAG_SRC_RTT     0x40000000ul

/* Version */
#define ICP_VERSION_2		2
#define ICP_VERSION_3		3
#define ICP_VERSION_CURRENT	ICP_VERSION_2

#define DIRECT_NO    0
#define DIRECT_MAYBE 1
#define DIRECT_YES   2

#define REDIRECT_AV_FACTOR 1000

#define REDIRECT_NONE 0
#define REDIRECT_PENDING 1
#define REDIRECT_DONE 2

#define  CONNECT_PORT        443

#define current_stacksize(stack) ((stack)->top - (stack)->base)

/* logfile status */
#define LOG_ENABLE  1
#define LOG_DISABLE 0

#define SM_PAGE_SIZE 4096
#define DISK_PAGE_SIZE  8192

#define EBIT_SET(flag, bit) 	((void)((flag) |= ((1<<(bit)))))
#define EBIT_CLR(flag, bit) 	((void)((flag) &= ~((1<<(bit)))))
#define EBIT_TEST(flag, bit) 	((flag) & ((1<<(bit))))

/* bit opearations on a char[] mask of unlimited length */
#define CBIT_BIT(bit)           (1<<((bit)%8))
#define CBIT_BIN(mask, bit)     (mask)[(bit)>>3]
#define CBIT_SET(mask, bit) 	((void)(CBIT_BIN(mask, bit) |= CBIT_BIT(bit)))
#define CBIT_CLR(mask, bit) 	((void)(CBIT_BIN(mask, bit) &= ~CBIT_BIT(bit)))
#define CBIT_TEST(mask, bit) 	(CBIT_BIN(mask, bit) & CBIT_BIT(bit))

#define MAX_FILES_PER_DIR (1<<20)

#define MAX_URL  4096
#define MAX_LOGIN_SZ  128

#define PEER_MAX_ADDRESSES 10
#define RTT_AV_FACTOR      1000

/* flags for peer->mcast.flags */
#define PEER_COUNT_EVENT_PENDING 1
#define PEER_COUNTING		 2

#define PEER_DEAD 0
#define PEER_ALIVE 1

#define AUTH_MSG_SZ 4096
#define HTTP_REPLY_BUF_SZ 4096

#if !defined(ERROR_BUF_SZ) && defined(MAX_URL)
#define ERROR_BUF_SZ (MAX_URL << 2)
#endif

#define READ_AHEAD_GAP		(1<<14)

#if SQUID_SNMP
#define VIEWINCLUDED    1
#define VIEWEXCLUDED    2
#endif

#define STORE_META_OK     0x03
#define STORE_META_DIRTY  0x04
#define STORE_META_BAD    0x05

#define IPC_NONE 0
#define IPC_TCP_SOCKET 1
#define IPC_UDP_SOCKET 2
#define IPC_FIFO 3

#define STORE_META_KEY STORE_META_KEY_MD5

#define STORE_META_TLD_START sizeof(int)+sizeof(char)
#define STORE_META_TLD_SIZE STORE_META_TLD_START
#define SwapMetaType(x) (char)x[0]
#define SwapMetaSize(x) &x[sizeof(char)]
#define SwapMetaData(x) &x[STORE_META_TLD_START]
#define STORE_HDR_METASIZE (4*sizeof(time_t)+2*sizeof(u_short)+sizeof(int))

#define STORE_ENTRY_WITH_MEMOBJ		1
#define STORE_ENTRY_WITHOUT_MEMOBJ	0
#define STORE_SWAP_BUF		DISK_PAGE_SIZE
#define VM_WINDOW_SZ		DISK_PAGE_SIZE

#define SKIP_BASIC_SZ ((size_t) 6)

#define PINGER_PAYLOAD_SZ 8192

#define QUICK_ABORT_100PCT	128

#define COUNT_INTERVAL 60
/*
 * keep 60 minutes' worth of per-minute readings (+ current reading)
 */
#define N_COUNT_HIST (3600 / COUNT_INTERVAL) + 1
/*
 * keep 3 days' (72 hours) worth of hourly readings
 */
#define N_COUNT_HOUR_HIST (86400 * 3) / (60 * COUNT_INTERVAL)

/* were to look for errors if config path fails */
#define DEFAULT_SQUID_ERROR_DIR "/usr/local/squid/etc/errors"

/* gb_type operations */
#define gb_flush_limit (0x3FFFFFFF)
#define gb_inc(gb, delta) { if ((gb)->bytes > gb_flush_limit || delta > gb_flush_limit) gb_flush(gb); (gb)->bytes += delta; (gb)->count++; }

/* iteration for HttpHdrRange */
#define HttpHdrRangeInitPos (-1)

/* use this and only this to initialize HttpHeaderPos */
#define HttpHeaderInitPos (-1)

/* handy to determine the #elements in a static array */
#define countof(arr) (sizeof(arr)/sizeof(*arr))

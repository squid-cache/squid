#ifndef __SQUID_HELPERS_DEFINES_H
#define __SQUID_HELPERS_DEFINES_H

/*
 * This file contains several macro definitions which are
 * useful and shared between helpers.
 */

#define HELPER_INPUT_BUFFER	8196

/* send OK result to Squid with a string parameter. */
#define SEND_OK(x)	fprintf(stdout, "OK %s\n",x)

/* send ERR result to Squid with a string parameter. */
#define SEND_ERR(x)	fprintf(stdout, "ERR %s\n",x)

#endif /* __SQUID_HELPERS_DEFINES_H */

AC_CHECK_HEADERS([sys/types.h rpc/rpc.h rpcsvc/yp_prot.h],[BUILD_HELPER="NIS"],,AC_INCLUDES_DEFAULT([
#if HAVE_RPC_RPC_H
#include <rpc/rpc.h>
#endif
]))

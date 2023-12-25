/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

#ifndef SQUID_AUTHREG_H_
#define SQUID_AUTHREG_H_

namespace Auth
{

#if USE_AUTH
/// Initialize Auth subsystem
void Init(void);
#else /* USE_AUTH */
inline void Init(void) {} /* NOP if not USE_AUTH */
#endif /* USE_AUTH */

} // namespace Auth
#endif /* SQUID_AUTHREG_H_ */


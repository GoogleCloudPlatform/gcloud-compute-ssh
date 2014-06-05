/*
 * Find the platform-specific misc.h header for this platform.
 */

#ifndef PUTTY_MISCPS_H
#define PUTTY_MISCPS_H

#ifdef _WINDOWS

#include "winmisc.h"

#elif defined(MACOSX)

#include "osxmisc.h"

#else

#include "uxmisc.h"

#endif

#endif /*PUTTY_MISCPS_H*/

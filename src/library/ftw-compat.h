/*
 * ftw-compat.h - GNU nftw action compatibility for POSIX implementations
 *
 * musl provides POSIX nftw(), where zero continues and any nonzero callback
 * result stops the walk, but not glibc's FTW_ACTIONRETVAL extension. Keep the
 * native glibc constants when available and provide their exact values for the
 * continue and stop actions used by fapolicyd. musl currently ignores the
 * unsupported action-return flag; skip actions must not be added without an
 * implementation that supplies their GNU semantics.
 */

#ifndef FTW_COMPAT_HEADER
#define FTW_COMPAT_HEADER

#include <ftw.h>

#ifndef FTW_ACTIONRETVAL
#define FTW_ACTIONRETVAL 16
#define FTW_CONTINUE 0
#define FTW_STOP 1
#endif

#endif

#ifndef GCC_ATTRIBUTES_H
#define GCC_ATTRIBUTES_H

#define NEVERNULL __attribute__ ((returns_nonnull))
#define WARNUNUSED __attribute__ ((warn_unused_result))
#define NORETURN __attribute__ ((noreturn))

// These macros originate in sys/cdefs.h. These are stubs in case undefined.
#include <string.h>  // any major header brings cdefs.h
#ifndef __attr_access
#  define __attr_access(x)
#endif
#ifndef __attr_dealloc
# define __attr_dealloc(dealloc, argno)
# define __attr_dealloc_free
#endif
#ifndef __attribute_malloc__
#  define __attribute_malloc__
#endif

#endif

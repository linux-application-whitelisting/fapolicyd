#ifndef GCC_ATTRIBUTES_H
#define GCC_ATTRIBUTES_H

// These macros originate in sys/cdefs.h. These are stubs in case undefined.
#include <string.h>  // any major header brings cdefs.h
#ifndef __fapolicyd_has_attribute
/* Match glibc's guard so older Clang does not parse __has_attribute calls. */
#  if (defined __has_attribute \
       && (!defined __clang_minor__ \
	   || 3 < __clang_major__ + (5 <= __clang_minor__)))
#    define __fapolicyd_has_attribute(attr) __has_attribute (attr)
#  else
#    define __fapolicyd_has_attribute(attr) 0
#  endif
#endif
#ifndef __returns_nonnull
#  define __returns_nonnull
#endif
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
#ifndef __attribute_const__
#  define __attribute_const__
#endif
#ifndef __attribute_pure__
#  define __attribute_pure__
#endif
#ifndef __noreturn
#  define __noreturn __attribute__ ((__noreturn__))
#endif
#ifndef __nonnull
#  define __nonnull(params)
#endif
#ifndef __attr_fd_arg
#  if __fapolicyd_has_attribute (__fd_arg__)
#    define __attr_fd_arg(argno) __attribute__ ((__fd_arg__ (argno)))
#  else
#    define __attr_fd_arg(argno)
#  endif
#endif
#ifndef __attr_fd_arg_read
#  if __fapolicyd_has_attribute (__fd_arg_read__)
#    define __attr_fd_arg_read(argno) \
	__attribute__ ((__fd_arg_read__ (argno)))
#  else
#    define __attr_fd_arg_read(argno)
#  endif
#endif
#ifndef __attr_fd_arg_write
#  if __fapolicyd_has_attribute (__fd_arg_write__)
#    define __attr_fd_arg_write(argno) \
	__attribute__ ((__fd_arg_write__ (argno)))
#  else
#    define __attr_fd_arg_write(argno)
#  endif
#endif
#ifndef __wur
# define __wur
#endif

#endif

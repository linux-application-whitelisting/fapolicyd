AC_REVISION($Revision: 1.3 $)dnl
AC_INIT([fapolicyd],[1.3.4])
AC_PREREQ([2.60])dnl
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_USE_SYSTEM_EXTENSIONS

AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(foreign subdir-objects)
LT_INIT
AC_SUBST(LIBTOOL_DEPS)

echo .
echo Checking for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_AWK
PKG_PROG_PKG_CONFIG
AC_CHECK_PROG([FILE_COMM], "file", "yes", "no")
if test "$FILE_COMM" = "no"; then
	AC_MSG_ERROR([Unable to find the file program need to build magic databases])
fi
AC_CHECK_MEMBER([struct fanotify_response_info_audit_rule.rule_number],
		[perm=yes], [perm=no], [[#include <linux/fanotify.h>]])
if test $perm = "yes"; then
	AC_DEFINE(FAN_AUDIT_RULE_NUM, 1,[Define if kernel supports audit rule numbers])
fi

echo .
echo Checking compiler options

AC_C_CONST
AC_C_INLINE

withval=""
AC_ARG_WITH(debug,
AS_HELP_STRING([--with-debug],[turn on debugging (default=no)]),
AC_DEFINE(DEBUG,1,[Define if you want to enable runtime debug checking.]),
[])

AC_MSG_CHECKING(__attr_access support)
AC_COMPILE_IFELSE(
  [AC_LANG_SOURCE(
    [[
      #include <stdio.h>
      int audit_fgets(char *buf, size_t blen, int fd)
        __attr_access ((__write_only__, 1, 2));
      int main(void) { return 0; }]])],
  [ACCESS="yes"],
  [ACCESS="no"]
)
AC_MSG_RESULT($ACCESS)

AC_MSG_CHECKING(__attr_dealloc_free support)
AC_COMPILE_IFELSE(
  [AC_LANG_SOURCE(
    [[
      #include <stdlib.h>
      const char *strdup(const char *buf) __attr_dealloc_free;
      int main(void) { return 0; }]])],
  [DEALLOC="yes"],
  [DEALLOC="no"]
)
AC_MSG_RESULT($DEALLOC)


withval=""
AC_ARG_WITH(asan,
AS_HELP_STRING([--with-asan],[build with asan sanitizer (default=no)]),
use_asan=yes,use_asan=$withval)

if test x$use_asan = xyes ; then
  AC_LANG_PUSH([C])

  CCFLAGS="-fno-omit-frame-pointer"
  ASAN_CFLAGS=""

  for CFLAG in $CCFLAGS; do
      echo -n "checking for $CFLAG... "
      TMPFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $CFLAG"
      AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[ASAN_CFLAGS="$ASAN_CFLAGS $CFLAG"
      AC_MSG_RESULT(yes)],
      [AC_MSG_RESULT(no)])
      CFLAGS="$TMPFLAGS"
  done

  LLDFLAGS="-faddress-sanitizer -fsanitize=address"
  ASAN_LDFLAGS=""

  for LDFLAG in $LLDFLAGS; do
      echo -n "checking for $LDFLAG... "
      TMPLDFLAGS="$LDFLAGS"
      LDFLAGS="$LDFLAGS $LDFLAG"
      AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[ASAN_LDFLAGS="$ASAN_LDFLAGS $LDFLAG"
      AC_MSG_RESULT(yes)],
      [AC_MSG_RESULT(no)])
      LDFLAGS="$TMPLDFLAGS"
  done

 # how many flags should pass? just one "-fno-omit-frame-pointer"
  if [[ -z "$ASAN_CFLAGS" ]] || [[ "`echo "$ASAN_CFLAGS" | wc -w`" -ne 1 ]]; then
     AC_MSG_ERROR([ Compiler does not support asan sanitizer cflags ])
  fi

  # how many flags should pass? just one of "-faddress-sanitizer -fsanitize=address"
  if [[ -z "$ASAN_LDFLAGS" ]] || [[ "`echo "$ASAN_LDFLAGS" | wc -w`" -ne 1 ]]; then
     AC_MSG_ERROR([ Compiler does not support asan sanitizer ldflags])
  fi

  CFLAGS="$CFLAGS $ASAN_CFLAGS -O0"
  LDFLAGS="$LDFLAGS $ASAN_LDFLAGS"
  AC_DEFINE([USE_ASAN], [1], [Address Sanitizer is enabled])
fi

AC_ARG_WITH(audit,
AS_HELP_STRING([--with-audit],[turn on decision auditing (default=no)]),
AC_DEFINE(USE_AUDIT,1,[Define if you want to enable decision auditing.]),
[])
AC_CHECK_DECLS([FAN_AUDIT], [], [], [[#include <linux/fanotify.h>]])
AC_CHECK_DECLS([FAN_OPEN_EXEC_PERM], [perm=yes], [perm=no], [[#include <linux/fanotify.h>]])
if test $perm = "no"; then
	AC_MSG_ERROR([FAN_OPEN_EXEC_PERM is not defined in linux/fanotify.h. It is required for the kernel to support it])
fi
AC_CHECK_DECLS([FAN_MARK_FILESYSTEM], [], [], [[#include <linux/fanotify.h>]])

withval=""
AC_ARG_WITH(rpm,
AS_HELP_STRING([--with-rpm],[Use the rpm database as a trust source]),
use_rpm=$withval,use_rpm=yes)

if test x$use_rpm = xyes ; then
    AC_CHECK_LIB(rpm, rpmtsInitIterator, , [AC_MSG_ERROR([librpm not found])], -lrpm)
    AC_CHECK_LIB(rpmio, rpmFreeCrypto, , [AC_MSG_ERROR([librpmio not found])], -lrpmio)
    AC_DEFINE(USE_RPM,1,[Define if you want to use the rpm database as trust source.])
fi
AM_CONDITIONAL(WITH_RPM, test x$use_rpm = xyes)

withval=""
AC_ARG_WITH(deb,
AS_HELP_STRING([--with-deb],[Use the deb database as a trust source]),
use_deb=$withval,use_deb=no)

if test x$use_deb = xyes ; then
    AC_CHECK_LIB(dpkg, pkg_array_init_from_hash, , [AC_MSG_ERROR([libdpkg not found])], -ldpkg)
    AC_DEFINE(USE_DEB,1,[Define if you want to use the deb database as trust source.])
    AC_CHECK_LIB(md, MD5Final, , [AC_MSG_ERROR([libmd is missing])], -lmd)
fi
AM_CONDITIONAL(WITH_DEB, test x$use_deb = xyes)
AM_CONDITIONAL(NEED_MD5, test x$use_deb = xyes)

withval=""
AC_ARG_WITH(ebuild,
AS_HELP_STRING([--with-ebuild],[Use the ebuild database as a trust source]),
use_ebuild=$withval,use_ebuild=no)

if test x$use_ebuild = xyes ; then
    AC_DEFINE(USE_EBUILD,1,[Define if you want to use the ebuild database as trust source.])
    AC_CHECK_LIB(md, MD5Final, , [AC_MSG_ERROR([libmd is missing])], -lmd)
fi
AM_CONDITIONAL(WITH_EBUILD, test x$use_ebuild = xyes)
AM_CONDITIONAL(NEED_MD5, test x$use_ebuild = xyes)

dnl FIXME some day pass this on the command line
def_systemdsystemunitdir=${prefix}/lib/systemd/system
AC_SUBST([systemdsystemunitdir], [$def_systemdsystemunitdir])

echo .
echo Checking for required header files
AC_CHECK_HEADER(sys/fanotify.h, , [AC_MSG_ERROR(
["Couldn't find sys/fanotify.h...your kernel might not be new enough"] )])
AC_CHECK_FUNCS(fexecve, [], [])
AC_CHECK_FUNCS([gettid])
AC_CHECK_HEADER(uthash.h, , [AC_MSG_ERROR(
["Couldn't find uthash.h...uthash-devel is missing"] )])


echo .
echo Checking for required libraries
AC_CHECK_LIB(udev, udev_device_get_devnode, , [AC_MSG_ERROR([libudev not found])], -ludev)
AC_CHECK_LIB(crypto, SHA256, , [AC_MSG_ERROR([openssl libcrypto not found])], -lcrypto)
AC_CHECK_LIB(magic, magic_descriptor, , [AC_MSG_ERROR([libmagic not found])], -lmagic)
AC_CHECK_LIB(cap-ng, capng_change_id, , [AC_MSG_ERROR([libcap-ng not found])], -lcap-ng)
AC_CHECK_LIB(seccomp, seccomp_rule_add, , [AC_MSG_ERROR([libseccomp not found])], -lseccomp)
AC_CHECK_LIB(lmdb, mdb_env_create, , [AC_MSG_ERROR([liblmdb not found])], -llmdb)

LD_SO_PATH

AC_CONFIG_FILES([Makefile src/Makefile src/tests/Makefile extra/Makefile doc/Makefile rules.d/Makefile])
AC_OUTPUT

echo .
echo "

  fapolicyd Version:      $VERSION
  Target:                 $target
  Installation prefix:    $prefix
  Compiler:               $CC
  Compiler flags:
`echo $CFLAGS | fmt -w 50 | sed 's,^,                          ,'`
  Linker flags:
`echo $LDFLAGS | fmt -w 50 | sed 's,^,                          ,'`
  __attr_access support:  $ACCESS
  __attr_dealloc_free support: $DEALLOC
"
 

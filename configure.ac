AC_REVISION($Revision: 1.3 $)dnl
AC_INIT(fapolicyd,0.8)
AC_PREREQ(2.12)dnl
AM_CONFIG_HEADER(config.h)
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

echo .
echo Checking for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_AWK
PKG_PROG_PKG_CONFIG

echo .
echo Checking compiler options

AC_C_CONST
AC_C_INLINE

dnl FIXME some day pass this on the command line
def_systemdsystemunitdir=${prefix}/lib/systemd/system
AC_SUBST([systemdsystemunitdir], [$def_systemdsystemunitdir])

echo .
echo Checking for required header files
AC_HEADER_STDC
AC_CHECK_HEADER(sys/fanotify.h, , [AC_MSG_ERROR(
["Couldn't find sys/fanotify.h...your kernel might not be new enough"] )])

echo .
echo Checking for required libraries
AC_CHECK_LIB(udev, udev_device_get_devnode, , [AC_MSG_ERROR([libudev not found])], -ludev)
AC_CHECK_LIB(gcrypt, gcry_md_open, , [AC_MSG_ERROR([libgcrypt not found])], -lgcrypt)
AC_CHECK_LIB(rpm, rpmtsInitIterator, , [AC_MSG_ERROR([librpm not found])], -lrpm)
AC_CHECK_LIB(rpmio, rpmFreeCrypto, , [AC_MSG_ERROR([librpmio not found])], -lrpmio)
AC_CHECK_LIB(magic, magic_descriptor, , [AC_MSG_ERROR([libmagic not found])], -lmagic)

AC_OUTPUT(Makefile src/Makefile init/Makefile doc/Makefile)

echo .
echo "

  fapolicyd Version:      $VERSION
  Target:                 $target
  Installation prefix:    $prefix
  Compiler:               $CC
  Compiler flags:
`echo $CFLAGS | fmt -w 50 | sed 's,^,                          ,'`
"
 

AC_DEFUN([LD_SO_PATH],
[
  xpath=`realpath /usr/lib64/ld-2.*.so`
  echo "dynamic linker is.....$xpath"
  AC_DEFINE_UNQUOTED(SYSTEM_LD_SO, ["$xpath"], [dynamic linker])
])

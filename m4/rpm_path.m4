AC_DEFUN([RPMDB_PATH],
[
  xpath=`rpm --eval '%_dbpath'`
  echo "rpmdb path is.....$xpath"
  AC_DEFINE_UNQUOTED(RPM_DB_PATH, ["$xpath"], [rpmdb path])
])

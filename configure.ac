AC_INIT([gttlvutil], m4_esyscmd([tr -d [:space:] <VERSION]), [suppot@guardtime.com])
AC_CONFIG_SRCDIR([src/common.h])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([crypto], [SHA256_Init], [], [AC_MSG_FAILURE([Could not find OpenSSL 0.9.8+ libraries.])])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Add more compile time warnings
CFLAGS+=" -Wall"

AC_ARG_ENABLE([local-data],
[  --enable-local-data    Use local data.],
[case "${enableval}" in
  yes) local_data=true ;;
  no)  local_data=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-local-data]) ;;
esac],[local_data=false])
AM_CONDITIONAL([PKG_DATA_DIR], [test x$local_data = xfalse])


AC_CONFIG_FILES([GNUmakefile src/GNUmakefile])
AC_OUTPUT


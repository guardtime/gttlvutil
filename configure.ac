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

AC_ARG_WITH([data-dir],  
  [AC_HELP_STRING([--with-data-dir=PATH], 
                  [path to directory containing desc files. Use '-' to search the files from the directory where executable is located.])], 
  [case "${withval}" in
     -)
       # Search desc files from the same directory where executable is located.
       ;;
     *)
       # Search desc files from the specified path.
       AC_SUBST(DESC_DATA_DIR, "$withval")
       use_datadir=true
       ;;
   esac;
  ], 
  [# No path is specified, search desc files from the default system directory. 
   AC_SUBST(DESC_DATA_DIR, "pkgdatadir")
   use_pkgdatadir=true
   use_datadir=true
  ]
)
AM_CONDITIONAL([USE_DATA_DIR], [test x$use_datadir = xtrue])
AM_CONDITIONAL([USE_PKG_DATA_DIR], [test x$use_pkgdatadir = xtrue])

AC_CONFIG_FILES([GNUmakefile src/GNUmakefile])
AC_OUTPUT


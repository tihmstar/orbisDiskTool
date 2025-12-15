AC_PREREQ([2.69])
AC_INIT([orbisDiskTool], m4_esyscmd([git rev-list --count HEAD | tr -d '\n']), [tihmstar@gmail.com])

AC_CANONICAL_SYSTEM
AC_CANONICAL_HOST
AM_PROG_LIBTOOL

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])


AC_DEFINE([VERSION_COMMIT_COUNT], "m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])", [Git commit count])
AC_DEFINE([VERSION_COMMIT_SHA], "m4_esyscmd([git rev-parse HEAD | tr -d '\n'])", [Git commit sha])
AC_SUBST([VERSION_COMMIT_COUNT], ["m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])"])
AC_SUBST([VERSION_COMMIT_SHA], ["m4_esyscmd([git rev-parse HEAD | tr -d '\n'])"])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

CXXFLAGS+=" -std=c++11"
CFLAGS+=" -std=c11"
# Versioning.

# Checks for libraries.
FUSE_REQUIRES_STR="fuse >= 2.8"
LIBGENERAL_REQUIRES_STR="libgeneral >= 84"
OPENSSL_REQUIRES_STR="openssl >= 3.0.0"

PKG_CHECK_MODULES(libfuse, $FUSE_REQUIRES_STR, have_fuse=yes, have_fuse=no)
PKG_CHECK_MODULES(libgeneral, $LIBGENERAL_REQUIRES_STR)
PKG_CHECK_MODULES(openssl, $OPENSSL_REQUIRES_STR)

AC_SUBST([libgeneral_requires], [$LIBGENERAL_REQUIRES_STR])
AC_SUBST([openssl_requires], [$OPENSSL_REQUIRES_STR])

AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
            [enable debug build(default is no)])],
            [debug_build=true],
            [debug_build=false])

AC_ARG_WITH([fuse],
            [AS_HELP_STRING([--without-fuse],
            [do not build with libfuse @<:@default=yes@:>@])],
            [with_fuse=no],
            [with_fuse=yes])

if test "x$with_fuse" == "xyes"; then
  if test "x$have_fuse" == "xyes"; then
    AC_DEFINE([HAVE_FUSE], [1], [Define if you have libfuse])
    AC_SUBST([HEADER_HAVE_FUSE], [1])
    AC_SUBST([libfuse_CFLAGS])
    AC_SUBST([libfuse_LIBS])
  else
    AC_MSG_ERROR([requested building with libfuse, but library could not be found])
  fi
else
  echo "*** Note: libfuse has been disabled ***"
  AC_SUBST([HEADER_HAVE_FUSE], [0])
fi

# Checks for header files.
AC_CHECK_HEADERS([sys/disk.h linux/fs.h])

# Check for libraries

# Checks for typedefs, structures, and compiler characteristics.


AC_CONFIG_FILES([Makefile
                 orbisDiskTool/Makefile])

AC_OUTPUT


echo "
Configuration for $PACKAGE-$VERSION:
-------------------------------------------

  install prefix ..........: $prefix
  with fuse ...............: $with_fuse"

echo "  compiler ................: ${CC}

  Now type 'make' to build $PACKAGE-$VERSION,
  and then 'make install' for installation.
"

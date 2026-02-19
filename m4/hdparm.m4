# hdparm.m4 serial 0
dnl Copyright (C) 1995-2003, 2005-2006 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.
dnl
dnl This file can can be used in projects which are not available under
dnl the GNU General Public License or the GNU Library General Public
dnl License but which still want to provide support for the GNU gettext
dnl functionality.
dnl Please note that the actual code of the GNU gettext library is covered
dnl by the GNU Library General Public License, and the rest of the GNU
dnl gettext package package is covered by the GNU General Public License.
dnl They are *not* in the public domain.

dnl Authors:
dnl   Andrew Medico <amedico@users.sourceforge.net>, 2008.

AC_PREREQ(2.50)

AC_DEFUN([DC3_HDPARM],
[
  AC_MSG_CHECKING([whether hdparm support is requested])
  dnl Default is disabled
  AC_ARG_ENABLE(hdparm,
    [  --enable-hdparm         use hdparm code to check for HPA/DCO on ATA drives],
    USE_HDPARM=$enableval, USE_HDPARM=no)
  AM_CONDITIONAL([COND_USE_HDPARM], [test x$USE_HDPARM == xyes])
  AC_MSG_RESULT($USE_HDPARM)
  AC_SUBST(USE_HDPARM)
])

AC_DEFUN([DC3_HDPARM_SET],
[
  if test "$USE_HDPARM" = "yes"; then
    AC_DEFINE(USE_HDPARM, 1, [Define if hdparm is requested for detecting HPA/DCO.])
  fi
])


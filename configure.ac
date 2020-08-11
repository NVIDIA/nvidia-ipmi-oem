#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([nvidia-ipmi-oem], [0.1], [sharady@nvidia.com])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-xz])
AC_LANG([C++])

# Checks for programs.
AC_PROG_CXX
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
PKG_CHECK_MODULES([SYSTEMD], [libsystemd >= 221])
PKG_CHECK_MODULES([SDBUSPLUS], [sdbusplus])
PKG_CHECK_MODULES([LIBIPMID], [libipmid])
PKG_CHECK_MODULES([PHOSPHOR_DBUS_INTERFACES], [phosphor-dbus-interfaces])
PKG_CHECK_MODULES([PHOSPHOR_LOGGING], [phosphor-logging])
AX_PTHREAD

LT_INIT

# Checks for header files.
AC_CHECK_HEADER(systemd/sd-bus.h, ,[
        AC_MSG_ERROR([Could not find systemd/sd-bus.h...systemd development package required])
    ])

AC_CHECK_HEADER(nlohmann/json.hpp, [], [
        AC_MSG_ERROR([Could not find nlohmann/json.hpp])
    ])

# Checks for typedefs, structures, and compiler characteristics.
AX_CXX_COMPILE_STDCXX_17([noext])

# Checks for library functions.

AC_CONFIG_FILES([Makefile
                 include/Makefile])
AC_OUTPUT

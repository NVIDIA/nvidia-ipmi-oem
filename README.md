# NVIDIA IPMI OEM support library
This component provides NVIDIA-specific IPMI`[3]` command handlers for OpenBMC.
These handlers are intended to integrate BMC with servers based on NVIDIA architecture.

## Overview
`nvidia-ipmi-oem` serves as an extension`[1]` to OpenBMC IPMI daemon`[2]`.
It is compiled as a shared library and intended to both:
- override existing implementation of standard IPMI commands to comply with
  Nvidia-specific solutions.
- provide implementation for non-standard OEM extensions.

## Build
### Environment Setup

OS | Build Tool Package
--- | ---
Ubuntu 18.04 | g++<br>autoconf<br>autoconf-archive<br>pkg-config<br>libtool-bin<br>doxygen
Cygwin | g++<br>autoconf<br>autoconf-archive<br>pkg-config<br>libtool-bin<br>doxygen

OpenBMC SDK Installation Instructions: [link](https://github.com/openbmc/docs/blob/master/development/dev-environment.md#download-and-install-sdk)

Instead of setting up those manually, run following script inside *source code folder* will help,
``` shell
$ sudo scripts/setup_bldenv
```
>**NOTE: Cygwin packages need to be installed manually with [Cygwin setup utility](https://www.cygwin.com/setup-x86_64.exe)!**

### How to Build
Source the environment setup script e.g.
```
$ . /...path-to-sdk.../environment-setup-arm1176jzs-openbmc-linux-gnueabi
```

The general build steps are as below, inside *source code folder* and run,
``` shell
$ ./bootstrap.sh
$ ./configure ${CONFIGURE_FLAGS}
$ make
$ make install  # Optional
```

[CONFIGURE_FLAGS](#tablebuildmode) are defined as below, any combinations of them are valid,
<a id="tablebuildmode"></a>

Mode | `${CONFIGURE_FLAGS}` | Description
--- | --- | ---
SDK | ${CONFIGURE_FLAGS} | Verify if this module can be built into OpenBMC SDK with cross-compiler toolchains.<br>OpenSDK Build Environment needs to be exported first (assume installed at /opt/oecore-x86_64),<br>**$ . /opt/oecore-x86_64/environment-setup-armv6-openbmc-linux-gnueabi**<br>(NOTE: May need to switch to root before that and keep in root for rest of the steps)
Production | (OpenBMC recipes defined options) | Build it into OpenBMC for production release. Build with OpenBMC code repository.


### How to Clean
To clean build cache,
``` shell
$ make clean
```
or
``` shell
$ make distclean
```

To completely clean the workspace,
``` shell
$ ./bootstrap.sh clean
```

## References
1. [OpenBMC IPMI Architecture](https://github.com/openbmc/docs/blob/master/architecture/ipmi-architecture.md)
2. [Phosphor IPMI Host](https://github.com/openbmc/phosphor-host-ipmid)
3. [IPMI Specification v2.0](https://www.intel.pl/content/www/pl/pl/products/docs/servers/ipmi/ipmi-second-gen-interface-spec-v2-rev1-1.html)


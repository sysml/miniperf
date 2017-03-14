default : all

######################################
## user defined
######################################
XEN_VER		?= 4.4.2
GCC_VERSION	?= 4.9.0
verbose		?=
stubdom		 = y
debug		?= n

ARCH		 = x86_64

XEN_TARGET_ARCH		?= $(ARCH)
XEN_COMPILE_ARCH	?= $(ARCH)
XEN_ROOT		?= $(realpath ../xen)
TOOLCHAIN_ROOT		?= $(realpath ../toolchain)
MINIOS_ROOT		?= $(realpath ../mini-os)
NEWLIB_ROOT		?= $(TOOLCHAIN_ROOT)/$(ARCH)-root/x86_64-xen-elf
LWIP_ROOT		?= $(TOOLCHAIN_ROOT)/$(ARCH)-root/x86_64-xen-elf

CFLAGS			+= -Winline -Wtype-limits -Wcast-align
CFLAGS			+= -isystem $(realpath .)

######################################
## configuration
######################################
CONFIG_NETFRONT		 		 = y
CONFIG_NETFRONT_POLLTIMEOUT	 	 = 1

CONFIG_BLKFRONT		 		 = n

CONFIG_LWIP				 = y
CONFIG_LWIP_MINIMAL			 = y
CONFIG_LWIP_NOTHREADS			 = y
CONFIG_LWIP_CHECKSUM_NOCHECK		 = y

CONFIG_START_NETWORK			 = n
CONFIG_CONSFRONT_SYNC			 = y

include Config.mk
-include .config.mk

######################################
## building
######################################
STUBDOM_NAME	= miniperf
STUBDOM_ROOT	= $(realpath .)

STUB_APP_OBJS0  = iperf.o main.o mempool.o
STUB_APP_OBJS	= $(addprefix $(STUB_APP_OBJ_DIR)/,$(STUB_APP_OBJS0))

include $(MINIOS_ROOT)/stub.mk

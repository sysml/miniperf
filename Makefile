default : all

######################################
## user defined
######################################
XEN_VER		?= 4.4.2
GCC_VERSION	?= 4.9.0
verbose		?=
stubdom		 = y

ARCH = x86_64

XEN_TARGET_ARCH		?= $(ARCH)
XEN_COMPILE_ARCH	?= $(ARCH)
XEN_ROOT		?= $(realpath ../xen)
TOOLCHAIN_ROOT		?= $(realpath ../toolchain)
MINIOS_ROOT		?= $(realpath ../mini-os)
NEWLIB_ROOT             ?= $(TOOLCHAIN_ROOT)/$(ARCH)-root/x86_64-xen-elf
LWIP_ROOT               ?= $(TOOLCHAIN_ROOT)/$(ARCH)-root/x86_64-xen-elf

CFLAGS          += -Winline -Wtype-limits -Wcast-align -DDEBUG_SHELL
CFLAGS          += -isystem $(realpath .)

CFLAGS	       			+= -DLWIP_WND_SCALE=1
CFLAGS	       			+= -DLWIP_STATS_DISPLAY=1
#CFLAGS				+= -DLWIP_IF_DEBUG
#CFLAGS				+= -DLWIP_TCP_DEBUG
#CFLAGS				+= -DLWIP_POOL_DEBUG

CONFIG_START_NETWORK		= n
# use 'vale' for xenbus driver instead of 'vif'
CONFIG_NETMAP_XENBUS		= y
# POSIX netmap implementation
CONFIG_NETMAP			= y
CONFIG_NETMAP_API		= 4
CONFIG_MEMPOOL			= y
CONFIG_LWIP			= y
CONFIG_LWIP_MINIMAL		= y
# Uncomment the following line to enable single threaded processing:
CONFIG_LWIP_SINGLETHREADED 	= y
#CONFIG_LWIP_NOTHREADS		= y
CONFIG_LWIP_CHECKSUM_NOCHECK	= y

######################################
## netif: NM_NETFRONT2
######################################
#CONFIG_NETFRONT		= y
#CONFIG_NETFRONT_NETMAP2	= y
#CONFIG_NMWRAP			= n

######################################
## netif: NM_WRAP
######################################
CONFIG_NETFRONT			= y
CONFIG_NETFRONT_GSO		= y
CONFIG_NETFRONT_PERSISTENT_GRANTS = y
#CONFIG_NETFRONT_NETMAP2		= n
#CONFIG_NMWRAP			= y
#CONFIG_NMWRAP_SYNCRX		= n

######################################
## debugging options
######################################
CONFIG_CONSFRONT_SYNC		= y
#CONFIG_DEBUG			= y
#CONFIG_DEBUG_LWIP		= y
#CONFIG_DEBUG_LWIP_MALLOC	= y

MINIOS_ROOT	?= $(realpath ../mini-os/)

STUBDOM_NAME	= iperf
STUBDOM_ROOT	= $(realpath .)

STUB_APP_OBJS0  = iperf.o main.o mempool.o ring.o
STUB_APP_OBJS	= $(addprefix $(STUB_APP_OBJ_DIR)/,$(STUB_APP_OBJS0))

include $(MINIOS_ROOT)/stub.mk

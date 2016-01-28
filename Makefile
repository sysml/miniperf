default : all

######################################
## user defined
######################################
XEN_VER		?= 4.4.2
GCC_VERSION	?= 4.9.0
verbose		?=
stubdom		 = y
debug		?= y

ARCH = x86_64

XEN_TARGET_ARCH		?= $(ARCH)
XEN_COMPILE_ARCH	?= $(ARCH)
XEN_ROOT			?= $(realpath ../xen)
TOOLCHAIN_ROOT		?= $(realpath ../toolchain)
MINIOS_ROOT			?= $(realpath ../mini-os)
NEWLIB_ROOT         ?= $(TOOLCHAIN_ROOT)/$(ARCH)-root/x86_64-xen-elf
LWIP_ROOT           ?= $(TOOLCHAIN_ROOT)/$(ARCH)-root/x86_64-xen-elf

CFLAGS          += -Winline -Wtype-limits -Wcast-align -DDEBUG_SHELL
CFLAGS          += -isystem $(realpath .)

CFLAGS			+= -DLWIP_STATS_DISPLAY=1

#CONFIG_SELECT_POLL		= y

## vif
CONFIG_NETFRONT		 			   = y
CONFIG_NETFRONT_PERSISTENT_GRANTS ?= y
CONFIG_NETFRONT_GSO		 		  ?= y
CONFIG_NETFRONT_POLL		 	   = $(CONFIG_SELECT_POLL)
CONFIG_NETFRONT_POLLTIMEOUT	 	   = 1
CONFIG_START_NETWORK			   = n

CONFIG_LWIP						= y
CONFIG_LWIP_MINIMAL				= y
CONFIG_LWIP_NOTHREADS			= y
CONFIG_LWIP_HEAP_ONLY		   ?= n
CONFIG_LWIP_POOLS_ONLY			= n
CONFIG_LWIP_CHECKSUM_NOCHECK	= y
CONFIG_LWIP_WAITFORTX		   ?= y
CONFIG_LWIP_BATCHTX			   ?= n
CONFIG_LWIP_WND_SCALE		   ?= y

######################################
## debugging options
######################################
CONFIG_CONSFRONT_SYNC		= y
#CONFIG_DEBUG			= y
#CONFIG_DEBUG_LWIP		= y
#CONFIG_DEBUG_LWIP_MALLOC	= y

STUBDOM_NAME	= iperf
STUBDOM_ROOT	= $(realpath .)

STUB_APP_OBJS0  = iperf.o main.o mempool.o ring.o
STUB_APP_OBJS	= $(addprefix $(STUB_APP_OBJ_DIR)/,$(STUB_APP_OBJS0))

include $(MINIOS_ROOT)/stub.mk

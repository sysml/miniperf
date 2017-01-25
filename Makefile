default : all

######################################
## user defined
######################################
XEN_VER		?= 4.4.2
GCC_VERSION	?= 4.9.0
verbose		?=
stubdom		 = y
debug		?= n

ARCH = x86_64

XEN_TARGET_ARCH		?= $(ARCH)
XEN_COMPILE_ARCH	?= $(ARCH)
XEN_ROOT		?= $(realpath ../xen)
TOOLCHAIN_ROOT		?= $(realpath ../toolchain)
MINIOS_ROOT		?= $(realpath ../mini-os)
NEWLIB_ROOT		?= $(TOOLCHAIN_ROOT)/$(ARCH)-root/x86_64-xen-elf
LWIP_ROOT		?= $(TOOLCHAIN_ROOT)/$(ARCH)-root/x86_64-xen-elf

CFLAGS			+= -Winline -Wtype-limits -Wcast-align -DDEBUG_SHELL
CFLAGS			+= -isystem $(realpath .)

######################################
## tuning options
######################################
CONFIG_SELECT_POLL			 = y

## vif
CONFIG_NETFRONT		 		 = y
CONFIG_NETFRONT_PERSISTENT_GRANTS 	?= y
CONFIG_NETFRONT_GSO		 	?= y
CONFIG_NETFRONT_WAITFORTX		 = y
CONFIG_NOAVXMEMCPY			?= n
CONFIG_NETFRONT_POLL		 	 = $(CONFIG_SELECT_POLL)
CONFIG_NETFRONT_POLLTIMEOUT	 	 = 1
CONFIG_START_NETWORK			 = n

## lwip
CONFIG_LWIP				 = y
CONFIG_LWIP_MINIMAL			 = y
CONFIG_LWIP_NOTHREADS			 = y
CONFIG_LWIP_HEAP_ONLY			?= n
CONFIG_LWIP_POOLS_ONLY			 = n
CONFIG_LWIP_CHECKSUM_NOCHECK		 = y
CONFIG_LWIP_WAITFORTX			?= y
CONFIG_LWIP_PARTIAL_CHECKSUM		?= $(CONFIG_NETFRONT_GSO)
CONFIG_LWIP_GSO				?= n
CONFIG_LWIP_BATCHTX			?= n
CONFIG_LWIP_WND_SCALE			?= y
CONFIG_LWIP_NUM_TCPCON			?= 512
#CFLAGS					+= -DMEMP_NUM_PBUF=65535

######################################
## debugging options
######################################
CONFIG_CONSFRONT_SYNC		= y
#CONFIG_DEBUG			= y
#CONFIG_DEBUG_LWIP		= y
#CONFIG_DEBUG_LWIP_MALLOC	= y
#CFLAGS				+= -DLWIP_STATS_DISPLAY=1


######################################
## building
######################################
STUBDOM_NAME	= iperf
STUBDOM_ROOT	= $(realpath .)

STUB_APP_OBJS0  = iperf.o main.o mempool.o ring.o
STUB_APP_OBJS	= $(addprefix $(STUB_APP_OBJ_DIR)/,$(STUB_APP_OBJS0))

include $(MINIOS_ROOT)/stub.mk

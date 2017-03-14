######################################
## tuning options
######################################
CONFIG_SELECT_POLL			?= y

## vif
CONFIG_NETFRONT_PERSISTENT_GRANTS 	?= y
CONFIG_NETFRONT_GSO		 	?= y
CONFIG_NETFRONT_WAITFORTX		?= y
CONFIG_NOAVXMEMCPY			?= n
CONFIG_NETFRONT_POLL		 	?= $(CONFIG_SELECT_POLL)

## lwip
CONFIG_LWIP_HEAP_ONLY			?= y
CONFIG_LWIP_POOLS_ONLY			?= n
CONFIG_LWIP_WAITFORTX			?= y
CONFIG_LWIP_PARTIAL_CHECKSUM		?= $(CONFIG_NETFRONT_GSO)
CONFIG_LWIP_GSO				?= n
CONFIG_LWIP_BATCHTX			?= n
CONFIG_LWIP_WND_SCALE			?= y
CONFIG_LWIP_NUM_TCPCON			?= 64

######################################
## debugging options
######################################
CONFIG_DEBUG				?= n
CONFIG_DEBUG_LWIP			?= n
#CFLAGS				+= -DLWIP_STATS_DISPLAY=1

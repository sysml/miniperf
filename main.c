#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <kernel.h>
#include <sched.h>
#include <pkt_copy.h>
#include <mempool.h>

#include <lwip/ip4_addr.h>
#include <netif/etharp.h>
#include <lwip/netif.h>
#include <lwip/inet.h>
#include <lwip/tcp.h>
#include <lwip/tcp_impl.h>
#include <lwip/tcpip.h>
#include <lwip/dhcp.h>
#include <lwip/dns.h>
#include <lwip/ip_frag.h>
#include <lwip/init.h>
#include <lwip/stats.h>

#ifdef CONFIG_NMWRAP
#include <lwip-nmwrap.h>
#else
#include <lwip-net.h>
#endif
#include "iperf.h"

#ifndef min
#define min(a, b) \
    ({ __typeof__ (a) __a = (a); \
       __typeof__ (b) __b = (b); \
       __a < __b ? __a : __b; })
#endif
#ifndef min3
#define min3(a, b, c) (min(min((a), (b)), (c)))
#endif
#ifndef min4
#define min4(a, b ,c, d) (min(min((a), (b)), min((c), (d))))
#endif

/* checks if a number is a power of two. Copied from BNX2X driver (Linux) */
#ifndef POWER_OF_2
  #define POWER_OF_2(x)   ((0 != (x)) && (0 == ((x) & ((x)-1))))
#endif

#ifdef CONFIG_LWIP_SINGLETHREADED
#define RXBURST_LEN (LNMW_MAX_RXBURST_LEN)

/* runs (func) a command on a timeout */
#define TIMED(ts_now, ts_tmr, interval, func)                        \
	do {                                                         \
		if (unlikely(((ts_now) - (ts_tmr)) >= (interval))) { \
			if ((ts_tmr))                                \
				(func);                              \
			(ts_tmr) = (ts_now);                         \
		}                                                    \
	} while(0)
#endif /* CONFIG_LWIP_MINIMAL */

struct _args {
    int             dhclient;
    struct eth_addr mac;
    struct ip_addr  ip;
    struct ip_addr  mask;
    struct ip_addr  gw;
    struct ip_addr  dns0;
    struct ip_addr  dns1;
} args;

static int shall_exit = 0;


static inline void print_dot(void)
{
	printf(".");
	fflush(stdout);
}

int main(int argc, char *argv[])
{
    struct _args args;
    struct netif netif;
#ifdef CONFIG_LWIP_SINGLETHREADED
    uint64_t now;

    uint64_t ts_dot = 0;
    uint64_t ts_tcp = 0;
    uint64_t ts_etharp = 0;
    uint64_t ts_ipreass = 0;
    uint64_t ts_dns = 0;
    uint64_t ts_dhcp_fine = 0;
    uint64_t ts_dhcp_coarse = 0;
#endif

    IP4_ADDR(&args.ip,   10,  100,  0,  3); /* default */
    IP4_ADDR(&args.mask, 255, 255, 255, 0); /* default */
    IP4_ADDR(&args.gw,   0,   0,   0,   0); /* default */
    IP4_ADDR(&args.dns0, 0,   0,   0,   0); /* default */
    IP4_ADDR(&args.dns1, 0,   0,   0,   0); /* default */
    args.dhclient = 0;                      /* default */

    /* -----------------------------------
     * lwIP initialization
     * ----------------------------------- */
#ifdef CONFIG_LWIP_SINGLETHREADED
    lwip_init(); /* single threaded */
#else
    tcpip_init(NULL, NULL); /* multi-threaded */
#endif

    /* -----------------------------------
     * network interface initialization
     * ----------------------------------- */
#ifdef CONFIG_LWIP_SINGLETHREADED
#ifdef CONFIG_NMWRAP
    if (!netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
                   nmwif_init, ethernet_input)) {
#else
    /* TODO: Non-nmwrap devices are not yet implemented for single-threaded! */
#endif /* CONFIG_NMWRAP */
#else
#ifdef CONFIG_NMWRAP
    if (!netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
                   nmwif_init, tcpip_input)) {
#else
    if (!netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
                   netfrontif_init, tcpip_input)) {
#endif /* CONFIG_NMWRAP */

#endif /* CONFIG_LWIP_SINGLETHREADED */
    /* device init function is user-defined
     * use ip_input instead of ethernet_input for non-ethernet hardware
     * (this function is assigned to netif.input and should be called by
     * the hardware driver) */
    /*
     * The final parameter input is the function that a driver will
     * call when it has received a new packet. This parameter
     * typically takes one of the following values:
     * ethernet_input: If you are not using a threaded environment
     *                 and the driver should use ARP (such as for
     *                 an Ethernet device), the driver will call
     *                 this function which permits ARP packets to
     *                 be handled, as well as IP packets.
     * ip_input:       If you are not using a threaded environment
     *                 and the interface is not an Ethernet device,
     *                 the driver will directly call the IP stack.
     * tcpip_ethinput: If you are using the tcpip application thread
     *                 (see lwIP and threads), the driver uses ARP,
     *                 and has defined the ETHARP_TCPIP_ETHINPUT lwIP
     *                 option. This function is used for drivers that
     *                 passes all IP and ARP packets to the input function.
     * tcpip_input:    If you are using the tcpip application thread
     *                 and have defined ETHARP_TCPIP_INPUT option.
     *                 This function is used for drivers that pass
     *                 only IP packets to the input function.
     *                 (The driver probably separates out ARP packets
     *                 and passes these directly to the ARP module).
     *                 (Someone please recheck this: in lwip 1.4.1
     *                 there is no tcpip_ethinput() ; tcp_input()
     *                 handles ARP packets as well).
     */
        printf("FATAL: Could not initialize the network interface\n");
        goto out;
    }
    netif_set_default(&netif);
    netif_set_up(&netif);
    if (args.dhclient)
        dhcp_start(&netif);

    /* register iperf server */
    register_iperfsrv();

    /* -----------------------------------
     * Processing loop
     * ----------------------------------- */
    while(likely(!shall_exit)) {
#ifdef CONFIG_LWIP_SINGLETHREADED
        /* NIC handling loop (single threaded lwip) */
#ifdef CONFIG_NMWRAP
	nmwif_handle(&netif, RXBURST_LEN);
#else
	/* TODO: Handling a non-nmwrap device is not yet implemented! */
#endif /* CONFIG_NMWRAP */
	/* Process lwip network-related timers */
        now = NSEC_TO_MSEC(NOW());
        TIMED(now, ts_etharp,  ARP_TMR_INTERVAL, etharp_tmr());
        TIMED(now, ts_ipreass, IP_TMR_INTERVAL,  ip_reass_tmr());
        TIMED(now, ts_tcp,     TCP_TMR_INTERVAL, tcp_tmr());
        TIMED(now, ts_dns,     DNS_TMR_INTERVAL, dns_tmr);
        if (args.dhclient) {
	        TIMED(now, ts_dhcp_fine,   DHCP_FINE_TIMER_MSECS,   dhcp_fine_tmr());
	        TIMED(now, ts_dhcp_coarse, DHCP_COARSE_TIMER_MSECS, dhcp_coarse_tmr());
        }

        TIMED(now, ts_dot, 5000, print_dot());

        //schedule(); /* not required for network processing */
#else
        msleep(5000);
        print_dot();
#endif /* CONFIG_LWIP_SINGLETHREADED */
    }

    /* -----------------------------------
     * Shutdown
     * ----------------------------------- */
    printf("System is going to halt now\n");
    unregister_iperfsrv();
    netif_set_down(&netif);
    netif_remove(&netif);
out:
    return 0;
}

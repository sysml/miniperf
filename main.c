#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <kernel.h>
#include <sched.h>
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

#include <lwip-net.h>
#include "iperf.h"

#define MAX_NB_STATIC_ARP_ENTRIES 6
#define ANI_INTERVAL_MSEC 5000

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

/* runs (func) a command on a timeout */
#define TIMED(ms_now, ms_till, ms_next, ms_interval, func)	     \
	do {                                                         \
		if (unlikely((ms_next) <= (ms_now))) {		     \
			(ms_next) = (ms_now) + (ms_interval);	     \
			(func);				     \
		}						     \
		/* update ms_till only if current nextin	     \
		 * is smaller than the passed one */		     \
		(ms_till) = (ms_next) < (ms_till) ? (ms_next) : (ms_till); \
	} while(0)

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

static struct _args {
    int dhclient;
    ip4_addr_t ip;
    ip4_addr_t mask;
    ip4_addr_t gw;

    /* static arp entries can only be added if DHCP is disabled */
    struct {
	    ip4_addr_t ip;
	    struct eth_addr mac;
    } sarp_entry[MAX_NB_STATIC_ARP_ENTRIES];
    unsigned int    nb_sarp_entries;

    unsigned int    debug_msec;
} args;

static int parse_args_setval_cut(char delimiter, char **out_presnip, char **out_postsnip,
                                 const char *buf)
{
	size_t len = strlen(buf);
	size_t p;

	for (p = 0; p < len; ++p) {
		if (buf[p] == delimiter) {
			*out_presnip = strndup(buf, p);
			*out_postsnip = strdup(&buf[p+1]);
			if (!*out_presnip || !*out_postsnip) {
				if (out_postsnip)
					free(*out_postsnip);
				if (out_presnip)
					free(*out_presnip);
				return -ENOMEM;
			}
			return 0;
		}
	}

	return -1; /* delimiter not found */
}

static int parse_args_setval_ipv4cidr(ip4_addr_t *out_ip, ip4_addr_t *out_mask, const char *buf)
{
	int ip0, ip1, ip2, ip3;
	int rprefix;
	uint32_t mask;

	if (sscanf(buf, "%d.%d.%d.%d/%d", &ip0, &ip1, &ip2, &ip3, &rprefix) != 5)
		return -1;
	if ((ip0 < 0 || ip0 > 255) ||
	    (ip1 < 0 || ip1 > 255) ||
	    (ip2 < 0 || ip2 > 255) ||
	    (ip3 < 0 || ip3 > 255) ||
	    (rprefix < 0 || rprefix > 32))
		return -1;

	IP4_ADDR(out_ip, ip0, ip1, ip2, ip3);
	if (rprefix == 0)
		mask = 0x0;
	else if (rprefix == 32)
		mask = 0xFFFFFFFF;
	else
		mask = ~((1 << (32 - rprefix)) - 1);
	IP4_ADDR(out_mask,
	         (mask & 0xFF000000) >> 24,
	         (mask & 0x00FF0000) >> 16,
	         (mask & 0x0000FF00) >> 8,
	         (mask & 0x000000FF));
	return 0;
}

static int parse_args_setval_ipv4(ip4_addr_t *out, const char *buf)
{
	int ip0, ip1, ip2, ip3;

	if (sscanf(buf, "%d.%d.%d.%d", &ip0, &ip1, &ip2, &ip3) != 4)
		return -1;
	if ((ip0 < 0 || ip0 > 255) ||
	    (ip1 < 0 || ip1 > 255) ||
	    (ip2 < 0 || ip2 > 255) ||
	    (ip3 < 0 || ip3 > 255))
		return -1;

	IP4_ADDR(out, ip0, ip1, ip2, ip3);
	return 0;
}

static int parse_args_setval_hwaddr(struct eth_addr *out, const char *buf)
{
	uint8_t hwaddr[6];

	if (sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
	           &hwaddr[0], &hwaddr[1], &hwaddr[2],
	           &hwaddr[3], &hwaddr[4], &hwaddr[5]) != 6)
		return -1;

	out->addr[0] = hwaddr[0];
	out->addr[1] = hwaddr[1];
	out->addr[2] = hwaddr[2];
	out->addr[3] = hwaddr[3];
	out->addr[4] = hwaddr[4];
	out->addr[5] = hwaddr[5];
	return 0;
}

static int parse_args_setval_int(int *out, const char *buf)
{
	if (sscanf(buf, "%d", out) != 1)
		return -1;
	return 0;
}

static int parse_args(int argc, char *argv[])
{
    char *presnip;
    char *postsnip;
    int opt;
    int ret;
    int ival;

    /* default arguments */
    memset(&args, 0, sizeof(args));
    IP4_ADDR(&args.ip,   192, 168, 128, 124);
    IP4_ADDR(&args.mask, 255, 255, 255, 252);
    IP4_ADDR(&args.gw,     0,   0,   0,   0);
    args.dhclient = 1; /* dhcp as default */
    args.nb_sarp_entries = 0;
    args.debug_msec = 0;

    while ((opt = getopt(argc, argv, "i:g:a:d:")) != -1) {
         switch(opt) {
         case 'i': /* IP address/mask */
	      ret = parse_args_setval_ipv4cidr(&args.ip, &args.mask, optarg);
	      if (ret < 0) {
	           printk("invalid host IP in CIDR notation specified (e.g., 192.168.0.2/24)\n");
	           return -1;
              }
	      args.dhclient = 0;
              break;
         case 'g': /* gateway */
	      ret = parse_args_setval_ipv4(&args.gw, optarg);
	      if (ret < 0) {
	           printk("invalid gateway IP specified (e.g., 192.168.0.1)\n");
	           return -1;
              }
              break;
         case 'a': /* static arp entry */
	      if (args.nb_sarp_entries == (MAX_NB_STATIC_ARP_ENTRIES - 1)) {
		   printk("At most %d static ARP entries can be specified\n",
		          MAX_NB_STATIC_ARP_ENTRIES);
		   return -1;
	      }
	      ret = parse_args_setval_cut('/', &presnip, &postsnip, optarg);
	      if (ret < 0) {
		   if (ret == -ENOMEM)
			printk("static ARP parsing error: Out of memory\n");
		   else
			printk("invalid static ARP entry specified (e.g., 01:23:45:67:89:AB/192.168.0.1)\n");
	           return -1;
              }
	      ret = parse_args_setval_hwaddr(&args.sarp_entry[args.nb_sarp_entries].mac, presnip);
	      if (ret < 0) {
	           printk("invalid static ARP entry specified (e.g., 01:23:45:67:89:AB/192.168.0.1)\n");
	           free(postsnip);
	           free(presnip);
	           return -1;
              }
	      ret = parse_args_setval_ipv4(&args.sarp_entry[args.nb_sarp_entries].ip, postsnip);
	      if (ret < 0) {
	           printk("invalid static ARP entry specified (e.g., 01:23:45:67:89:AB/192.168.0.1)\n");
	           free(postsnip);
	           free(presnip);
	           return -1;
              }
	      free(postsnip);
	      free(presnip);
	      args.nb_sarp_entries++;
              break;
         case 'd': /* debug interval */
	      ret = parse_args_setval_int(&ival, optarg);
	      if (ret < 0 || ival < 0) {
	           printk("invalid debug output interval specified\n");
	           return -1;
              }
	      args.debug_msec = ival * 1000;
              break;

         default:
	      return -1;
         }
    }

    if (args.nb_sarp_entries > 0 && args.dhclient != 0) {
         printk("Static ARP entries cannot specified when DHCP client is enabled\n");
	 return -1;
    }

    return 0;
}

static volatile int shall_exit = 0;
static volatile int shall_reboot = 0;
static volatile int shall_suspend = 0;

void app_shutdown(unsigned reason)
{
    switch (reason) {
    case TARGET_SHTDN_POWEROFF:
	    printk("Poweroff requested\n");
	    shall_reboot = 0;
	    shall_exit = 1;
	    break;
    case TARGET_SHTDN_REBOOT:
	    printk("Reboot requested\n");
	    shall_reboot = 1;
	    shall_exit = 1;
	    break;
    case TARGET_SHTDN_SUSPEND:
	    printk("Suspend requested\n");
	    shall_suspend = 1;
	    break;
    default:
	    printk("Unknown shutdown action requested: %d. Ignoring\n", reason);
	    break;
    }
}

static inline void print_ani(void)
{
	printf(".");
	fflush(stdout);
}

static inline void print_debug(void)
{
	printk("\n---------------------------------------------------------");
#if LWIP_STATS_DISPLAY
	stats_display();
#endif
	printk("\n---------------------------------------------------------\n");
}

int main(int argc, char *argv[])
{
    struct netif netif;
#ifdef CONFIG_SELECT_POLL
    fd_set poll_rfdset;
    int poll_netif_fd;
    struct timeval poll_to;
#endif
    uint64_t ts_now;
    uint64_t ts_till;
    uint64_t ts_to;
    uint64_t ts_ani = 0;
    uint64_t ts_debug = 0;
#ifdef CONFIG_LWIP_NOTHREADS
    uint64_t ts_tcp = 0;
    uint64_t ts_etharp = 0;
    uint64_t ts_ipreass = 0;
    uint64_t ts_dhcp_fine = 0;
    uint64_t ts_dhcp_coarse = 0;
#endif
    /* -----------------------------------
     * argument parsing
     * ----------------------------------- */
    if (parse_args(argc, argv) < 0) {
	    printk("Argument parsing error!\n" \
	           "Please check your arguments\n");
	    goto out;
    }

    /* -----------------------------------
     * lwIP initialization
     * ----------------------------------- */
#ifdef CONFIG_LWIP_NOTHREADS
    lwip_init(); /* single threaded */
#else
    tcpip_init(NULL, NULL); /* multi-threaded */
#endif

    /* -----------------------------------
     * network interface initialization
     * ----------------------------------- */
    printk("Initialize network interface 0: ");
    if (args.dhclient)
      printk("DHCP\n");
    else
      printk("%u.%u.%u.%u netmask %u.%u.%u.%u gw %u.%u.%u.%u\n",
             ip4_addr1(&args.ip),   ip4_addr2(&args.ip),   ip4_addr3(&args.ip),   ip4_addr4(&args.ip),
	     ip4_addr1(&args.mask), ip4_addr2(&args.mask), ip4_addr3(&args.mask), ip4_addr4(&args.mask),
	     ip4_addr1(&args.gw),   ip4_addr2(&args.gw),   ip4_addr3(&args.gw),   ip4_addr4(&args.gw));
#ifdef CONFIG_LWIP_NOTHREADS
    if (!netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
		   netfrontif_init, ethernet_input)) {
#else
    if (!netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
		   netfrontif_init, tcpip_input)) {
#endif
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
#ifdef CONFIG_SELECT_POLL
    poll_netif_fd = netfrontif_fd(&netif);
#endif
    if (args.dhclient)
        dhcp_start(&netif);

    /* register iperf server */
    register_iperfsrv();

    /* -----------------------------------
     * Initialize select/poll
     * ----------------------------------- */
#ifdef CONFIG_SELECT_POLL
    FD_ZERO(&poll_rfdset);
#endif
    ts_to = 0;

    /* -----------------------------------
     * Processing loop
     * ----------------------------------- */
    printk("Entering main event loop: ");
#ifdef CONFIG_LWIP_NOTHREADS
#ifdef CONFIG_SELECT_POLL
    printk("select/poll\n");
#else
    printk("schedule\n");
#endif /* CONFIG_SELECT_POLL */
#else /* CONFIG_LWIP_NOTHREADS */
    printk("msleep\n");
#endif /* defined CONFIG_LWIP_NOTHREADS */

    while(likely(!shall_exit)) {
	if (ts_to) {
#ifdef CONFIG_LWIP_NOTHREADS
#ifdef CONFIG_SELECT_POLL
		/* select with ignoring return reason */
		FD_SET(poll_netif_fd, &poll_rfdset);
		poll_to.tv_sec = ts_to / 1000;
		poll_to.tv_usec = (ts_to % 1000) * 1000;
		select(poll_netif_fd + 1, &poll_rfdset, NULL, NULL, &poll_to);
#else
		schedule();
#endif /* CONFIG_SELECT_POLL */
#else /* CONFIG_LWIP_NOTHREADS */
		msleep(ts_to); /* yield CPU */
#endif /* defined CONFIG_LWIP_NOTHREADS */
	}

#ifdef CONFIG_LWIP_NOTHREADS
        /* NIC handling loop (single threaded lwip) */
	netfrontif_poll(&netif);
#endif /* CONFIG_LWIP_NOTHREADS */

        ts_now  = NSEC_TO_MSEC(NOW());
	ts_till = UINT64_MAX;

#ifdef CONFIG_LWIP_NOTHREADS
	/* Process lwip network-related timers */
        TIMED(ts_now, ts_till, ts_etharp,  ARP_TMR_INTERVAL, etharp_tmr());
        TIMED(ts_now, ts_till, ts_ipreass, IP_TMR_INTERVAL,  ip_reass_tmr());
        TIMED(ts_now, ts_till, ts_tcp,     TCP_TMR_INTERVAL, tcp_tmr());
        if (args.dhclient) {
	        TIMED(ts_now, ts_till, ts_dhcp_fine,   DHCP_FINE_TIMER_MSECS,   dhcp_fine_tmr());
	        TIMED(ts_now, ts_till, ts_dhcp_coarse, DHCP_COARSE_TIMER_MSECS, dhcp_coarse_tmr());
        }
#endif /* CONFIG_LWIP_NOTHREADS */
        TIMED(ts_now, ts_till, ts_ani,  ANI_INTERVAL_MSEC, print_ani());
	if (unlikely(args.debug_msec))
	  TIMED(ts_now, ts_till, ts_debug,  args.debug_msec, print_debug());
        ts_to = ts_till - ts_now;

        if (unlikely(shall_suspend)) {
            printk("System is going to suspend now\n");
            netif_set_down(&netif);
            netif_remove(&netif);

            kernel_suspend();

            printk("System woke up from suspend\n");
            netif_set_default(&netif);
            netif_set_up(&netif);
#ifdef CONFIG_SELECT_POLL
            poll_netif_fd = netfrontif_fd(&netif);
#endif
            if (args.dhclient)
                dhcp_start(&netif);
            shall_suspend = 0;
        }
    }

    /* -----------------------------------
     * Shutdown
     * ----------------------------------- */
    if (shall_reboot)
	    printk("System is going down to reboot now\n");
    else
	    printk("System is going down to halt now\n");
    unregister_iperfsrv();
    netif_set_down(&netif);
    netif_remove(&netif);
out:
    if (shall_reboot)
	    kernel_shutdown(SHUTDOWN_reboot);
    kernel_shutdown(SHUTDOWN_poweroff);

    return 0;
}

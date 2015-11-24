/**
 *
 * Code based partly on: https://github.com/lsgunth/lwip_contrib.git
 * and
 * http://docs.lpcware.com/lpcopen/v1.03/lpc17xx__40xx_2examples_2misc_2iperf__server_2iperf__server_8c_source.html
 *
 * TODO: include external code license
 *
 * */
#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <kernel.h>
#include <sched.h>
#include <mempool.h>

#include <lwip/tcp.h>

#include "iperf.h"

#define SESSMP_NBOBJ (MEMP_NUM_TCP_PCB)

#define IPERF_PORT 5001
#define ICMD_CONNECT_NOW  0x00000001
#define ICMD_HEADER       0x80000000

//#define MANUALLY_DEFINED_AMOUNT

#ifdef MANUALLY_DEFINED_AMOUNT
/* Amount of bytes to send during test*/
#define AMOUNT 107374182400
#endif

struct iperfsrv {
    struct tcp_pcb *tpcb;
    struct mempool *sessmp;

    uint32_t refcount;
};

struct iperf_cmd_hdr {
    int32_t flags;
    int32_t numThreads;
    int32_t mPort;
    int32_t bufferlen;
    int32_t mWinBand;
    int32_t mAmount;
};
#define IPERF_CMD_HDRLEN (sizeof(struct iperf_cmd_hdr))

enum iperf_sess_close
{
    ISC_CLOSE = 0,
    ISC_ABORT,
    ISC_KILL,
};

enum iperfsrv_state
{
    ES_NONE = 0,
    ES_CONNECTED,
    ES_CONNECTING,
    ES_RECEIVED,
    ES_CLOSING
};

enum iperfsrv_type
{
    IT_UNINITIALIZED = 0,
    IT_RECEIVER,
    IT_SENDER
};

#define DATA_SIZE 4096
static unsigned long send_data[DATA_SIZE];

struct iperfsrv_sess {
    struct mempool_obj *obj; /* reference to mempool object where
                              * this struct is embedded in */
    struct iperfsrv *server;
    struct tcp_pcb  *tpcb;

    enum iperfsrv_state state;

    int recvhdr;
#ifdef MANUALLY_DEFINED_AMOUNT
    uint64_t amount;
#else
    int32_t amount;
#endif
    uint8_t retries;

    /* for connecting to client after finish receiving */
    uint8_t connect_after;
    struct iperf_cmd_hdr chdr;

    unsigned long sent_bytes;

    /* pbuf (chain) to recycle */
    struct pbuf *p;

    enum iperfsrv_type type;
    uint32_t id;
};

static void iperfsrv_sessmp_objinit(struct mempool_obj *obj, void *unused)
{
    struct iperfsrv_sess *sess = obj->data;
    LWIP_UNUSED_ARG(unused);

    sess->obj   = obj;
    sess->tpcb  = NULL;
    sess->type  = IT_UNINITIALIZED;
    sess->state = ES_NONE;
}

static err_t iperfsrv_accept(void *argp, struct tcp_pcb *new_tpcb, err_t err);
static err_t iperfsrv_recv(void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void  iperfsrv_error(void *argp, err_t err);
static err_t iperfsrv_close(struct iperfsrv_sess *sess, enum iperf_sess_close type);
static err_t iperfsrv_sender_connected(void *arg, struct tcp_pcb *tpcb, err_t err);
static void  iperfsrv_sender_connect_err(void *arg, err_t err);
static err_t iperfsrv_sender_sent(void *arg, struct tcp_pcb *tpcb, u16_t len);
static err_t iperfsrv_sender_connect(struct iperfsrv *server, const struct iperf_cmd_hdr *chdr, const ip_addr_t *rip, uint16_t rport);

static struct iperfsrv *server = NULL; /* server instance */

int register_iperfsrv(void)
{
    err_t err;
    int i;
    int ret = 0;

    ASSERT(server == NULL);

    for (i = 0; i < sizeof(send_data) / sizeof(*send_data); i++)
        send_data[i] = i;

    server = _xmalloc(sizeof(struct iperfsrv), 64);
    if (!server) {
        ret = -ENOMEM;
        goto out;
    }

    server->sessmp = alloc_mempool(SESSMP_NBOBJ, sizeof(struct iperfsrv_sess), \
                                   64, 0, 0, iperfsrv_sessmp_objinit, NULL, 0);
    if (!server->sessmp) {
        ret = -ENOMEM;
        goto out_free_server;
    }

    server->refcount = 0;
    server->tpcb     = tcp_new();
    if (!server->tpcb) {
        ret = -ENOMEM;
        goto out_free_mp;
    }

    err = tcp_bind(server->tpcb, IP_ADDR_ANY, IPERF_PORT);
    if (err != ERR_OK) {
        ret = -ENOMEM;
        goto out_close_server;
    }

    server->tpcb = tcp_listen(server->tpcb);   /* transform it to a listener */
    tcp_arg(server->tpcb, server);             /* set callback argp          */
    tcp_accept(server->tpcb, iperfsrv_accept); /* set accept callback        */

    printf("IPerf server started\n");
    printk("------------------------------------------------------------\n");
    printk(" Server listening on TCP port %u \n", IPERF_PORT);
    printk("------------------------------------------------------------\n");
    return 0;

out_close_server:
    tcp_close(server->tpcb);

out_free_mp:
    free_mempool(server->sessmp);

out_free_server:
    xfree(server);

out:
    return ret;
}

void unregister_iperfsrv(void)
{
    ASSERT(server != NULL);
    ASSERT(server->refcount == 0);

    tcp_close(server->tpcb);
    free_mempool(server->sessmp);
    xfree(server);

    server = NULL;
}

static err_t iperfsrv_accept(void *argp, struct tcp_pcb *new_tpcb, err_t err)
{
    struct iperfsrv *server = argp;
    struct mempool_obj *obj;
    struct iperfsrv_sess *sess;

    LWIP_UNUSED_ARG(err);

    obj = mempool_pick(server->sessmp);
    if (!obj)
        return ERR_MEM;

    sess = obj->data;

    sess->retries    = 0;
    sess->server     = server;
    sess->type       = IT_RECEIVER;
    sess->state      = ES_CONNECTED;
    sess->tpcb       = new_tpcb;
    sess->recvhdr    = 1; /* enable commands */
    sess->sent_bytes = 0;

    sess->connect_after = 0;

    /* register callbacks for this connection */
    tcp_arg (sess->tpcb, sess);
    tcp_recv(sess->tpcb, iperfsrv_recv);
    tcp_err (sess->tpcb, iperfsrv_error);
    tcp_sent(sess->tpcb, iperfsrv_sender_sent);
    tcp_poll(sess->tpcb, NULL, 0);
    tcp_setprio(sess->tpcb, TCP_PRIO_MAX);

    server->refcount++;
    sess->id = server->refcount;

    printk("[%3u] Connection from %u.%u.%u.%u:%"PRIu16"\n", sess->id,
	   ip4_addr1(&sess->tpcb->remote_ip), ip4_addr2(&sess->tpcb->remote_ip),
	   ip4_addr3(&sess->tpcb->remote_ip), ip4_addr4(&sess->tpcb->remote_ip),
	   sess->tpcb->remote_port);

    return ERR_OK;
}

static err_t iperfsrv_close(struct iperfsrv_sess *sess, enum iperf_sess_close type)
{
    err_t err;

    if (sess->connect_after) {
        sess->connect_after = 0;
        iperfsrv_sender_connect(sess->server, (const struct iperf_cmd_hdr *) &(sess->chdr), &sess->tpcb->remote_ip, IPERF_PORT);
        return ERR_OK;
    }

    printk("[%3u] Connection to %u.%u.%u.%u:%"PRIu16" closed\n", sess->id,
	   ip4_addr1(&sess->tpcb->remote_ip), ip4_addr2(&sess->tpcb->remote_ip),
	   ip4_addr3(&sess->tpcb->remote_ip), ip4_addr4(&sess->tpcb->remote_ip),
	   sess->tpcb->remote_port);

    /* disable this session */
    tcp_arg (sess->tpcb, NULL);
    tcp_recv(sess->tpcb, NULL);
    tcp_err (sess->tpcb, NULL);
    tcp_sent(sess->tpcb, NULL);
    tcp_poll(sess->tpcb, NULL, 0);

    /* terminate connection */
    switch (type) {
    case ISC_CLOSE:
        err = tcp_close(sess->tpcb);
        if (likely(err == ERR_OK))
	        break;
    case ISC_ABORT:
        tcp_abort(sess->tpcb);
        err = ERR_ABRT; /* lwip callback functions need to be notified */
        break;
    default: /* ISC_KILL */
        err = ERR_OK;
        break;
    }
    sess->tpcb = NULL;

    /* unregister session */
    sess->server->refcount--;
    mempool_put(sess->obj);

    return err;
}

static err_t iperfsrv_sender_connected(void *arg, struct tcp_pcb *tpcb, err_t err)
{
    struct iperfsrv_sess *sess = (struct iperfsrv_sess *) arg;
    BUG_ON(sess->type != IT_SENDER);

    sess->state = ES_CONNECTED;

    printk("[%3u] Connected to %u.%u.%u.%u:%"PRIu16"\n", sess->id,
	   ip4_addr1(&sess->tpcb->remote_ip), ip4_addr2(&sess->tpcb->remote_ip),
	   ip4_addr3(&sess->tpcb->remote_ip), ip4_addr4(&sess->tpcb->remote_ip),
	   sess->tpcb->remote_port);

    /* start sending chain */
    return iperfsrv_sender_sent(sess, sess->tpcb, 0);
}

static void iperfsrv_sender_connect_err(void *arg, err_t err)
{
    struct iperfsrv_sess *sess = (struct iperfsrv_sess *) arg;
    BUG_ON(sess->type != IT_SENDER);

    printk("[%3u] Connection to %u.%u.%u.%u:%"PRIu16" failed: %d\n", sess->id,
	   ip4_addr1(&sess->tpcb->remote_ip), ip4_addr2(&sess->tpcb->remote_ip),
	   ip4_addr3(&sess->tpcb->remote_ip), ip4_addr4(&sess->tpcb->remote_ip),
	   sess->tpcb->remote_port, err);

    /* close connection */
    iperfsrv_close(sess, ISC_ABORT);
}

static err_t iperfsrv_sender_connect(struct iperfsrv *server, const struct iperf_cmd_hdr *chdr, const ip_addr_t *rip, uint16_t rport)
{
    struct mempool_obj *obj;
    struct iperfsrv_sess *sess;
    err_t err;

    obj = mempool_pick(server->sessmp);
    if (!obj) {
        err = ERR_MEM;
        goto err_out;
    }

    sess = obj->data;

    sess->tpcb       = tcp_new();
    if (!sess->tpcb) {
        err = ERR_MEM;
        goto err_freeobj;
    }

    sess->retries    = 0;
    sess->server     = server;
    sess->state      = ES_CONNECTING;
    sess->type       = IT_SENDER;
    sess->recvhdr    = 0; /* disable commands */
    sess->sent_bytes = 0;

#ifdef MANUALLY_DEFINED_AMOUNT
    sess->amount = AMOUNT;
#else
    sess->amount = ntohl(chdr->mAmount);
    //sess->amount *= TICK_FREQ;
    //sess->amount /= 100;
#endif

    /* register callbacks for this connection */
    tcp_arg (sess->tpcb, sess);
    tcp_err (sess->tpcb, iperfsrv_sender_connect_err);
    tcp_recv(sess->tpcb, iperfsrv_recv);
    tcp_sent(sess->tpcb, iperfsrv_sender_sent);
    tcp_poll(sess->tpcb, NULL, 0);
    tcp_setprio(sess->tpcb, TCP_PRIO_MAX);

    server->refcount++;
    sess->id = server->refcount;

    err = tcp_connect(sess->tpcb, rip, rport, iperfsrv_sender_connected);
    if (err != ERR_OK)
        goto err_close_tpcb;
    return ERR_OK;

 err_close_tpcb:
    server->refcount--;
    tcp_abort(sess->tpcb);
 err_freeobj:
    mempool_put(obj);
 err_out:
    printk("[%3u] Failed to connect to %u.%u.%u.%u:%"PRIu16": %d\n", server->refcount + 1,
	   ip4_addr1(&rip), ip4_addr2(&rip), ip4_addr3(&rip), ip4_addr4(&rip),
	   rport, err);
    return err;
}

static inline err_t iperfsrv_command(struct iperfsrv_sess *sess, struct pbuf *p)
{
    struct iperf_cmd_hdr *chdr;

    if (p->len >= IPERF_CMD_HDRLEN) {
        chdr = (struct iperf_cmd_hdr *) p->payload;

        if (chdr->flags & htonl(ICMD_HEADER)) {
            if ((chdr->flags & htonl(ICMD_CONNECT_NOW))) {
                printk("[%3u] Received connect command from client\n", sess->id);
                return iperfsrv_sender_connect(sess->server, chdr, &sess->tpcb->remote_ip, IPERF_PORT);
            }
            else { /*connect only after receiving*/
                sess->connect_after   = 1;

                sess->chdr.flags      = chdr->flags;
                sess->chdr.numThreads = chdr->numThreads;
                sess->chdr.mPort      = chdr->mPort;
                sess->chdr.bufferlen  = chdr->bufferlen;
                sess->chdr.mWinBand   = chdr->mWinBand;
                sess->chdr.mAmount    = chdr->mAmount;
            }
        }
    }
    return ERR_OK;
}

/*----------------------------------------------------------------------------
 * Part of the following code is derived from:
 *  http://docs.lpcware.com/lpcopen/v1.03/lpc17xx__40xx_2examples_2misc_2iperf__server_2iperf__server_8c_source.html
 *----------------------------------------------------------------------------*/
static err_t iperfsrv_recv(void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    struct iperfsrv_sess *sess = argp;
    err_t ret_err;

    if (unlikely(!p)) {
        /* remote host closed connection */
        sess->state = ES_CLOSING;
        return iperfsrv_close(sess, ISC_CLOSE);
    } else if (unlikely(err != ERR_OK)) {
        /* cleanup, for unkown reason */
        if (p) {
            sess->p = NULL;
            pbuf_free(p);
        }
        return err;
    }

    if (unlikely(sess->recvhdr)) {
        ret_err = iperfsrv_command(sess, p);
	    if (unlikely(ret_err != ERR_OK))
	        printk("[%3u] Failed to execute command from client: %d\n", sess->id, err);
	    sess->recvhdr = 0;
    }

    ret_err = ERR_OK;
    switch (sess->state) {
    case ES_CONNECTED:
        /* receive the package and discard it silently for testing
           reception bandwidth */
        sess->p = p;
        pbuf_free(p);
        tcp_recved(tpcb, p->tot_len);
        break;

    case ES_CLOSING:
        /* odd case, remote side closing twice, trash data */
        tcp_recved(tpcb, p->tot_len);
        sess->p = NULL;
        pbuf_free(p);
        break;

    default:
        /* unkown es->state, trash data  */
        tcp_recved(tpcb, p->tot_len);
        sess->p = NULL;
        pbuf_free(p);
        break;
    }

    return ret_err;
}

static void iperfsrv_error(void *argp, err_t err)
{
    struct iperfsrv_sess *sess = argp;

    LWIP_UNUSED_ARG(err);

    if (sess)
      iperfsrv_close(sess, ISC_ABORT);
}

static inline err_t iperfsrv_sender_done(struct iperfsrv_sess *sess)
{
    tcp_output(sess->tpcb);
    return iperfsrv_close(sess, ISC_CLOSE);
}

static err_t iperfsrv_sender_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    struct iperfsrv_sess *sess = (struct iperfsrv_sess *) arg;

    err_t err;
    size_t amount = sizeof(send_data);

try_send:

    if (sess->amount > 0 && sess->sent_bytes > sess->amount)
        return iperfsrv_sender_done(sess);

    err = tcp_write(tpcb, send_data, amount, 0);

    if (unlikely(err == ERR_MEM)) {
        if (amount > 1 && tcp_sndbuf(tpcb)) { /* if there is still space available   */
            amount >>= 1;                     /* divide amount of bytes to send by 2 */
            goto try_send;                    /* and try again */
        }
        else
            goto out;
    }

    if (likely(err == ERR_OK)) {
        sess->sent_bytes += amount;
        goto try_send;
    }

out:
    return ERR_OK;
}

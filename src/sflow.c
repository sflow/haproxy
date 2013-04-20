/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Copyright (c) 2002-2013 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include <sys/time.h>

#include <inttypes.h>

#include <common/appsession.h>
#include <common/base64.h>
#include <common/chunk.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/global.h>
#include <types/log.h>

#include <proto/frontend.h>
#include "proto/log.h"
#include <proto/sample.h>
#include <proto/stream_interface.h>
#ifdef USE_OPENSSL
#include <proto/ssl_sock.h>
#endif
#include "proto/proto_http.h"
#include "sflow/sflow_api.h"
#include "sflow/sflow_config.h"

#if (SFLOW_THREADS)
#include "pthread.h"
#endif

typedef uint32_t sflow_atomic_int_t;

/*_________________---------------------------__________________
  _________________   unknown output defs     __________________
  -----------------___________________________------------------
*/

#define SFLOW_DURATION_UNKNOWN 0
#define SFLOW_TOKENS_UNKNOWN 0

/*_________________---------------------------__________________
  _________________   structure definitions   __________________
  -----------------___________________________------------------
*/

typedef struct _SFWB {
#if (SFLOW_THREADS)
    pthread_mutex_t *mut;
#define SFWB_LOCK(_s) pthread_mutex_lock((_s)->mut)
#define SFWB_UNLOCK(_s) pthread_mutex_unlock((_s)->mut)
#define SFWB_INC_CTR(_c) pthread_atomic_fetch_add(&(_c), 1)
#define SFWB_COUNTDOWN(_c) (pthread_atomic_fetch_add(&(_c), -1) == 1)
#else
#define SFWB_LOCK(_s) /* no-op */
#define SFWB_UNLOCK(_s) /* no-op */
#define SFWB_INC_CTR(_c) (_c)++
#define SFWB_COUNTDOWN(_c) (--(_c) == 0)
#endif

    /* delegate acquiring the sflow config */
    SFWBConfigManager *config_manager;

    /* sFlow agent */
    SFLAgent *agent;
    SFLReceiver *receiver;
    SFLSampler *sampler;
    SFLPoller *poller;

    /* keep track of the current second */
    time_t currentTime;

    /* skip countdown */
    sflow_atomic_int_t sflow_skip;

    /* the http counters */
    SFLCounters_sample_element http_counters;

    /* lowest port*/
    int32_t lowestPort;

    /* pool for sflow_capture allocation */
    struct pool_head *pool2_sflow_capture;

} SFWB;

// just use global for now
static SFWB global_SFWB;

/*_________________---------------------------__________________
  _________________  sflow agent callbacks    __________________
  -----------------___________________________------------------
*/

static void *sfwb_cb_alloc(void *magic, SFLAgent *agent, size_t bytes)
{
    // SFWB *sm = (SFWB *)magic;
    return calloc(1, bytes);
}

static int sfwb_cb_free(void *magic, SFLAgent *agent, void *obj)
{
    // SFWB *sm = (SFWB *)magic;
    if(obj) {
        free(obj);
    }
    return 0;
}

static void sfwb_cb_error(void *magic, SFLAgent *agent, char *msg)
{
    // SFWB *sm = (SFWB *)magic;
    Warning("sFlow agent error: %s", msg);
}

static void sfwb_cb_counters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    SFWB *sm = (SFWB *)poller->magic;
    SFLCounters_sample_element parElem;
    uint32_t parent_ds_index;

    if(sfwb_config_polling_secs(sm->config_manager)) {
        /* counters have been accumulated here */
        SFLADD_ELEMENT(cs, &sm->http_counters);

        parent_ds_index = sfwb_config_parent_ds_index(sm->config_manager);
        if(parent_ds_index) {
            /* we learned the parent_ds_index from the config file, so add a parent structure too. */
            memset(&parElem, 0, sizeof(parElem));
            parElem.tag = SFLCOUNTERS_HOST_PAR;
            parElem.counterBlock.host_par.dsClass = SFL_DSCLASS_PHYSICAL_ENTITY;
            parElem.counterBlock.host_par.dsIndex = parent_ds_index;
            SFLADD_ELEMENT(cs, &parElem);
        }

        sfl_poller_writeCountersSample(poller, cs);
    }
}

static void sfwb_cb_sendPkt(void *magic, SFLAgent *agent, SFLReceiver *receiver, u_char *pkt, uint32_t pktLen)
{
    SFWB *sm = (SFWB *)magic;
    if(sm->config_manager) {
        sfwb_config_send_packet(sm->config_manager, pkt, pktLen);
    }
}

/*_________________---------------------------__________________
  _________________ lowest active listen port __________________
  -----------------___________________________------------------
*/

#ifndef DEFAULT_HTTP_PORT
#define DEFAULT_HTTP_PORT 80
#endif

static uint16_t lowestActiveListenPort(SFWB *sm)
{
    // actually we already looked this up and saved it in sm
    return (sm->lowestPort == -1) ?  DEFAULT_HTTP_PORT : (u_int16_t)sm->lowestPort;
}

/*_________________----------------------------------_______________
  _________________       add_random_skip            _______________
  -----------------__________________________________---------------
  return false if adding the next skip count did not bring the skip
  count back above 0 (only an issue in multithreaded deployment)
*/

static int32_t add_random_skip(SFWB *sm)
{
    sflow_atomic_int_t next_skip = sfl_sampler_next_skip(sm->sampler);
#if (SFLOW_THREADS)
    sflow_atomic_int_t test_skip = sflow_atomic_fetch_add(&sm->sflow_skip, next_skip);
    return (test_skip + next_skip);
#else
    sm->sflow_skip = next_skip;
    return next_skip;
#endif
}

/*_________________---------------------------__________________
  _________________       sfwb_changed        __________________
  -----------------___________________________------------------

The config changed - build/rebuild the sFlow agent
*/

static void sfwb_changed(SFWB *sm)
{
    if(!sfwb_config_valid(sm->config_manager)) {
        return;
    }

    /* create or re-create the agent */
    if(sm->agent) {
        sfl_agent_release(sm->agent);
    }
    
    sm->agent = (SFLAgent *)calloc(1, sizeof(SFLAgent));
    
    uint16_t servicePort = lowestActiveListenPort(sm);

    /* initialize the agent with it's address, bootime, callbacks etc. */
    sfl_agent_init(sm->agent,
                   sfwb_config_agentIP(sm->config_manager),
                   servicePort, /* subAgentId */
                   sm->currentTime,
                   sm->currentTime,
                   sm,
                   sfwb_cb_alloc,
                   sfwb_cb_free,
                   sfwb_cb_error,
                   sfwb_cb_sendPkt);
    
    /* add a receiver */
    sm->receiver = sfl_agent_addReceiver(sm->agent);
    sfl_receiver_set_sFlowRcvrOwner(sm->receiver, "httpd sFlow Probe");
    sfl_receiver_set_sFlowRcvrTimeout(sm->receiver, 0xFFFFFFFF);
    
    /* no need to configure the receiver further, because we are */
    /* using the sendPkt callback to handle the forwarding ourselves. */
    
    /* add a <logicalEntity> datasource to represent this application instance */
    SFLDataSource_instance dsi;
    /* ds_class = <logicalEntity>, ds_index = <lowest service port>, ds_instance = 0 */
    SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, servicePort, 0);
    
    /* add a poller for the counters */
    sm->poller = sfl_agent_addPoller(sm->agent, &dsi, sm, sfwb_cb_counters);
    sfl_poller_set_sFlowCpInterval(sm->poller, sfwb_config_polling_secs(sm->config_manager));
    sfl_poller_set_sFlowCpReceiver(sm->poller, 1 /* receiver index == 1 */);
    
    /* add a sampler for the sampled operations */
    sm->sampler = sfl_agent_addSampler(sm->agent, &dsi);
    sfl_sampler_set_sFlowFsPacketSamplingRate(sm->sampler, sfwb_config_sampling_n(sm->config_manager));
    sfl_sampler_set_sFlowFsReceiver(sm->sampler, 1 /* receiver index == 1 */);
    
    /* we're going to handle the skip countdown ourselves, so initialize it here */
    sm->sflow_skip = 0;
    add_random_skip(sm);
}

/*_________________---------------------------__________________
  _________________      1 second tick        __________________
  -----------------___________________________------------------
*/
        
static void sfwb_tick(SFWB *sm) {
    if(sm->config_manager) {
        if(sfwb_config_tick(sm->config_manager)) {
            /* the config changed - init/reinit the agent */
            sfwb_changed(sm);
        }
    }
    if(sm->agent) {
        sfl_agent_tick(sm->agent, sm->currentTime);
    }
}

/*_________________---------------------------__________________
  _________________      sfwb_init            __________________
  -----------------___________________________------------------
*/

static void sfwb_init(SFWB *sm)
{

#if (SFLOW_THREADS)
    /* a mutex to lock the sFlow agent when taking a sample (only needed if there
       is more that one worker thread) */
    sm->mut = calloc(sizeof(pthread_mutex_t);
    pthread_mutex_init(sm->mut, NULL);
#endif

    /* create and initialze the config_manager */
    sm->config_manager = calloc(1, sizeof(SFWBConfigManager));
    sfwb_config_init(sm->config_manager);

    /* initialize the counter block */
    sm->http_counters.tag = SFLCOUNTERS_HTTP;

    /* allocation pool */
    sm->pool2_sflow_capture = create_pool("sflow_capture", sizeof(struct sflow_capture), MEM_F_SHARED);
}

/*_________________---------------------------__________________
  _________________      sflow_init           __________________
  -----------------___________________________------------------
*/

void sflow_init()
{
    SFWB *sm = &global_SFWB;

    //uint32_t ii;
    int32_t lowestPort;

    lowestPort = -1;
/*     if(cmcf->ports) { */
/*         ngx_http_conf_port_t *port = (ngx_http_conf_port_t *)cmcf->ports->elts; */
/*         for (ii = 0; ii < cmcf->ports->nelts; ii++) { */
/*             in_port_t pt = ntohs(port[ii].port); */
/*             if(lowestPort == -1 ||  */
/*                (int)pt < lowestPort) lowestPort = (int)pt; */
/*         } */
/*     } */

    //smcf->sfwb = ngx_pcalloc(cf->pool, sizeof(SFWB));
    sm->lowestPort = lowestPort;
    sfwb_init(sm);
}

/*_________________--------------------------------__________________
  _________________   method number lookup         __________________
  -----------------________________________________------------------
*/

static SFLHTTP_method sfwb_methodNumberLookup(http_meth_t method)
{
    /* defititions from src/http/ngx_http_request.h */
    switch(method) {
    case HTTP_METH_GET: return SFHTTP_GET;
    case HTTP_METH_HEAD: return SFHTTP_HEAD;
    case HTTP_METH_PUT: return SFHTTP_PUT;
    case HTTP_METH_POST: return SFHTTP_POST;
    case HTTP_METH_DELETE: return SFHTTP_DELETE;
        /* case HTTP_METH_CONNECT: return SFHTTP_CONNECT; */
    case HTTP_METH_OPTIONS: return SFHTTP_OPTIONS;
    case HTTP_METH_TRACE: return SFHTTP_TRACE;
    case HTTP_METH_NONE:
    case HTTP_METH_OTHER:
    default:
        return SFHTTP_OTHER;
    }
}

/*_________________--------------------------------__________________
  _________________     sflow_start_transaction    __________________
  -----------------________________________________------------------
*/

void
sflow_start_transaction(struct session *s)
{
    // just use a global until we can figure out where to park the state
    // and how to register for an init callback.
    SFWB *sm = &global_SFWB;

    if(sfwb_config_sampling_n(sm->config_manager) == 0) {
        /* not configured for sampling yet */
        return;
    }

    /* increment the all-important sample_pool */
    SFWB_INC_CTR(sm->sampler->samplePool);

    if(SFWB_COUNTDOWN(sm->sflow_skip)) {
        /* skip just went from 1 to 0, so take sample */

        /* in this split arrangement we only have to mark
           the transaction to be sampled here. The rest
           will be done at the end of the transaction. We
           also need to ask for certain headers to be
           recorded (regardless of whether they will be
           captured for the ascii syslog. */

        SFWB_LOCK(sm);

        /* setting this pointer also serves to indicate that we are sampling this transaction */
        s->txn.sflow_c = pool_alloc2(sm->pool2_sflow_capture);

        /* the skip counter could be something like -1 or -2 now if other threads were decrementing
           it while we were taking this sample. So rather than just set the new skip count and ignore those
           other decrements, we do an atomic add.
           In the extreme case where the new random skip is small then we might not get the skip back above 0
           with this add,  and so the new skip would effectively be ~ 2^32.  Just to make sure that doesn't
           happen we loop until the skip is above 0 (and count any extra adds as drop-events). */
        /* one advantage of this approach is that we only have to generate a new random number when we
           take a sample,  and because we have the mutex locked we don't need to make the random number
           seed a per-thread variable. */
        while(add_random_skip(sm) <= 0) {
            sm->sampler->dropEvents++;
        }
        
        SFWB_UNLOCK(sm);
    }
}


/*_________________--------------------------------__________________
  _________________     sflow_encode_socket        __________________
  -----------------________________________________------------------
*/

static bool_t
sflow_encode_socket( SFLFlow_sample_element *socElem, struct sockaddr *localsoc, struct sockaddr *peersoc, int backend)
{
    int encoded = false;
    struct sockaddr_in *localsoc4 = (struct sockaddr_in *)localsoc;
    struct sockaddr_in *peersoc4 = (struct sockaddr_in *)peersoc;
    if(localsoc4 && peersoc4) {
        if(/* localsoc4->sin_family == AF_INET
              && */ peersoc4->sin_family == AF_INET) {
            socElem->tag = backend ? SFLFLOW_EX_PROXY_SOCKET4 : SFLFLOW_EX_SOCKET4;
            socElem->flowType.socket4.protocol = 6; /* TCP */
            memcpy(&socElem->flowType.socket4.local_ip.addr, &(localsoc4->sin_addr), 4);
            socElem->flowType.socket4.local_port = ntohs(localsoc4->sin_port);
            memcpy(&socElem->flowType.socket4.remote_ip.addr, &(peersoc4->sin_addr), 4);
            socElem->flowType.socket4.remote_port = ntohs(peersoc4->sin_port);
            encoded = true;
        }
        else if(/* localsoc4->sin_family == AF_INET6
                   && */ peersoc4->sin_family == AF_INET6) {
            struct sockaddr_in6 *localsoc6 = (struct sockaddr_in6 *)localsoc;
            struct sockaddr_in6 *peersoc6 = (struct sockaddr_in6 *)peersoc;
            struct in_addr peer4;
            struct in_addr local4;
            if(v6tov4(&local4, &localsoc6->sin6_addr)
               && v6tov4(&peer4, &peersoc6->sin6_addr)) {
                // encode as v4 anyway
                socElem->tag = backend ? SFLFLOW_EX_PROXY_SOCKET4 : SFLFLOW_EX_SOCKET4;
                socElem->flowType.socket4.protocol = 6; /* TCP */
                memcpy(&socElem->flowType.socket4.local_ip.addr, &(local4.s_addr), 4);
                socElem->flowType.socket4.local_port = ntohs(localsoc6->sin6_port);
                memcpy(&socElem->flowType.socket4.remote_ip.addr, &(peer4.s_addr), 4);
                socElem->flowType.socket4.remote_port = ntohs(peersoc6->sin6_port);
                encoded = true;
            }
            else {
                // v6
                socElem->tag = backend ? SFLFLOW_EX_PROXY_SOCKET6 : SFLFLOW_EX_SOCKET6;
                socElem->flowType.socket6.protocol = 6; /* TCP */
                memcpy(&socElem->flowType.socket6.local_ip.addr, &(localsoc6->sin6_addr), 4);
                socElem->flowType.socket6.local_port = ntohs(localsoc6->sin6_port);
                memcpy(&socElem->flowType.socket6.remote_ip.addr, &(peersoc6->sin6_addr), 4);
                socElem->flowType.socket6.remote_port = ntohs(peersoc6->sin6_port);
                encoded = true;
            }
        }
    }
    return encoded;
}

/*_________________--------------------------------__________________
  _________________     sflow_end_transaction      __________________
  -----------------________________________________------------------
*/

void
sflow_end_transaction(struct session *s)
{
    // just use a global until we can figure out where to park the state
    // and how to register for an init callback.
    SFWB *sm = &global_SFWB;

    /* approximate a 1-second tick - this assumes that we have constant activity. It may be
       better to run a separate thread just to do this reliably and conform to the sFlow standard
       even when nothing is happening,  or find out how to get timer events from the main event loop.
    */

    if(now.tv_sec != sm->currentTime) {
        SFWB_LOCK(sm);
        /* repeat the test now that we have the mutex,  in case two threads saw the second rollover */
        if(now.tv_sec != sm->currentTime) {
            sm->currentTime = now.tv_sec;
            sfwb_tick(sm);
        }
        SFWB_UNLOCK(sm);
    }

    SFLHTTP_method method = sfwb_methodNumberLookup(s->txn.meth);

    uint32_t status = s->txn.status;
    SFLHTTP_counters *ctrs = &sm->http_counters.counterBlock.http;
    switch(method) {
    case SFHTTP_HEAD: SFWB_INC_CTR(ctrs->method_head_count); break;
    case SFHTTP_GET: SFWB_INC_CTR(ctrs->method_get_count); break;
    case SFHTTP_PUT: SFWB_INC_CTR(ctrs->method_put_count); break;
    case SFHTTP_POST: SFWB_INC_CTR(ctrs->method_post_count); break;
    case SFHTTP_DELETE: SFWB_INC_CTR(ctrs->method_delete_count); break;
    case SFHTTP_CONNECT: SFWB_INC_CTR(ctrs->method_connect_count); break;
    case SFHTTP_OPTIONS: SFWB_INC_CTR(ctrs->method_option_count); break;
    case SFHTTP_TRACE: SFWB_INC_CTR(ctrs->method_trace_count); break;
    default: SFWB_INC_CTR(ctrs->method_other_count); break;
    }

    if(status < 100) SFWB_INC_CTR(ctrs->status_other_count);
    else if(status < 200) SFWB_INC_CTR(ctrs->status_1XX_count);
    else if(status < 300) SFWB_INC_CTR(ctrs->status_2XX_count);
    else if(status < 400) SFWB_INC_CTR(ctrs->status_3XX_count);
    else if(status < 500) SFWB_INC_CTR(ctrs->status_4XX_count);
    else if(status < 600) SFWB_INC_CTR(ctrs->status_5XX_count);    
    else SFWB_INC_CTR(ctrs->status_other_count);

    if(s->txn.sflow_c) {
        SFL_FLOW_SAMPLE_TYPE fs;
        SFLFlow_sample_element httpElem;
        SFLFlow_sample_element socElem_front;
        SFLFlow_sample_element socElem_back;

        memset(&fs, 0, sizeof(fs));
        memset(&httpElem, 0, sizeof(httpElem));
        memset(&socElem_front, 0, sizeof(socElem_front));
        memset(&socElem_back, 0, sizeof(socElem_back));
        
        /* indicate that I am the server by setting the
           destination interface to 0x3FFFFFFF=="internal"
           and leaving the source interface as 0=="unknown" */
        fs.output = 0x3FFFFFFF;
        
        httpElem.tag = SFLFLOW_HTTP;
        httpElem.flowType.http.method = method;
        httpElem.flowType.http.protocol = s->txn.sflow_c->version;
        httpElem.flowType.http.uri.str = s->txn.sflow_c->uri;
        httpElem.flowType.http.uri.len = s->txn.sflow_c->uri_len;
        httpElem.flowType.http.host.str = s->txn.sflow_c->host;
        httpElem.flowType.http.host.len = s->txn.sflow_c->host_len;
        httpElem.flowType.http.referer.str = s->txn.sflow_c->referer;
        httpElem.flowType.http.referer.len = s->txn.sflow_c->referer_len;
        httpElem.flowType.http.useragent.str = s->txn.sflow_c->useragent;
        httpElem.flowType.http.useragent.len = s->txn.sflow_c->useragent_len;
        httpElem.flowType.http.xff.str = s->txn.sflow_c->xff;
        httpElem.flowType.http.xff.len = s->txn.sflow_c->xff_len;
        httpElem.flowType.http.authuser.str = s->txn.sflow_c->authuser;
        httpElem.flowType.http.authuser.len = s->txn.sflow_c->authuser_len;
        httpElem.flowType.http.mimetype.str = s->txn.sflow_c->mimetype;
        httpElem.flowType.http.mimetype.len = s->txn.sflow_c->mimetype_len;
        httpElem.flowType.http.req_bytes = s->logs.bytes_out;
        httpElem.flowType.http.resp_bytes = s->logs.bytes_in;
        httpElem.flowType.http.uS = 1000 * tv_ms_elapsed(&s->logs.tv_accept, &now);
        httpElem.flowType.http.status = status;

        SFWB_LOCK(sm);

        SFLADD_ELEMENT(&fs, &httpElem);

        /* add frontend and backend socket structures */
        /* TODO: local sockets lookups don't seem to be working - probably
           that Linux thing where you have to use msgrcv instead if you want
           this info. */
        if(sflow_encode_socket(&socElem_front,
                               (struct sockaddr *)&(s->req->prod->conn->addr.to),
                               (struct sockaddr *)&(s->req->prod->conn->addr.from),
                               false)) {
            SFLADD_ELEMENT(&fs, &socElem_front);
        }
        if(sflow_encode_socket(&socElem_back,
                               (struct sockaddr *)&(s->req->cons->conn->addr.from),
                               (struct sockaddr *)&(s->req->cons->conn->addr.to),
                               true)) {
            SFLADD_ELEMENT(&fs, &socElem_back);
        }

        sfl_sampler_writeFlowSample(sm->sampler, &fs);
        
        SFWB_UNLOCK(sm);
        
        /* free the sflow_capture structure that we attached to the transaction */
        pool_free2(sm->pool2_sflow_capture, s->txn.sflow_c);
        s->txn.sflow_c = NULL;
    }
}

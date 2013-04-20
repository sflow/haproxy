/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Copyright (c) 2002-2013 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#include <stdio.h> // for snprintf()
#include <string.h> // for memset()
#include <arpa/inet.h> // for htonl()
#include "sflow/sflow_api.h"

/* ===================================================*/
/* ===================== AGENT =======================*/


static void * sflAlloc(SFLAgent *agent, size_t bytes);
static void sflFree(SFLAgent *agent, void *obj);
static void sfl_agent_jumpTableAdd(SFLAgent *agent, SFLSampler *sampler);
static void sfl_agent_jumpTableRemove(SFLAgent *agent, SFLSampler *sampler);

/*_________________---------------------------__________________
  _________________       alloc and free      __________________
  -----------------___________________________------------------
*/

static void * sflAlloc(SFLAgent *agent, size_t bytes)
{
    /* just assume we were given an allocFn */
    return (*agent->allocFn)(agent->magic, agent, bytes);
}

static void sflFree(SFLAgent *agent, void *obj)
{
    /* just assume we were given an allocFn */
    (*agent->freeFn)(agent->magic, agent, obj);
}
  
/*_________________---------------------------__________________
  _________________       error logging       __________________
  -----------------___________________________------------------
*/
#define MAX_ERRMSG_LEN 1000

void sfl_agent_error(SFLAgent *agent, char *modName, char *msg)
{
    char errm[MAX_ERRMSG_LEN];
    snprintf(errm, MAX_ERRMSG_LEN, "sfl_agent_error: %s: %s\n", modName, msg);
    if(agent->errorFn) (*agent->errorFn)(agent->magic, agent, errm);
}

/*________________--------------------------__________________
  ________________    sfl_agent_init        __________________
  ----------------__________________________------------------
*/

void sfl_agent_init(SFLAgent *agent,
                    SFLAddress *myIP, /* IP address of this agent in net byte order */
                    uint32_t subId,  /* agent_sub_id */
                    time_t bootTime,  /* agent boot time */
                    time_t now,       /* time now */
                    void *magic,      /* ptr to pass back in logging and alloc fns */
                    allocFn_t allocFn,
                    freeFn_t freeFn,
                    errorFn_t errorFn,
                    sendFn_t sendFn)
{
    /* first clear everything */
    memset(agent, 0, sizeof(*agent));
    /* now copy in the parameters */
    agent->myIP = *myIP; /* structure copy */
    agent->subId = subId;
    agent->bootTime = bootTime;
    agent->now = now;
    agent->magic = magic;
    agent->allocFn = allocFn;
    agent->freeFn = freeFn;
    agent->errorFn = errorFn;
    agent->sendFn = sendFn;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_release       __________________
  -----------------___________________________------------------
*/

void sfl_agent_release(SFLAgent *agent)
{
 
    SFLSampler *sm;
    SFLPoller *pl;
    SFLReceiver *rcv;
    /* release and free the samplers */
    for(sm = agent->samplers; sm != NULL; ) {
        SFLSampler *nextSm = sm->nxt;
        sflFree(agent, sm);
        sm = nextSm;
    }
    agent->samplers = NULL;

    /* release and free the pollers */
    for( pl= agent->pollers; pl != NULL; ) {
        SFLPoller *nextPl = pl->nxt;
        sflFree(agent, pl);
        pl = nextPl;
    }
    agent->pollers = NULL;

    /* release and free the receivers */
    for( rcv = agent->receivers; rcv != NULL; ) {
        SFLReceiver *nextRcv = rcv->nxt;
        sflFree(agent, rcv);
        rcv = nextRcv;
    }
    agent->receivers = NULL;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_tick          __________________
  -----------------___________________________------------------
*/

void sfl_agent_tick(SFLAgent *agent, time_t now)
{
    SFLReceiver *rcv;
    SFLSampler *sm;
    SFLPoller *pl;

    agent->now = now;
    /* receivers use ticks to flush send data */
    for( rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt) sfl_receiver_tick(rcv, now);
    /* samplers use ticks to decide when they are sampling too fast */
    for( sm = agent->samplers; sm != NULL; sm = sm->nxt) sfl_sampler_tick(sm, now);
    /* pollers use ticks to decide when to ask for counters */
    for( pl = agent->pollers; pl != NULL; pl = pl->nxt) sfl_poller_tick(pl, now);
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addReceiver   __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_addReceiver(SFLAgent *agent)
{
    SFLReceiver *rcv, *r, *prev;

    prev = NULL;
    rcv = (SFLReceiver *)sflAlloc(agent, sizeof(SFLReceiver));
    sfl_receiver_init(rcv, agent);
    /* add to end of list - to preserve the receiver index numbers for existing receivers */
 
    for(r = agent->receivers; r != NULL; prev = r, r = r->nxt);
    if(prev) prev->nxt = rcv;
    else agent->receivers = rcv;
    rcv->nxt = NULL;
    return rcv;
}

/*_________________---------------------------__________________
  _________________     sfl_dsi_compare       __________________
  -----------------___________________________------------------

  Note that if there is a mixture of ds_classes for this agent, then
  the simple numeric comparison may not be correct - the sort order (for
  the purposes of the SNMP MIB) should really be determined by the OID
  that these numeric ds_class numbers are a shorthand for.  For example,
  ds_class == 0 means ifIndex, which is the oid "1.3.6.1.2.1.2.2.1"
*/

static int sfl_dsi_compare(SFLDataSource_instance *pdsi1, SFLDataSource_instance *pdsi2) {
    /* could have used just memcmp(),  but not sure if that would */
    /* give the right answer on little-endian platforms. Safer to be explicit... */
    int cmp = pdsi2->ds_class - pdsi1->ds_class;
    if(cmp == 0) cmp = pdsi2->ds_index - pdsi1->ds_index;
    if(cmp == 0) cmp = pdsi2->ds_instance - pdsi1->ds_instance;
    return cmp;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addSampler    __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_addSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    SFLSampler *newsm, *prev, *sm, *test;

    prev = NULL;
    sm = agent->samplers;
    /* keep the list sorted */
    for(; sm != NULL; prev = sm, sm = sm->nxt) {
        int64_t cmp = sfl_dsi_compare(pdsi, &sm->dsi);
        if(cmp == 0) return sm;  /* found - return existing one */
        if(cmp < 0) break;       /* insert here */
    }
    /* either we found the insert point, or reached the end of the list... */
    newsm = (SFLSampler *)sflAlloc(agent, sizeof(SFLSampler));
    sfl_sampler_init(newsm, agent, pdsi);
    if(prev) prev->nxt = newsm;
    else agent->samplers = newsm;
    newsm->nxt = sm;

    /* see if we should go in the ifIndex jumpTable */
    if(SFL_DS_CLASS(newsm->dsi) == 0) {
        test = sfl_agent_getSamplerByIfIndex(agent, SFL_DS_INDEX(newsm->dsi));
        if(test && (SFL_DS_INSTANCE(newsm->dsi) < SFL_DS_INSTANCE(test->dsi))) {
            /* replace with this new one because it has a lower ds_instance number */
            sfl_agent_jumpTableRemove(agent, test);
            test = NULL;
        }
        if(test == NULL) sfl_agent_jumpTableAdd(agent, newsm);
    }
    return newsm;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addPoller     __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_addPoller(SFLAgent *agent,
                               SFLDataSource_instance *pdsi,
                               void *magic,         /* ptr to pass back in getCountersFn() */
                               getCountersFn_t getCountersFn)
{
    SFLPoller *newpl;

    /* keep the list sorted */
    SFLPoller *prev = NULL, *pl = agent->pollers;
    for(; pl != NULL; prev = pl, pl = pl->nxt) {
        int64_t cmp = sfl_dsi_compare(pdsi, &pl->dsi);
        if(cmp == 0) return pl;  /* found - return existing one */
        if(cmp < 0) break;       /* insert here */
    }
    /* either we found the insert point, or reached the end of the list... */
    newpl = (SFLPoller *)sflAlloc(agent, sizeof(SFLPoller));
    sfl_poller_init(newpl, agent, pdsi, magic, getCountersFn);
    if(prev) prev->nxt = newpl;
    else agent->pollers = newpl;
    newpl->nxt = pl;
    return newpl;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_removeSampler  __________________
  -----------------___________________________------------------
*/

int sfl_agent_removeSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    SFLSampler *prev, *sm;

    /* find it, unlink it and free it */
    for(prev = NULL, sm = agent->samplers; sm != NULL; prev = sm, sm = sm->nxt) {
        if(sfl_dsi_compare(pdsi, &sm->dsi) == 0) {
            if(prev == NULL) agent->samplers = sm->nxt;
            else prev->nxt = sm->nxt;
            sfl_agent_jumpTableRemove(agent, sm);
            sflFree(agent, sm);
            return 1;
        }
    }
    /* not found */
    return 0;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_removePoller   __________________
  -----------------___________________________------------------
*/

int sfl_agent_removePoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    SFLPoller *prev, *pl;
    /* find it, unlink it and free it */
    for(prev = NULL, pl = agent->pollers; pl != NULL; prev = pl, pl = pl->nxt) {
        if(sfl_dsi_compare(pdsi, &pl->dsi) == 0) {
            if(prev == NULL) agent->pollers = pl->nxt;
            else prev->nxt = pl->nxt;
            sflFree(agent, pl);
            return 1;
        }
    }
    /* not found */
    return 0;
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_jumpTableAdd        __________________
  -----------------________________________________------------------
*/

static void sfl_agent_jumpTableAdd(SFLAgent *agent, SFLSampler *sampler)
{
    uint32_t hashIndex = SFL_DS_INDEX(sampler->dsi) % SFL_HASHTABLE_SIZ;
    sampler->hash_nxt = agent->jumpTable[hashIndex];
    agent->jumpTable[hashIndex] = sampler;
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_jumpTableRemove     __________________
  -----------------________________________________------------------
*/

static void sfl_agent_jumpTableRemove(SFLAgent *agent, SFLSampler *sampler)
{
    uint32_t hashIndex = SFL_DS_INDEX(sampler->dsi) % SFL_HASHTABLE_SIZ;
    SFLSampler *search = agent->jumpTable[hashIndex], *prev = NULL;
    for( ; search != NULL; prev = search, search = search->hash_nxt) if(search == sampler) break;
    if(search) {
        /* found - unlink */
        if(prev) prev->hash_nxt = search->hash_nxt;
        else agent->jumpTable[hashIndex] = search->hash_nxt;
        search->hash_nxt = NULL;
    }
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_getSamplerByIfIndex __________________
  -----------------________________________________------------------
  fast lookup (pointers cached in hash table).  If there are multiple
  sampler instances for a given ifIndex, then this fn will return
  the one with the lowest instance number.  Since the samplers
  list is sorted, this means the other instances will be accesible
  by following the sampler->nxt pointer (until the ds_class
  or ds_index changes).  This is helpful if you need to offer
  the same flowSample to multiple samplers.
*/

SFLSampler *sfl_agent_getSamplerByIfIndex(SFLAgent *agent, uint32_t ifIndex)
{
    SFLSampler *search = agent->jumpTable[ifIndex % SFL_HASHTABLE_SIZ];
    for( ; search != NULL; search = search->hash_nxt) if(SFL_DS_INDEX(search->dsi) == ifIndex) break;
    return search;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getSampler     __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_getSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    SFLSampler *sm;

    /* find it and return it */
    for( sm = agent->samplers; sm != NULL; sm = sm->nxt)
        if(sfl_dsi_compare(pdsi, &sm->dsi) == 0) return sm;
    /* not found */
    return NULL;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getPoller      __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_getPoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    SFLPoller *pl;

    /* find it and return it */
    for( pl = agent->pollers; pl != NULL; pl = pl->nxt)
        if(sfl_dsi_compare(pdsi, &pl->dsi) == 0) return pl;
    /* not found */
    return NULL;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getReceiver    __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_getReceiver(SFLAgent *agent, uint32_t receiverIndex)
{
    SFLReceiver *rcv;

    uint32_t rcvIdx = 0;
    for( rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt)
        if(receiverIndex == ++rcvIdx) return rcv;

    /* not found - ran off the end of the table */
    return NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextSampler  __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_getNextSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* return the one lexograpically just after it - assume they are sorted
       correctly according to the lexographical ordering of the object ids */
    SFLSampler *sm = sfl_agent_getSampler(agent, pdsi);
    return sm ? sm->nxt : NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextPoller   __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_getNextPoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* return the one lexograpically just after it - assume they are sorted
       correctly according to the lexographical ordering of the object ids */
    SFLPoller *pl = sfl_agent_getPoller(agent, pdsi);
    return pl ? pl->nxt : NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextReceiver __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_getNextReceiver(SFLAgent *agent, uint32_t receiverIndex)
{
    return sfl_agent_getReceiver(agent, receiverIndex + 1);
}


/*_________________---------------------------__________________
  _________________ sfl_agent_resetReceiver   __________________
  -----------------___________________________------------------
*/

void sfl_agent_resetReceiver(SFLAgent *agent, SFLReceiver *receiver)
{
    SFLReceiver *rcv;
    SFLSampler *sm;
    SFLPoller *pl;

    /* tell samplers and pollers to stop sending to this receiver */
    /* first get his receiverIndex */
    uint32_t rcvIdx = 0;
    for( rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt) {
        rcvIdx++; /* thanks to Diego Valverde for pointing out this bugfix */
        if(rcv == receiver) {
            /* now tell anyone that is using it to stop */
            for( sm = agent->samplers; sm != NULL; sm = sm->nxt)
                if(sfl_sampler_get_sFlowFsReceiver(sm) == rcvIdx) sfl_sampler_set_sFlowFsReceiver(sm, 0);
      
            for( pl = agent->pollers; pl != NULL; pl = pl->nxt)
                if(sfl_poller_get_sFlowCpReceiver(pl) == rcvIdx) sfl_poller_set_sFlowCpReceiver(pl, 0);

            break;
        }
    }
}




/* ===================================================*/
/* ===================== SAMPLER =====================*/

/*_________________--------------------------__________________
  _________________   sfl_sampler_init       __________________
  -----------------__________________________------------------
*/

void sfl_sampler_init(SFLSampler *sampler, SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* copy the dsi in case it points to sampler->dsi, which we are about to clear.
       (Thanks to Jagjit Choudray of Force 10 Networks for pointing out this bug) */
    SFLDataSource_instance dsi = *pdsi;

    /* preserve the *nxt pointer too, in case we are resetting this poller and it is
       already part of the agent's linked list (thanks to Matt Woodly for pointing this out) */
    SFLSampler *nxtPtr = sampler->nxt;
  
    /* clear everything */
    memset(sampler, 0, sizeof(*sampler));
  
    /* restore the linked list ptr */
    sampler->nxt = nxtPtr;
  
    /* now copy in the parameters */
    sampler->agent = agent;
    sampler->dsi = dsi;
  
    /* set defaults */
    sfl_sampler_set_sFlowFsMaximumHeaderSize(sampler, SFL_DEFAULT_HEADER_SIZE);
    sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, SFL_DEFAULT_SAMPLING_RATE);
}

/*_________________--------------------------__________________
  _________________       reset              __________________
  -----------------__________________________------------------
*/

static void resetSampler(SFLSampler *sampler)
{
    SFLDataSource_instance dsi = sampler->dsi;
    sfl_sampler_init(sampler, sampler->agent, &dsi);
}

/*_________________---------------------------__________________
  _________________      MIB access           __________________
  -----------------___________________________------------------
*/
uint32_t sfl_sampler_get_sFlowFsReceiver(SFLSampler *sampler) {
    return sampler->sFlowFsReceiver;
}

void sfl_sampler_set_sFlowFsReceiver(SFLSampler *sampler, uint32_t sFlowFsReceiver) {
    sampler->sFlowFsReceiver = sFlowFsReceiver;
    if(sFlowFsReceiver == 0) resetSampler(sampler);
    else {
        /* retrieve and cache a direct pointer to my receiver */
        sampler->myReceiver = sfl_agent_getReceiver(sampler->agent, sampler->sFlowFsReceiver);
    }
}

uint32_t sfl_sampler_get_sFlowFsPacketSamplingRate(SFLSampler *sampler) {
    return sampler->sFlowFsPacketSamplingRate;
}

void sfl_sampler_set_sFlowFsPacketSamplingRate(SFLSampler *sampler, uint32_t sFlowFsPacketSamplingRate) {
    sampler->sFlowFsPacketSamplingRate = sFlowFsPacketSamplingRate;
    /* initialize the skip count too */
    sampler->skip = sFlowFsPacketSamplingRate ? sfl_random(sFlowFsPacketSamplingRate) : 0;
}

uint32_t sfl_sampler_get_sFlowFsMaximumHeaderSize(SFLSampler *sampler) {
    return sampler->sFlowFsMaximumHeaderSize;
}

void sfl_sampler_set_sFlowFsMaximumHeaderSize(SFLSampler *sampler, uint32_t sFlowFsMaximumHeaderSize) {
    sampler->sFlowFsMaximumHeaderSize = sFlowFsMaximumHeaderSize;
}

/* call this to set a maximum samples-per-second threshold. If the sampler reaches this
   threshold it will automatically back off the sampling rate. A value of 0 disables the
   mechanism */

void sfl_sampler_set_backoffThreshold(SFLSampler *sampler, uint32_t samplesPerSecond) {
    sampler->backoffThreshold = samplesPerSecond;
}

uint32_t sfl_sampler_get_backoffThreshold(SFLSampler *sampler) {
    return sampler->backoffThreshold;
}

uint32_t sfl_sampler_get_samplesLastTick(SFLSampler *sampler) {
    return sampler->samplesLastTick;
}

/*_________________---------------------------------__________________
  _________________   sequence number reset         __________________
  -----------------_________________________________------------------
  Used by the agent to indicate a samplePool discontinuity
  so that the sflow collector will know to ignore the next delta.
*/
void sfl_sampler_resetFlowSeqNo(SFLSampler *sampler) { sampler->flowSampleSeqNo = 0; }


/*_________________---------------------------__________________
  _________________    sfl_sampler_tick       __________________
  -----------------___________________________------------------
*/

void sfl_sampler_tick(SFLSampler *sampler, time_t now)
{
    if(sampler->backoffThreshold && sampler->samplesThisTick > sampler->backoffThreshold) {
        /* automatic backoff.  If using hardware sampling then this is where you have to */
        /* call out to change the sampling rate and make sure that any other registers/variables */
        /* that hold this value are updated. */
        sampler->sFlowFsPacketSamplingRate *= 2;
    }
    sampler->samplesLastTick = sampler->samplesThisTick;
    sampler->samplesThisTick = 0;
}



/*_________________------------------------------__________________
  _________________ sfl_sampler_writeFlowSample  __________________
  -----------------______________________________------------------
*/

void sfl_sampler_writeFlowSample(SFLSampler *sampler, SFL_FLOW_SAMPLE_TYPE *fs)
{
    if(fs == NULL) return;
    sampler->samplesThisTick++;
    /* increment the sequence number */
    fs->sequence_number = ++sampler->flowSampleSeqNo;
    /* copy the other header fields in */
#ifdef SFL_USE_32BIT_INDEX
    fs->ds_class = SFL_DS_CLASS(sampler->dsi);
    fs->ds_index = SFL_DS_INDEX(sampler->dsi);
#else
    fs->source_id = SFL_DS_DATASOURCE(sampler->dsi);
#endif
    /* the sampling rate may have been set already. */
    if(fs->sampling_rate == 0) fs->sampling_rate = sampler->sFlowFsPacketSamplingRate;
    /* the samplePool may be maintained upstream too. */
    if(fs->sample_pool == 0) fs->sample_pool = sampler->samplePool;
    /* and the same for the drop event counter */
    if(fs->drops == 0) fs->drops = sampler->dropEvents;
    /* sent to my receiver */
    if(sampler->myReceiver) sfl_receiver_writeFlowSample(sampler->myReceiver, fs);
}

/*_________________-------------------------------------__________________
  _________________ sfl_sampler_writeEncodedFlowSample  __________________
  -----------------_____________________________________------------------
*/

void sfl_sampler_writeEncodedFlowSample(SFLSampler *sampler, char *xdrBytes, uint32_t len)
{
    SFL_FLOW_SAMPLE_TYPE fs;
    memset(&fs, 0, sizeof(fs));
    sampler->samplesThisTick++;
    /* increment the sequence number */
    fs.sequence_number = ++sampler->flowSampleSeqNo;
    /* copy the other header fields in */
#ifdef SFL_USE_32BIT_INDEX
    fs.ds_class = SFL_DS_CLASS(sampler->dsi);
    fs.ds_index = SFL_DS_INDEX(sampler->dsi);
#else
    fs.source_id = SFL_DS_DATASOURCE(sampler->dsi);
#endif
    fs.sampling_rate = sampler->sFlowFsPacketSamplingRate;
    fs.sample_pool = sampler->samplePool;
    fs.drops = sampler->dropEvents;
    if(sampler->myReceiver) sfl_receiver_writeEncodedFlowSample(sampler->myReceiver, &fs, xdrBytes, len);
}

/*_________________---------------------------__________________
  _________________     sfl_random            __________________
  -----------------___________________________------------------
  Gerhard's generator
*/

static uint32_t SFLRandom = 1;

uint32_t sfl_random(uint32_t lim) {
    SFLRandom = ((SFLRandom * 32719) + 3) % 32749;
    return ((SFLRandom % lim) + 1);
} 

void sfl_random_init(uint32_t seed) {
    SFLRandom = seed;
} 

uint32_t sfl_sampler_next_skip(SFLSampler *sampler) {
    return sfl_random((2 * sampler->sFlowFsPacketSamplingRate) - 1);
}

/*_________________---------------------------__________________
  _________________  sfl_sampler_takeSample   __________________
  -----------------___________________________------------------
*/

int sfl_sampler_takeSample(SFLSampler *sampler)
{
    /* increment the samplePool */
    sampler->samplePool++;

    if(unlikely(--sampler->skip == 0)) {
        /* reached zero. Set the next skip and return true. */
        sampler->skip = sfl_sampler_next_skip(sampler);
        return 1;
    }
    return 0;
}



/* ===================================================*/
/* ===================== POLLER ======================*/

/*_________________--------------------------__________________
  _________________    sfl_poller_init       __________________
  -----------------__________________________------------------
*/

void sfl_poller_init(SFLPoller *poller,
                     SFLAgent *agent,
                     SFLDataSource_instance *pdsi,
                     void *magic,         /* ptr to pass back in getCountersFn() */
                     getCountersFn_t getCountersFn)
{
    /* copy the dsi in case it points to poller->dsi, which we are about to clear */
    SFLDataSource_instance dsi = *pdsi;

    /* preserve the *nxt pointer too, in case we are resetting this poller and it is
       already part of the agent's linked list (thanks to Matt Woodly for pointing this out) */
    SFLPoller *nxtPtr = poller->nxt;

    /* clear everything */
    memset(poller, 0, sizeof(*poller));
  
    /* restore the linked list ptr */
    poller->nxt = nxtPtr;
  
    /* now copy in the parameters */
    poller->agent = agent;
    poller->dsi = dsi; /* structure copy */
    poller->magic = magic;
    poller->getCountersFn = getCountersFn;
}

/*_________________--------------------------__________________
  _________________       reset              __________________
  -----------------__________________________------------------
*/

static void resetPoller(SFLPoller *poller)
{
    SFLDataSource_instance dsi = poller->dsi;
    sfl_poller_init(poller, poller->agent, &dsi, poller->magic, poller->getCountersFn);
}

/*_________________---------------------------__________________
  _________________      MIB access           __________________
  -----------------___________________________------------------
*/
uint32_t sfl_poller_get_sFlowCpReceiver(SFLPoller *poller) {
    return poller->sFlowCpReceiver;
}

void sfl_poller_set_sFlowCpReceiver(SFLPoller *poller, uint32_t sFlowCpReceiver) {
    poller->sFlowCpReceiver = sFlowCpReceiver;
    if(sFlowCpReceiver == 0) resetPoller(poller);
    else {
        /* retrieve and cache a direct pointer to my receiver */
        poller->myReceiver = sfl_agent_getReceiver(poller->agent, poller->sFlowCpReceiver);
    }
}

uint32_t sfl_poller_get_sFlowCpInterval(SFLPoller *poller) {
    return (uint32_t)poller->sFlowCpInterval;
}

void sfl_poller_set_sFlowCpInterval(SFLPoller *poller, uint32_t sFlowCpInterval) {
    poller->sFlowCpInterval = sFlowCpInterval;
    /* Set the countersCountdown to be a randomly selected value between 1 and
       sFlowCpInterval. That way the counter polling would be desynchronised
       (on a 200-port switch, polling all the counters in one second could be harmful). */
    poller->countersCountdown = sfl_random(sFlowCpInterval);
}

/*_________________---------------------------------__________________
  _________________   sequence number reset         __________________
  -----------------_________________________________------------------
  Used to indicate a counter discontinuity
  so that the sflow collector will know to ignore the next delta.
*/
void sfl_poller_resetCountersSeqNo(SFLPoller *poller) {  poller->countersSampleSeqNo = 0; }

/*_________________---------------------------__________________
  _________________    sfl_poller_tick        __________________
  -----------------___________________________------------------
*/

void sfl_poller_tick(SFLPoller *poller, time_t now)
{
    if(poller->countersCountdown == 0) return; /* counters retrieval was not enabled */
    if(poller->sFlowCpReceiver == 0) return;

    if(--poller->countersCountdown == 0) {
        if(poller->getCountersFn != NULL) {
            /* call out for counters */
            SFL_COUNTERS_SAMPLE_TYPE cs;
            memset(&cs, 0, sizeof(cs));
            poller->getCountersFn(poller->magic, poller, &cs);
            /* this countersFn is expected to fill in some counter block elements */
            /* and then call sfl_poller_writeCountersSample(poller, &cs); */
        }
        /* reset the countdown */
        poller->countersCountdown = poller->sFlowCpInterval;
    }
}

/*_________________---------------------------------__________________
  _________________ sfl_poller_writeCountersSample  __________________
  -----------------_________________________________------------------
*/

void sfl_poller_writeCountersSample(SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    /* fill in the rest of the header fields, and send to the receiver */
    cs->sequence_number = ++poller->countersSampleSeqNo;
#ifdef SFL_USE_32BIT_INDEX
    cs->ds_class = SFL_DS_CLASS(poller->dsi);
    cs->ds_index = SFL_DS_INDEX(poller->dsi);
#else
    cs->source_id = SFL_DS_DATASOURCE(poller->dsi);
#endif
    /* sent to my receiver */
    if(poller->myReceiver) sfl_receiver_writeCountersSample(poller->myReceiver, cs);
}





/* ===================================================*/
/* ===================== RECEIVER ====================*/

static void resetSampleCollector(SFLReceiver *receiver);
static void sendSample(SFLReceiver *receiver);
static void receiverError(SFLReceiver *receiver, char *errm);
static void putNet32(SFLReceiver *receiver, uint32_t val);
static void putAddress(SFLReceiver *receiver, SFLAddress *addr);
static void putOpaque(SFLReceiver *receiver, char *val, int len);

/*_________________--------------------------__________________
  _________________    sfl_receiver_init     __________________
  -----------------__________________________------------------
*/

void sfl_receiver_init(SFLReceiver *receiver, SFLAgent *agent)
{
    /* first clear everything */
    memset(receiver, 0, sizeof(*receiver));

    /* now copy in the parameters */
    receiver->agent = agent;

    /* set defaults */
    receiver->sFlowRcvrMaximumDatagramSize = SFL_DEFAULT_DATAGRAM_SIZE;
    receiver->sFlowRcvrPort = SFL_DEFAULT_COLLECTOR_PORT;

    /* prepare to receive the first sample */
    resetSampleCollector(receiver);
}

/*_________________---------------------------__________________
  _________________      reset                __________________
  -----------------___________________________------------------

  called on timeout, or when owner string is cleared
*/

static void resetReceiver(SFLReceiver *receiver) {
    /* ask agent to tell samplers and pollers to stop sending samples */
    sfl_agent_resetReceiver(receiver->agent, receiver);
    /* reinitialize */
    sfl_receiver_init(receiver, receiver->agent);
}


/*_________________----------------------------------------_____________
  _________________          MIB Vars                      _____________
  -----------------________________________________________-------------
*/

char * sfl_receiver_get_sFlowRcvrOwner(SFLReceiver *receiver) {
    return receiver->sFlowRcvrOwner;
}
void sfl_receiver_set_sFlowRcvrOwner(SFLReceiver *receiver, char *sFlowRcvrOwner) {
    receiver->sFlowRcvrOwner = sFlowRcvrOwner;
    if(sFlowRcvrOwner == NULL || sFlowRcvrOwner[0] == '\0') {
        /* reset condition! owner string was cleared */
        resetReceiver(receiver);
    }
}
time_t sfl_receiver_get_sFlowRcvrTimeout(SFLReceiver *receiver) {
    return receiver->sFlowRcvrTimeout;
}
void sfl_receiver_set_sFlowRcvrTimeout(SFLReceiver *receiver, time_t sFlowRcvrTimeout) {
    receiver->sFlowRcvrTimeout =sFlowRcvrTimeout;
} 
uint32_t sfl_receiver_get_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver) {
    return receiver->sFlowRcvrMaximumDatagramSize;
}
void sfl_receiver_set_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver, uint32_t sFlowRcvrMaximumDatagramSize) {
    uint32_t mdz = sFlowRcvrMaximumDatagramSize;
    if(mdz < SFL_MIN_DATAGRAM_SIZE) mdz = SFL_MIN_DATAGRAM_SIZE;
    receiver->sFlowRcvrMaximumDatagramSize = mdz;
}
SFLAddress *sfl_receiver_get_sFlowRcvrAddress(SFLReceiver *receiver) {
    return &receiver->sFlowRcvrAddress;
}
void sfl_receiver_set_sFlowRcvrAddress(SFLReceiver *receiver, SFLAddress *sFlowRcvrAddress) {
    if(sFlowRcvrAddress) receiver->sFlowRcvrAddress = *sFlowRcvrAddress; /* structure copy */
}
uint32_t sfl_receiver_get_sFlowRcvrPort(SFLReceiver *receiver) {
    return receiver->sFlowRcvrPort;
}
void sfl_receiver_set_sFlowRcvrPort(SFLReceiver *receiver, uint32_t sFlowRcvrPort) {
    receiver->sFlowRcvrPort = sFlowRcvrPort;
}

/*_________________---------------------------__________________
  _________________   sfl_receiver_tick       __________________
  -----------------___________________________------------------
*/

void sfl_receiver_tick(SFLReceiver *receiver, time_t now)
{
    /* if there are any samples to send, flush them now */
    if(receiver->sampleCollector.numSamples > 0) sendSample(receiver);
    /* check the timeout */
    if(receiver->sFlowRcvrTimeout && (uint32_t)receiver->sFlowRcvrTimeout != 0xFFFFFFFF) {
        /* count down one tick and reset if we reach 0 */
        if(--receiver->sFlowRcvrTimeout == 0) resetReceiver(receiver);
    }
}

/*_________________-----------------------------__________________
  _________________   receiver write utilities  __________________
  -----------------_____________________________------------------
*/
 
static void put32(SFLReceiver *receiver, uint32_t val)
{
    *receiver->sampleCollector.datap++ = val;
}

static void putNet32(SFLReceiver *receiver, uint32_t val)
{
    *receiver->sampleCollector.datap++ = htonl(val);
}

static void putNet64(SFLReceiver *receiver, uint64_t val64)
{
    uint32_t *firstQuadPtr = receiver->sampleCollector.datap;
    /* first copy the bytes in */
    memcpy((byte_t *)firstQuadPtr, &val64, 8);
    if(htonl(1) != 1) {
        /* swap the bytes, and reverse the quads too */
        uint32_t tmp = *receiver->sampleCollector.datap++;
        *firstQuadPtr = htonl(*receiver->sampleCollector.datap);
        *receiver->sampleCollector.datap++ = htonl(tmp);
    }
    else receiver->sampleCollector.datap += 2;
}

static void put128(SFLReceiver *receiver, byte_t *val)
{
    memcpy(receiver->sampleCollector.datap, val, 16);
    receiver->sampleCollector.datap += 4;
}

static void putString(SFLReceiver *receiver, SFLString *s)
{
    putNet32(receiver, s->len);
    memcpy(receiver->sampleCollector.datap, s->str, s->len);
    receiver->sampleCollector.datap += (s->len + 3) / 4; /* pad to 4-byte boundary */
}

static uint32_t stringEncodingLength(SFLString *s) {
    /* answer in bytes,  so remember to mulitply by 4 after rounding up to nearest 4-byte boundary */
    return 4 + (((s->len + 3) / 4) * 4);
}

static void putAddress(SFLReceiver *receiver, SFLAddress *addr)
{
    /* encode unspecified addresses as IPV4:0.0.0.0 - or should we flag this as an error? */
    if(addr->type == 0) {
        putNet32(receiver, SFLADDRESSTYPE_IP_V4);
        put32(receiver, 0);
    }
    else {
        putNet32(receiver, addr->type);
        if(addr->type == SFLADDRESSTYPE_IP_V4) put32(receiver, addr->address.ip_v4.addr);
        else put128(receiver, addr->address.ip_v6.addr);
    }
}

static void putOpaque(SFLReceiver *receiver, char *val, int len)
{
    memcpy((char *)receiver->sampleCollector.datap, val, len);
    receiver->sampleCollector.datap += ((len+3)/4);
}

static uint32_t httpOpEncodingLength(SFLSampled_http *op) {
  uint32_t elemSiz = stringEncodingLength(&op->uri);
  elemSiz += stringEncodingLength(&op->host);
  elemSiz += stringEncodingLength(&op->referer);
  elemSiz += stringEncodingLength(&op->useragent);
  elemSiz += stringEncodingLength(&op->xff);
  elemSiz += stringEncodingLength(&op->authuser);
  elemSiz += stringEncodingLength(&op->mimetype);
  elemSiz += 32; /* method, protocol, req_bytes, resp_bytes, uS, status */
  return elemSiz;
}

static void putSocket4(SFLReceiver *receiver, SFLExtended_socket_ipv4 *socket4) {
    putNet32(receiver, socket4->protocol);
    put32(receiver, socket4->local_ip.addr);
    put32(receiver, socket4->remote_ip.addr);
    putNet32(receiver, socket4->local_port);
    putNet32(receiver, socket4->remote_port);
}

static void putSocket6(SFLReceiver *receiver, SFLExtended_socket_ipv6 *socket6) {
    putNet32(receiver, socket6->protocol);
    put128(receiver, socket6->local_ip.addr);
    put128(receiver, socket6->remote_ip.addr);
    putNet32(receiver, socket6->local_port);
    putNet32(receiver, socket6->remote_port);
}


/*_________________-----------------------------__________________
  _________________      computeFlowSampleSize  __________________
  -----------------_____________________________------------------
*/

static int computeFlowSampleSize(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs)
{
    SFLFlow_sample_element *elem;
    uint32_t elemSiz;
#ifdef SFL_USE_32BIT_INDEX
    uint siz = 52; /* tag, length, sequence_number, ds_class, ds_index, sampling_rate,
                      sample_pool, drops, inputFormat, input, outputFormat, output, number of elements */
#else
    uint32_t siz = 40; /* tag, length, sequence_number, source_id, sampling_rate,
                          sample_pool, drops, input, output, number of elements */
#endif

    /* hard code the wire-encoding sizes, in case the structures are expanded to be 64-bit aligned */

    fs->num_elements = 0; /* we're going to count them again even if this was set by the client */
    for(elem = fs->elements; elem != NULL; elem = elem->nxt) {
        fs->num_elements++;
        siz += 8; /* tag, length */
        elemSiz = 0;
        switch(elem->tag) {
        case SFLFLOW_HTTP: elemSiz = httpOpEncodingLength(&elem->flowType.http);  break;
        case SFLFLOW_EX_PROXY_SOCKET4:
        case SFLFLOW_EX_SOCKET4: elemSiz = XDRSIZ_SFLEXTENDED_SOCKET4;  break;
        case SFLFLOW_EX_PROXY_SOCKET6:
        case SFLFLOW_EX_SOCKET6: elemSiz = XDRSIZ_SFLEXTENDED_SOCKET6;  break;
        default:
            {
                char errm[MAX_ERRMSG_LEN];
                snprintf(errm, MAX_ERRMSG_LEN, "computeFlowSampleSize(): unexpected tag (%ud)", elem->tag);
                receiverError(receiver, errm);
                return -1;
            }
            break;
        }
        /* cache the element size, and accumulate it into the overall FlowSample size */
        elem->length = elemSiz;
        siz += elemSiz;
    }

    return siz;
}

/*_________________-------------------------------__________________
  _________________ sfl_receiver_writeFlowSample  __________________
  -----------------_______________________________------------------
*/

int sfl_receiver_writeFlowSample(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs)
{
    int packedSize;
    SFLFlow_sample_element *elem;
    uint32_t encodingSize;

    if(fs == NULL) return -1;
    if((packedSize = computeFlowSampleSize(receiver, fs)) == -1) return -1;

    /* check in case this one sample alone is too big for the datagram */
    if(packedSize > (int)(receiver->sFlowRcvrMaximumDatagramSize)) {
        receiverError(receiver, "flow sample too big for datagram");
        return -1;
    }

    /* if the sample pkt is full enough so that this sample might put */
    /* it over the limit, then we should send it now before going on. */
    if((receiver->sampleCollector.pktlen + packedSize) >= receiver->sFlowRcvrMaximumDatagramSize)
        sendSample(receiver);
    
    receiver->sampleCollector.numSamples++;

#ifdef SFL_USE_32BIT_INDEX
    putNet32(receiver, SFLFLOW_SAMPLE_EXPANDED);
#else
    putNet32(receiver, SFLFLOW_SAMPLE);
#endif

    putNet32(receiver, packedSize - 8); /* don't include tag and len */
    putNet32(receiver, fs->sequence_number);

#ifdef SFL_USE_32BIT_INDEX
    putNet32(receiver, fs->ds_class);
    putNet32(receiver, fs->ds_index);
#else
    putNet32(receiver, fs->source_id);
#endif

    putNet32(receiver, fs->sampling_rate);
    putNet32(receiver, fs->sample_pool);
    putNet32(receiver, fs->drops);

#ifdef SFL_USE_32BIT_INDEX
    putNet32(receiver, fs->inputFormat);
    putNet32(receiver, fs->input);
    putNet32(receiver, fs->outputFormat);
    putNet32(receiver, fs->output);
#else
    putNet32(receiver, fs->input);
    putNet32(receiver, fs->output);
#endif

    putNet32(receiver, fs->num_elements);

    for(elem = fs->elements; elem != NULL; elem = elem->nxt) {

        putNet32(receiver, elem->tag);
        putNet32(receiver, elem->length); /* length cached in computeFlowSampleSize() */

        switch(elem->tag) {
        case SFLFLOW_EX_PROXY_SOCKET4:
        case SFLFLOW_EX_SOCKET4: putSocket4(receiver, &elem->flowType.socket4); break;
        case SFLFLOW_EX_PROXY_SOCKET6:
        case SFLFLOW_EX_SOCKET6: putSocket6(receiver, &elem->flowType.socket6); break;
        case SFLFLOW_HTTP:
            putNet32(receiver, elem->flowType.http.method);
            putNet32(receiver, elem->flowType.http.protocol);
            putString(receiver, &elem->flowType.http.uri);
            putString(receiver, &elem->flowType.http.host);
            putString(receiver, &elem->flowType.http.referer);
            putString(receiver, &elem->flowType.http.useragent);
            putString(receiver, &elem->flowType.http.xff);
            putString(receiver, &elem->flowType.http.authuser);
            putString(receiver, &elem->flowType.http.mimetype);
            putNet64(receiver, elem->flowType.http.req_bytes);
            putNet64(receiver, elem->flowType.http.resp_bytes);
            putNet32(receiver, elem->flowType.http.uS);
            putNet32(receiver, elem->flowType.http.status);
            break;
        default:
            {
                char errm[MAX_ERRMSG_LEN];
                snprintf(errm, MAX_ERRMSG_LEN, "sfl_receiver_writeFlowSample: unexpected tag (%ud)", elem->tag);
                receiverError(receiver, errm);
                return -1;
            }
            break;
        }
    }

    /* sanity check */
    encodingSize = (byte_t *)receiver->sampleCollector.datap
        - (byte_t *)receiver->sampleCollector.data
        - receiver->sampleCollector.pktlen;

    if(encodingSize != (uint32_t)packedSize) {
        char errm[MAX_ERRMSG_LEN];
        snprintf(errm, MAX_ERRMSG_LEN, "sfl_receiver_writeFlowSample: encoding_size(%ud) != expected_size(%ud)",
                     encodingSize,
                     packedSize);
        receiverError(receiver, errm);
        return -1;
    }
      
    /* update the pktlen */
    receiver->sampleCollector.pktlen = (byte_t *)receiver->sampleCollector.datap - (byte_t *)receiver->sampleCollector.data;
    return packedSize;
}

/*_________________--------------------------------------__________________
  _________________ sfl_receiver_writeEncodedFlowSample  __________________
  -----------------______________________________________------------------
*/

int sfl_receiver_writeEncodedFlowSample(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs, char *xdrBytes, uint32_t packedSize)
{
    uint32_t encodingSize;
    uint32_t overrideEncodingSize;
    uint32_t xdrHdrStrip;

    /* check in case this one sample alone is too big for the datagram */
    if(packedSize > receiver->sFlowRcvrMaximumDatagramSize) {
        receiverError(receiver, "flow sample too big for datagram");
        return -1;
    }

    /* if the sample pkt is full enough so that this sample might put */
    /* it over the limit, then we should send it now before going on. */
    if((receiver->sampleCollector.pktlen + packedSize) >= receiver->sFlowRcvrMaximumDatagramSize)
        sendSample(receiver);
    
    receiver->sampleCollector.numSamples++;

#ifdef SFL_USE_32BIT_INDEX
    putNet32(receiver, SFLFLOW_SAMPLE_EXPANDED);
#else
    putNet32(receiver, SFLFLOW_SAMPLE);
#endif

    putNet32(receiver, packedSize - 8); /* don't include tag and len bytes in the length */
    putNet32(receiver, fs->sequence_number);

#ifdef SFL_USE_32BIT_INDEX
    putNet32(receiver, fs->ds_class);
    putNet32(receiver, fs->ds_index);
#else
    putNet32(receiver, fs->source_id);
#endif

    putNet32(receiver, fs->sampling_rate);
    putNet32(receiver, fs->sample_pool);
    putNet32(receiver, fs->drops);

    /* sanity check */
    overrideEncodingSize = (byte_t *)receiver->sampleCollector.datap
        - (byte_t *)receiver->sampleCollector.data
        - receiver->sampleCollector.pktlen;

#ifdef SFL_USE_32BIT_INDEX
    xdrHdrStrip = 32; /* tag, length, sequence_number, ds_class, ds_index, sampling_rate,
                         sample_pool, drops, [inputFormat, input, outputFormat, output, number of elements...] */
#else
    xdrHdrStrip = 28; /* tag, length, sequence_number, source_id, sampling_rate,
                         sample_pool, drops, [input, output, number of elements...] */
#endif

    memcpy(receiver->sampleCollector.datap, xdrBytes + xdrHdrStrip, packedSize - xdrHdrStrip);
    receiver->sampleCollector.datap += ((packedSize - xdrHdrStrip) >> 2);

    /* sanity check */
    encodingSize = (byte_t *)receiver->sampleCollector.datap
        - (byte_t *)receiver->sampleCollector.data
        - receiver->sampleCollector.pktlen;

    if(encodingSize != (uint32_t)packedSize) {
        char errm[MAX_ERRMSG_LEN];
        snprintf(errm, MAX_ERRMSG_LEN, "sfl_receiver_writeEncodedFlowSample: encoding_size(%ud) != expected_size(%ud) [overrideEncodingSize=%ud xdrHeaderStrip=%ud pktlen=%ud]",
                     encodingSize,
                     packedSize,
                     overrideEncodingSize,
                     xdrHdrStrip,
                     receiver->sampleCollector.pktlen);
        receiverError(receiver, errm);
        return -1;
    }
      
    /* update the pktlen */
    receiver->sampleCollector.pktlen = (byte_t *)receiver->sampleCollector.datap - (byte_t *)receiver->sampleCollector.data;
    return packedSize;
}

/*_________________-----------------------------__________________
  _________________ computeCountersSampleSize   __________________
  -----------------_____________________________------------------
*/

static int computeCountersSampleSize(SFLReceiver *receiver, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    SFLCounters_sample_element *elem;
    uint32_t elemSiz;

#ifdef SFL_USE_32BIT_INDEX
    uint siz = 24; /* tag, length, sequence_number, ds_class, ds_index, number of elements */
#else
    uint32_t siz = 20; /* tag, length, sequence_number, source_id, number of elements */
#endif

    cs->num_elements = 0; /* we're going to count them again even if this was set by the client */
    for( elem = cs->elements; elem != NULL; elem = elem->nxt) {
        cs->num_elements++;
        siz += 8; /* tag, length */
        elemSiz = 0;

        /* hard code the wire-encoding sizes rather than use sizeof() -- in case the
           structures are expanded to be 64-bit aligned */

        switch(elem->tag) {
        case SFLCOUNTERS_HOST_PAR: elemSiz = 8 /*sizeof(elem->counterBlock.host_par)*/;  break;
        case SFLCOUNTERS_HTTP: elemSiz = XDRSIZ_SFLHTTP_COUNTERS /*sizeof(elem->counterBlock.http)*/;  break;
        default:
            {
                char errm[MAX_ERRMSG_LEN];
                snprintf(errm, MAX_ERRMSG_LEN, "computeCounterSampleSize(): unexpected counters tag (%ud)", elem->tag);
                receiverError(receiver, errm);
                return -1;
            }
            break;
        }
        /* cache the element size, and accumulate it into the overall FlowSample size */
        elem->length = elemSiz;
        siz += elemSiz;
    }
    return siz;
}

/*_________________----------------------------------__________________
  _________________ sfl_receiver_writeCountersSample __________________
  -----------------__________________________________------------------
*/

int sfl_receiver_writeCountersSample(SFLReceiver *receiver, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    int packedSize;
    SFLCounters_sample_element *elem;
    uint32_t encodingSize;

    if(cs == NULL) return -1;
    /* if the sample pkt is full enough so that this sample might put */
    /* it over the limit, then we should send it now. */
    if((packedSize = computeCountersSampleSize(receiver, cs)) == -1) return -1;
  
    /* check in case this one sample alone is too big for the datagram */
    /* in fact - if it is even half as big then we should ditch it. Very */
    /* important to avoid overruning the packet buffer. */
    if(packedSize > (int)(receiver->sFlowRcvrMaximumDatagramSize / 2)) {
        receiverError(receiver, "counters sample too big for datagram");
        return -1;
    }
  
    if((receiver->sampleCollector.pktlen + packedSize) >= receiver->sFlowRcvrMaximumDatagramSize)
        sendSample(receiver);
  
    receiver->sampleCollector.numSamples++;
  
#ifdef SFL_USE_32BIT_INDEX
    putNet32(receiver, SFLCOUNTERS_SAMPLE_EXPANDED);
#else
    putNet32(receiver, SFLCOUNTERS_SAMPLE);
#endif

    putNet32(receiver, packedSize - 8); /* tag and length not included */
    putNet32(receiver, cs->sequence_number);

#ifdef SFL_USE_32BIT_INDEX
    putNet32(receiver, cs->ds_class);
    putNet32(receiver, cs->ds_index);
#else
    putNet32(receiver, cs->source_id);
#endif

    putNet32(receiver, cs->num_elements);
  
    for(elem = cs->elements; elem != NULL; elem = elem->nxt) {
    
        putNet32(receiver, elem->tag);
        putNet32(receiver, elem->length); /* length cached in computeCountersSampleSize() */
    
        switch(elem->tag) {
        case SFLCOUNTERS_HOST_PAR:
            putNet32(receiver, elem->counterBlock.host_par.dsClass);
            putNet32(receiver, elem->counterBlock.host_par.dsIndex);
            break;
        case SFLCOUNTERS_HTTP:
            putNet32(receiver, elem->counterBlock.http.method_option_count);
            putNet32(receiver, elem->counterBlock.http.method_get_count);
            putNet32(receiver, elem->counterBlock.http.method_head_count);
            putNet32(receiver, elem->counterBlock.http.method_post_count);
            putNet32(receiver, elem->counterBlock.http.method_put_count);
            putNet32(receiver, elem->counterBlock.http.method_delete_count);
            putNet32(receiver, elem->counterBlock.http.method_trace_count);
            putNet32(receiver, elem->counterBlock.http.method_connect_count);
            putNet32(receiver, elem->counterBlock.http.method_other_count);
            putNet32(receiver, elem->counterBlock.http.status_1XX_count);
            putNet32(receiver, elem->counterBlock.http.status_2XX_count);
            putNet32(receiver, elem->counterBlock.http.status_3XX_count);
            putNet32(receiver, elem->counterBlock.http.status_4XX_count);
            putNet32(receiver, elem->counterBlock.http.status_5XX_count);
            putNet32(receiver, elem->counterBlock.http.status_other_count);
            break;
        default:
            {
                char errm[MAX_ERRMSG_LEN];
                snprintf(errm, MAX_ERRMSG_LEN, "unexpected counters tag (%ud)", elem->tag);
                receiverError(receiver, errm);
                return -1;
            }
            break;
        }
    }
    /* sanity check */
    encodingSize = (byte_t *)receiver->sampleCollector.datap
        - (byte_t *)receiver->sampleCollector.data
        - receiver->sampleCollector.pktlen;
    if(encodingSize != (uint32_t)packedSize) {
        char errm[MAX_ERRMSG_LEN];
        snprintf(errm, MAX_ERRMSG_LEN, "sfl_receiver_writeCountersSample: encoding_size(%ud) != expected_size(%ud)",
                     encodingSize,
                     packedSize);
        receiverError(receiver, errm);
        return -1;
    }

    /* update the pktlen */
    receiver->sampleCollector.pktlen = (byte_t *)receiver->sampleCollector.datap - (byte_t *)receiver->sampleCollector.data;
    return packedSize;
}

/*_________________---------------------------------__________________
  _________________ sfl_receiver_samplePacketsSent  __________________
  -----------------_________________________________------------------
*/

uint32_t sfl_receiver_samplePacketsSent(SFLReceiver *receiver)
{
    return receiver->sampleCollector.packetSeqNo;
}

/*_________________---------------------------__________________
  _________________     sendSample            __________________
  -----------------___________________________------------------
*/

static void sendSample(SFLReceiver *receiver)
{  
    /* construct and send out the sample, then reset for the next one... */
    SFLAgent *agent = receiver->agent;
  
    /* go back and fill in the header */
    receiver->sampleCollector.datap = receiver->sampleCollector.data;
    putNet32(receiver, SFLDATAGRAM_VERSION5);
    putAddress(receiver, &agent->myIP);
    putNet32(receiver, agent->subId);
    putNet32(receiver, ++receiver->sampleCollector.packetSeqNo);
    putNet32(receiver,  (uint32_t)((agent->now - agent->bootTime) * 1000));
    putNet32(receiver, receiver->sampleCollector.numSamples);
  
    /* send */
    if(agent->sendFn) (*agent->sendFn)(agent->magic,
                                       agent,
                                       receiver,
                                       (byte_t *)receiver->sampleCollector.data, 
                                       receiver->sampleCollector.pktlen);

    /* reset for the next time */
    resetSampleCollector(receiver);
}

/*_________________---------------------------__________________
  _________________   resetSampleCollector    __________________
  -----------------___________________________------------------
*/

static void resetSampleCollector(SFLReceiver *receiver)
{
    receiver->sampleCollector.pktlen = 0;
    receiver->sampleCollector.numSamples = 0;

    /* clear the buffer completely (ensures that pad bytes will always be zeros - thank you CW) */
    memset((byte_t *)receiver->sampleCollector.data, 0, (SFL_SAMPLECOLLECTOR_DATA_QUADS * 4));

    /* point the datap to just after the header */
    receiver->sampleCollector.datap = (receiver->agent->myIP.type == SFLADDRESSTYPE_IP_V6) ?
        (receiver->sampleCollector.data + 10) :
        (receiver->sampleCollector.data + 7);

    /* start pktlen with the right value */
    receiver->sampleCollector.pktlen = (byte_t *)receiver->sampleCollector.datap - (byte_t *)receiver->sampleCollector.data;
}

/*_________________---------------------------__________________
  _________________    receiverError          __________________
  -----------------___________________________------------------
*/

static void receiverError(SFLReceiver *receiver, char *msg)
{
    sfl_agent_error(receiver->agent, "receiver", msg);
    resetSampleCollector(receiver);
}


/*_________________---------------------------__________________
  _________________         exposure          __________________
  -----------------___________________________------------------
selective exposure of some internal hooks,  just for this project
*/

void sfl_receiver_put32(SFLReceiver *receiver, uint32_t val) { put32(receiver, val); }
void sfl_receiver_putOpaque(SFLReceiver *receiver, char *val, int len) { putOpaque(receiver, val, len); }
void sfl_receiver_resetSampleCollector(SFLReceiver *receiver) { resetSampleCollector(receiver); }

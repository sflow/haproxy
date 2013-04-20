/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Copyright (c) 2002-2010 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef SFLOW_CONFIG_H
#define SFLOW_CONFIG_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "common/memory.h"
#include "sflow.h"

/*_________________---------------------------__________________
  _________________   config parsing defs     __________________
  -----------------___________________________------------------
*/

#define SFWB_DEFAULT_CONFIGFILE "/etc/hsflowd.auto"
#define SFWB_SEPARATORS " \t\r\n="
#define SFWB_QUOTES "'\" \t\r\n"
/* SFWB_MAX LINE LEN must be enough to hold the whole list of targets */
#define SFWB_MAX_LINELEN 1024
#define SFWB_MAX_COLLECTORS 10
#define SFWB_CONFIG_CHECK_S 10

/*_________________---------------------------__________________
  _________________   structure definitions   __________________
  -----------------___________________________------------------
*/

typedef struct _SFWBCollector {
    SFLAddress ipAddr;
    uint32_t udpPort;
    struct sockaddr_in6 sendSocketAddr;
    uint16_t priority;
} SFWBCollector;

typedef struct _SFWBConfig {
    int32_t error;
    uint32_t sampling_n;
    uint32_t polling_secs;
    bool_t got_sampling_n_http;
    bool_t got_polling_secs_http;
    SFLAddress agentIP;
    uint32_t num_collectors;
    SFWBCollector collectors[SFWB_MAX_COLLECTORS];
    uint32_t parent_ds_index;
} SFWBConfig;


typedef struct _SFWBConfigManager {
    /* master config */
    int32_t configCountDown;
    char *configFile;
    time_t configFile_modTime;
    SFWBConfig *config;
    int socket4;
    int socket6;
    struct pool_head *pool2_SFWBConfig;
} SFWBConfigManager;
        
bool_t sfwb_config_tick(SFWBConfigManager *sm);
void sfwb_config_send_packet(SFWBConfigManager *sm,  u_char *pkt, uint32_t pktLen);
void sfwb_config_init(SFWBConfigManager *sm);
SFLAddress *sfwb_config_agentIP(SFWBConfigManager *sm);
uint32_t sfwb_config_polling_secs(SFWBConfigManager *sm);
uint32_t sfwb_config_sampling_n(SFWBConfigManager *sm);
uint32_t sfwb_config_parent_ds_index(SFWBConfigManager *sm);
bool_t sfwb_config_valid(SFWBConfigManager *sm);

#endif /* SFLOW_CONFIG_H */

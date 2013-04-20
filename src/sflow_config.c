/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Copyright (c) 2002-2010 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/memory.h"
#include "proto/log.h"
#include "sflow/sflow_config.h"

/*________________---------------------------__________________
  ________________   sfwb_lookupAddress      __________________
  ----------------___________________________------------------
*/

static bool_t sfwb_lookupAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family)
{
    struct addrinfo *info = NULL;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM; /* constrain this so we don't get lots of answers */
    hints.ai_family = family; // PF_INET, PF_INET6 or 0
    int err = getaddrinfo(name, NULL, &hints, &info);
    if(err) {
        Warning("getaddrinfo() failed: %s", gai_strerror(err));
        switch(err) {
        case EAI_NONAME: break;
#ifdef EAI_NODATA /* because it requires __USE_GNU */
        case EAI_NODATA: break;
#endif
        case EAI_AGAIN: break; // loop and try again?
        default: Warning("getaddrinfo() error: %s", gai_strerror(err)); break;
        }
        return false;
    }
    
    if(info == NULL) return false;
    
    if(info->ai_addr) {
        /* answer is now in info - a linked list of answers with sockaddr values.
           extract the address we want from the first one. */
      switch(info->ai_family) {
      case PF_INET:
          {
              struct sockaddr_in *ipsoc = (struct sockaddr_in *)info->ai_addr;
              addr->type = SFLADDRESSTYPE_IP_V4;
              addr->address.ip_v4.addr = ipsoc->sin_addr.s_addr;
              if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
          }
          break;

      case PF_INET6:
          {
              struct sockaddr_in6 *ip6soc = (struct sockaddr_in6 *)info->ai_addr;
              addr->type = SFLADDRESSTYPE_IP_V6;
              memcpy(&addr->address.ip_v6, &ip6soc->sin6_addr, 16);
              if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
          }
          break;

      default:
          Warning("get addrinfo: unexpected address family: %d", info->ai_family);
          return false;
          break;
      }
    }
    /* free the dynamically allocated data before returning */
    freeaddrinfo(info);
    return true;
}


static bool_t sfwb_syntaxOK(SFWBConfig *cfg, uint32_t line, uint32_t tokc, uint32_t tokcMin, uint32_t tokcMax, char *syntax) {
    if(tokc < tokcMin || tokc > tokcMax) {
        cfg->error = true;
        Warning("syntax error: expected %s on line %ud", syntax, line);
        return false;
    }
    return true;
}

static void sfwb_syntaxError(SFWBConfig *cfg, uint32_t line, char *msg) {
    cfg->error = true;
    Warning("syntax error : %s (on line %ud)", msg, line);
}    

static SFWBConfig *sfwb_readConfig(SFWBConfigManager *sm)
{
    FILE *cfg = NULL;
    if((cfg = fopen(sm->configFile, "r")) == NULL) {
        Warning("cannot open config file %s : %s", sm->configFile, strerror(errno));
        return NULL;
    }

    uint32_t rev_start = 0;
    uint32_t rev_end = 0;

    SFWBConfig *config = pool_alloc2(sm->pool2_SFWBConfig);

    char line[SFWB_MAX_LINELEN+1];
    uint32_t lineNo = 0;
    char *tokv[5];
    uint32_t tokc;
    while(fgets(line, SFWB_MAX_LINELEN, cfg)) {
        int32_t i;
        char *p = line;
        lineNo++;
        /* comments start with '#' */
        p[strcspn(p, "#")] = '\0';
        /* 1 var and up to 3 value tokens, so detect up to 5 tokens overall */
        /* so we know if there was an extra one that should be flagged as a */
        /* syntax error. */
        tokc = 0;
        for(i = 0; i < 5; i++) {
            size_t len;
            p += strspn(p, SFWB_SEPARATORS);
            if((len = strcspn(p, SFWB_SEPARATORS)) == 0) break;
            tokv[tokc++] = p;
            p += len;
            if(*p != '\0') *p++ = '\0';
        }

        if(tokc) {
            if(strcasecmp(tokv[0], "rev_start") == 0
               && sfwb_syntaxOK(config, lineNo, tokc, 2, 2, "rev_start=<int>")) {
                rev_start = strtol(tokv[1], NULL, 0);
            }
            else if(strcasecmp(tokv[0], "rev_end") == 0
                    && sfwb_syntaxOK(config, lineNo, tokc, 2, 2, "rev_end=<int>")) {
                rev_end = strtol(tokv[1], NULL, 0);
            }
            else if(strcasecmp(tokv[0], "sampling") == 0
                    && sfwb_syntaxOK(config, lineNo, tokc, 2, 2, "sampling=<int>")) {
                if(!config->got_sampling_n_http) {
                    config->sampling_n = strtol(tokv[1], NULL, 0);
                }
            }
            else if(strcasecmp(tokv[0], "sampling.http") == 0
                    && sfwb_syntaxOK(config, lineNo, tokc, 2, 2, "sampling.http=<int>")) {
                /* sampling.http takes precedence over sampling */
                config->sampling_n = strtol(tokv[1], NULL, 0);
                config->got_sampling_n_http = true;
            }
            else if(strcasecmp(tokv[0], "polling") == 0 
                    && sfwb_syntaxOK(config, lineNo, tokc, 2, 2, "polling=<int>")) {
                if(!config->got_polling_secs_http) {
                    config->polling_secs = strtol(tokv[1], NULL, 0);
                }
            }
            else if(strcasecmp(tokv[0], "polling.http") == 0 
                    && sfwb_syntaxOK(config, lineNo, tokc, 2, 2, "polling.http=<int>")) {
                /* polling.http takes precedence over polling */
                config->polling_secs = strtol(tokv[1], NULL, 0);
                config->got_polling_secs_http = true;
            }
            else if(strcasecmp(tokv[0], "agentIP") == 0
                    && sfwb_syntaxOK(config, lineNo, tokc, 2, 2, "agentIP=<IP address>|<IPv6 address>")) {
                if(sfwb_lookupAddress(tokv[1], NULL, &config->agentIP, 0) == false) {
                    sfwb_syntaxError(config, lineNo, "agent address lookup failed");
                }
            }
            else if(strcasecmp(tokv[0], "collector") == 0
                    && sfwb_syntaxOK(config, lineNo, tokc, 2, 4, "collector=<IP address>[ <port>[ <priority>]]")) {
                if(config->num_collectors < SFWB_MAX_COLLECTORS) {
                    uint32_t i = config->num_collectors++;
                    config->collectors[i].udpPort = tokc >= 3 ? strtol(tokv[2], NULL, 0) : 6343;
                    config->collectors[i].priority = tokc >= 4 ? strtol(tokv[3], NULL, 0) : 0;
                    if(sfwb_lookupAddress(tokv[1],
                                          (struct sockaddr *)&config->collectors[i].sendSocketAddr,
                                          &config->collectors[i].ipAddr,
                                          0) == false) {
                        Warning("create_sflow_config: error allocating collector socket address");
                    }
                }
                else {
                    sfwb_syntaxError(config, lineNo, "exceeded max collectors");
                }
            }
            else if(strcasecmp(tokv[0], "ds_index") == 0
                    && sfwb_syntaxOK(config, lineNo, tokc, 2, 2, "ds_index=<int>")) {
                config->parent_ds_index = strtol(tokv[1], NULL, 0);
            }
            else if(strcasecmp(tokv[0], "header") == 0) { /* ignore */ }
            else if(strcasecmp(tokv[0], "agent") == 0) { /* ignore */ }
            else if(strncasecmp(tokv[0], "sampling.", 9) == 0) { /* ignore other sampling.<app> settings */ }
            else if(strncasecmp(tokv[0], "polling.", 8) == 0) { /* ignore other polling.<app> settings */ }
            else {
                /* don't abort just because a new setting was added */
                /* sfwb_syntaxError(config, lineNo, "unknown var=value setting"); */
            }
        }
    }
    fclose(cfg);
    
    /* sanity checks... */

    if(lineNo <= 1) {
        /* silently ignore an empty file - treat the same as missing */
        config->error = true;
    }
    else if(config->agentIP.type == SFLADDRESSTYPE_UNDEFINED) {
        /* make sure we got an agentIP. Log error if not. */
        sfwb_syntaxError(config, 0, "agentIP=<IP address>|<IPv6 address>");
    }
    
    if((rev_start == rev_end) && !config->error) {
        return config;
    }
    else {
        pool_free2(sm->pool2_SFWBConfig, config);
        return NULL;
    }
}

/*_________________---------------------------__________________
  _________________  sfwb_config_changed      __________________
  -----------------___________________________------------------
*/

static void sfwb_config_changed(SFWBConfigManager *sm)
{
    if(sfwb_config_valid(sm)) {
        /* make sure the send sockets are open - one for v4 and another for v6 */
        if(sm->socket4 <= 0) {
            if((sm->socket4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
                Warning("IPv4 send socket open failed : %s", strerror(errno));
        }
        if(sm->socket6 <= 0) {
            if((sm->socket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
                Warning("IPv6 send socket open failed : %s", strerror(errno));
        }
    }
}

/*_________________---------------------------__________________
  _________________        apply config       __________________
  -----------------___________________________------------------
*/

static bool_t sfwb_apply_config(SFWBConfigManager *sm, SFWBConfig *config)
{
    if(config == sm->config) {
        return false;
    }

    SFWBConfig *oldConfig = sm->config;
    sm->config = config;

    if(oldConfig) {
        /* free the old one */
        pool_free2(sm->pool2_SFWBConfig, oldConfig);
    }

    sfwb_config_changed(sm);
    return true;
}

/*_________________---------------------------__________________
  _________________   config file mod-time    __________________
  -----------------___________________________------------------
*/
        
static time_t sfwb_configModifiedTime(SFWBConfigManager *sm) {
    struct stat statBuf;
    time_t mtime = 0;
    if(stat(sm->configFile, &statBuf) != 0) {
        Warning("stat(%s) failed", sm->configFile);
    }
    else {
        mtime = statBuf.st_mtime;
    }
    return mtime;
}

/*_________________---------------------------__________________
  _________________      1 second tick        __________________
  -----------------___________________________------------------
*/
        
bool_t sfwb_config_tick(SFWBConfigManager *sm) {
    bool_t changed = false;
    if(--sm->configCountDown <= 0) {
        time_t modTime = sfwb_configModifiedTime(sm);
        sm->configCountDown = SFWB_CONFIG_CHECK_S;
        
        if(modTime == 0) {
            /* config file missing */
            changed = sfwb_apply_config(sm, NULL);
            sm->configFile_modTime = 0;
        }
        else if(modTime != sm->configFile_modTime) {
            /* config file modified */
            SFWBConfig *newConfig = sfwb_readConfig(sm);
            if(newConfig) {
                /* config OK - apply it */
                Warning("sFlow config file OK");
                changed = sfwb_apply_config(sm, newConfig);
                sm->configFile_modTime = modTime;
            }
            else {
                /* bad config - ignore it (may be in transition) */
                Warning("sFlow config file parse failed");
            }
        }
    }
    return changed;
}

/*_________________----------------------------__________________
  _________________   sfwb_config_valid        __________________
  -----------------____________________________------------------
*/

bool_t sfwb_config_valid(SFWBConfigManager *sm)
{
    return (sm && sm->config);
}

/*_________________----------------------------__________________
  _________________   sfwb_config_agentIP      __________________
  -----------------____________________________------------------
*/

SFLAddress *sfwb_config_agentIP(SFWBConfigManager *sm)
{
    return sfwb_config_valid(sm) ? &sm->config->agentIP : NULL;
}

/*_________________----------------------------__________________
  _________________   sfwb_config_polling_secs __________________
  -----------------____________________________------------------
*/

uint32_t sfwb_config_polling_secs(SFWBConfigManager *sm)
{
    return sfwb_config_valid(sm) ? sm->config->polling_secs : 0;
}

/*_________________----------------------------__________________
  _________________   sfwb_config_sampling_n   __________________
  -----------------____________________________------------------
*/

uint32_t sfwb_config_sampling_n(SFWBConfigManager *sm)
{
    return sfwb_config_valid(sm) ? sm->config->sampling_n : 0;
}

/*_________________---------------------------------_____________
  _________________   sfwb_config_parent_ds_index   _____________
  -----------------_________________________________-------------
*/

uint32_t sfwb_config_parent_ds_index(SFWBConfigManager *sm)
{
    return sfwb_config_valid(sm) ? sm->config->parent_ds_index : 0;
}

/*_________________---------------------------__________________
  _________________   sfwb_config_send_packet __________________
  -----------------___________________________------------------
*/

void sfwb_config_send_packet(SFWBConfigManager *sm,  u_char *pkt, uint32_t pktLen)
{
    uint32_t c = 0;
    if(!sm->config) {
        /* config is disabled */
        return;
    }

    for(c = 0; c < sm->config->num_collectors; c++) {
        SFWBCollector *coll = &sm->config->collectors[c];
        socklen_t socklen=0;
        int fd=0;
        switch(coll->ipAddr.type) {
        case SFLADDRESSTYPE_UNDEFINED:
            /* skip over it if the forward lookup failed */
            break;
        case SFLADDRESSTYPE_IP_V4:
            {
                struct sockaddr_in *sa = (struct sockaddr_in *)&(coll->sendSocketAddr);
                socklen = sizeof(struct sockaddr_in);
                sa->sin_family = AF_INET;
                sa->sin_port = htons(coll->udpPort);
                fd = sm->socket4;
            }
            break;

        case SFLADDRESSTYPE_IP_V6:
            {
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&(coll->sendSocketAddr);
                socklen = sizeof(struct sockaddr_in6);
                sa6->sin6_family = AF_INET6;
                sa6->sin6_port = htons(coll->udpPort);
                fd = sm->socket6;
            }
            break;

        }
        
        if(socklen && fd > 0) {
            int result = sendto(fd,
                                pkt,
                                pktLen,
                                0,
                                (struct sockaddr *)&coll->sendSocketAddr,
                                socklen);
            if(result == -1 && errno != EINTR) {
                Warning("socket sendto error: %s", strerror(errno));
            }
            if(result == 0) {
                Warning("socket sendto returned 0: %s", strerror(errno));
            }
        }
    }
}

/*_________________---------------------------__________________
  _________________   sfwb_config_init        __________________
  -----------------___________________________------------------
*/

void sfwb_config_init(SFWBConfigManager *sm)
{
    sm->configFile = SFWB_DEFAULT_CONFIGFILE;
    sm->pool2_SFWBConfig = create_pool("SFWBConfig", sizeof(SFWBConfig), MEM_F_SHARED);
}


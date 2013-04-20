/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Copyright (c) 2002-2013 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef SFLOW_HAPROXY_H
#define SFLOW_HAPROXY_H 1

#include "sflow.h"

struct sflow_capture {
    int version;
    char uri[SFLHTTP_MAX_URI_LEN + 1];
    int uri_len;
    char host[SFLHTTP_MAX_HOST_LEN + 1];
    int host_len;
    char referer[SFLHTTP_MAX_REFERER_LEN + 1];
    int referer_len;
    char useragent[SFLHTTP_MAX_USERAGENT_LEN + 1];
    int useragent_len;
    char xff[SFLHTTP_MAX_XFF_LEN + 1];
    int xff_len;
    char authuser[SFLHTTP_MAX_AUTHUSER_LEN + 1];
    int authuser_len;
    char mimetype[SFLHTTP_MAX_MIMETYPE_LEN + 1];
    int mimetype_len;
};

void sflow_init();
void sflow_start_transaction(struct session *s);
void sflow_end_transaction(struct session *s);

#endif /* SFLOW_HAPROXY_H */

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Copyright (c) 2002-2013 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef SFLOW_H
#define SFLOW_H 1

#include <inttypes.h>

typedef unsigned char byte_t;
/* #include <stdbool.h> */
#define true 1
#define false 0
/* use 32-bits for bool_t to help avoid unaligned fields */
typedef uint32_t bool_t;

typedef struct {
    uint32_t addr;
} SFLIPv4;

typedef struct {
    byte_t addr[16];
} SFLIPv6;

typedef union _SFLAddress_value {
    SFLIPv4 ip_v4;
    SFLIPv6 ip_v6;
} SFLAddress_value;

enum SFLAddress_type {
    SFLADDRESSTYPE_UNDEFINED = 0,
    SFLADDRESSTYPE_IP_V4 = 1,
    SFLADDRESSTYPE_IP_V6 = 2
};

typedef struct _SFLAddress {
    uint32_t type;           /* enum SFLAddress_type */
    SFLAddress_value address;
} SFLAddress;

enum SFL_DSCLASS {
    SFL_DSCLASS_IFINDEX=0,
    SFL_DSCLASS_VLAN=1,
    SFL_DSCLASS_PHYSICAL_ENTITY=2,
    SFL_DSCLASS_LOGICAL_ENTITY=3
};

/* Packet header data */

#define SFL_DEFAULT_HEADER_SIZE 128
#define SFL_DEFAULT_COLLECTOR_PORT 6343
#define SFL_DEFAULT_SAMPLING_RATE 400
#define SFL_DEFAULT_POLLING_INTERVAL 30

/* Extended data types */

typedef struct _SFLString {
    uint32_t len;
    const char *str;
} SFLString;

/* Extended socket information,
   Must be filled in for all application transactions associated with a network socket
   Omit if transaction associated with non-network IPC  */

/* IPv4 Socket */
/* opaque = flow_data; enterprise = 0; format = 2100 */
typedef struct _SFLExtended_socket_ipv4 {
    uint32_t protocol;     /* IP Protocol (e.g. TCP = 6, UDP = 17) */
    SFLIPv4 local_ip;          /* local IP address */
    SFLIPv4 remote_ip;         /* remote IP address */
    uint32_t local_port;   /* TCP/UDP local port number or equivalent */
    uint32_t remote_port;  /* TCP/UDP remote port number of equivalent */
} SFLExtended_socket_ipv4;

#define XDRSIZ_SFLEXTENDED_SOCKET4 20 

/* IPv6 Socket */
/* opaque = flow_data; enterprise = 0; format = 2101 */
typedef struct _SFLExtended_socket_ipv6 {
    uint32_t protocol;     /* IP Protocol (e.g. TCP = 6, UDP = 17) */
    SFLIPv6 local_ip;          /* local IP address */
    SFLIPv6 remote_ip;         /* remote IP address */
    uint32_t local_port;   /* TCP/UDP local port number or equivalent */
    uint32_t remote_port;  /* TCP/UDP remote port number of equivalent */
} SFLExtended_socket_ipv6;

#define XDRSIZ_SFLEXTENDED_SOCKET6 44

typedef enum {
    SFHTTP_OTHER    = 0,
    SFHTTP_OPTIONS  = 1,
    SFHTTP_GET      = 2,
    SFHTTP_HEAD     = 3,
    SFHTTP_POST     = 4,
    SFHTTP_PUT      = 5,
    SFHTTP_DELETE   = 6,
    SFHTTP_TRACE    = 7,
    SFHTTP_CONNECT  = 8,
} SFLHTTP_method;

typedef struct _SFLSampled_http {
    SFLHTTP_method method;
    uint32_t protocol;       /* 1.1 = 1001 */
    SFLString uri;               /* URI exactly as it came from the client */
    SFLString host;              /* Host value from request header */
    SFLString referer;           /* Referer value from request header */
    SFLString useragent;         /* User-Agent value from request header */
    SFLString xff;               /* X-Forwarded-For from request header */
    SFLString authuser;          /* RFC 1413 identity of user*/
    SFLString mimetype;          /* Mime-Type */
    uint64_t req_bytes;          /* Content-Length of request */
    uint64_t resp_bytes;         /* Content-Length of response */
    uint32_t uS;             /* duration of the operation (microseconds) */
    uint32_t status;         /* HTTP status code */
} SFLSampled_http;

#define SFLHTTP_MAX_URI_LEN 255
#define SFLHTTP_MAX_HOST_LEN 64
#define SFLHTTP_MAX_REFERER_LEN 255
#define SFLHTTP_MAX_USERAGENT_LEN 128
#define SFLHTTP_MAX_XFF_LEN 64
#define SFLHTTP_MAX_AUTHUSER_LEN 32
#define SFLHTTP_MAX_MIMETYPE_LEN 64

enum SFLFlow_type_tag {
    /* enterprise = 0, format = ... */
    SFLFLOW_EX_SOCKET4      = 2100,
    SFLFLOW_EX_SOCKET6      = 2101,
    SFLFLOW_EX_PROXY_SOCKET4 = 2102,
    SFLFLOW_EX_PROXY_SOCKET6 = 2103,
    /* SFLFLOW_MEMCACHE        = 2200, */
    SFLFLOW_HTTP            = 2206,
};

typedef union _SFLFlow_type {
    SFLSampled_http http;
    SFLExtended_socket_ipv4 socket4;
    SFLExtended_socket_ipv6 socket6;
} SFLFlow_type;

typedef struct _SFLFlow_sample_element {
    struct _SFLFlow_sample_element *nxt;
    uint32_t tag;  /* SFLFlow_type_tag */
    uint32_t length;
    SFLFlow_type flowType;
} SFLFlow_sample_element;

enum SFL_sample_tag {
    SFLFLOW_SAMPLE = 1,              /* enterprise = 0 : format = 1 */
    SFLCOUNTERS_SAMPLE = 2,          /* enterprise = 0 : format = 2 */
    SFLFLOW_SAMPLE_EXPANDED = 3,     /* enterprise = 0 : format = 3 */
    SFLCOUNTERS_SAMPLE_EXPANDED = 4  /* enterprise = 0 : format = 4 */
};
  
/* Format of a single flow sample */

typedef struct _SFLFlow_sample {
    /* uint32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
    /* uint32_t length; */
    uint32_t sequence_number;      /* Incremented with each flow sample
                                      generated */
    uint32_t source_id;            /* fsSourceId */
    uint32_t sampling_rate;        /* fsPacketSamplingRate */
    uint32_t sample_pool;          /* Total number of packets that could have been
                                      sampled (i.e. packets skipped by sampling
                                      process + total number of samples) */
    uint32_t drops;                /* Number of times a packet was dropped due to
                                      lack of resources */
    uint32_t input;                /* SNMP ifIndex of input interface.
                                      0 if interface is not known. */
    uint32_t output;               /* SNMP ifIndex of output interface,
                                      0 if interface is not known.
                                      Set most significant bit to indicate
                                      multiple destination interfaces
                                      (i.e. in case of broadcast or multicast)
                                      and set lower order bits to indicate
                                      number of destination interfaces.
                                      Examples:
                                      0x00000002  indicates ifIndex = 2
                                      0x00000000  ifIndex unknown.
                                      0x80000007  indicates a packet sent
                                      to 7 interfaces.
                                      0x80000000  indicates a packet sent to
                                      an unknown number of
                                      interfaces greater than 1.*/
    uint32_t num_elements;
    SFLFlow_sample_element *elements;
} SFLFlow_sample;

/* same thing, but the expanded version (for full 32-bit ifIndex numbers) */

typedef struct _SFLFlow_sample_expanded {
    /* uint32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
    /* uint32_t length; */
    uint32_t sequence_number;      /* Incremented with each flow sample
                                      generated */
    uint32_t ds_class;             /* EXPANDED */
    uint32_t ds_index;             /* EXPANDED */
    uint32_t sampling_rate;        /* fsPacketSamplingRate */
    uint32_t sample_pool;          /* Total number of packets that could have been
                                      sampled (i.e. packets skipped by sampling
                                      process + total number of samples) */
    uint32_t drops;                /* Number of times a packet was dropped due to
                                      lack of resources */
    uint32_t inputFormat;          /* EXPANDED */
    uint32_t input;                /* SNMP ifIndex of input interface.
                                      0 if interface is not known. */
    uint32_t outputFormat;         /* EXPANDED */
    uint32_t output;               /* SNMP ifIndex of output interface,
                                      0 if interface is not known. */
    uint32_t num_elements;
    SFLFlow_sample_element *elements;
} SFLFlow_sample_expanded;

/* Counter types */

typedef struct _SFLHTTP_counters {
    uint32_t method_option_count;
    uint32_t method_get_count;
    uint32_t method_head_count;
    uint32_t method_post_count;
    uint32_t method_put_count;
    uint32_t method_delete_count;
    uint32_t method_trace_count;
    uint32_t method_connect_count;
    uint32_t method_other_count;
    uint32_t status_1XX_count;
    uint32_t status_2XX_count;
    uint32_t status_3XX_count;
    uint32_t status_4XX_count;
    uint32_t status_5XX_count;
    uint32_t status_other_count;
} SFLHTTP_counters;

#define XDRSIZ_SFLHTTP_COUNTERS (15*4)

typedef struct _SFLHost_par_counters {
    uint32_t dsClass;       /* sFlowDataSource class */
    uint32_t dsIndex;       /* sFlowDataSource index */
} SFLHost_par_counters;

/* Counters data */

enum SFLCounters_type_tag {
    /* enterprise = 0, format = ... */
    SFLCOUNTERS_HOST_PAR      = 2002, /* host parent */
    SFLCOUNTERS_HTTP          = 2201, /* http counters */
};

typedef union _SFLCounters_type {
    SFLHost_par_counters host_par;
    SFLHTTP_counters http;
} SFLCounters_type;

typedef struct _SFLCounters_sample_element {
    struct _SFLCounters_sample_element *nxt; /* linked list */
    uint32_t tag; /* SFLCounters_type_tag */
    uint32_t length;
    SFLCounters_type counterBlock;
} SFLCounters_sample_element;

typedef struct _SFLCounters_sample {
    /* uint32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
    /* uint32_t length; */
    uint32_t sequence_number;    /* Incremented with each counters sample
                                    generated by this source_id */
    uint32_t source_id;          /* fsSourceId */
    uint32_t num_elements;
    SFLCounters_sample_element *elements;
} SFLCounters_sample;

/* same thing, but the expanded version, so ds_index can be a full 32 bits */
typedef struct _SFLCounters_sample_expanded {
    /* uint32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
    /* uint32_t length; */
    uint32_t sequence_number;    /* Incremented with each counters sample
                                    generated by this source_id */
    uint32_t ds_class;           /* EXPANDED */
    uint32_t ds_index;           /* EXPANDED */
    uint32_t num_elements;
    SFLCounters_sample_element *elements;
} SFLCounters_sample_expanded;

#define SFLADD_ELEMENT(_sm, _el) do { (_el)->nxt = (_sm)->elements; (_sm)->elements = (_el); } while(0)

/* Format of a sample datagram */

enum SFLDatagram_version {
    SFLDATAGRAM_VERSION2 = 2,
    SFLDATAGRAM_VERSION4 = 4,
    SFLDATAGRAM_VERSION5 = 5
};

typedef struct _SFLSample_datagram_hdr {
    uint32_t datagram_version;      /* (enum SFLDatagram_version) = VERSION5 = 5 */
    SFLAddress agent_address;        /* IP address of sampling agent */
    uint32_t sub_agent_id;          /* Used to distinguishing between datagram
                                       streams from separate agent sub entities
                                       within an device. */
    uint32_t sequence_number;       /* Incremented with each sample datagram
                                       generated */
    uint32_t uptime;                /* Current time (in milliseconds since device
                                       last booted). Should be set as close to
                                       datagram transmission time as possible.*/
    uint32_t num_records;           /* Number of tag-len-val flow/counter records to follow */
} SFLSample_datagram_hdr;

#define SFL_MAX_DATAGRAM_SIZE 1500
#define SFL_MIN_DATAGRAM_SIZE 200
#define SFL_DEFAULT_DATAGRAM_SIZE 1400

#define SFL_DATA_PAD 400

#endif /* SFLOW_H */

#ifndef _NFCT_EXTERN_H_
#define _NFCT_EXTERN_H_

#ifdef __cplusplus
extern "C" {
#endif

enum tcp_state
{
     TCP_CONNTRACK_NONE,
     TCP_CONNTRACK_SYN_SENT,
     TCP_CONNTRACK_SYN_RECV,
     TCP_CONNTRACK_ESTABLISHED,
     TCP_CONNTRACK_FIN_WAIT,
     TCP_CONNTRACK_CLOSE_WAIT,
     TCP_CONNTRACK_LAST_ACK,
     TCP_CONNTRACK_TIME_WAIT,
     TCP_CONNTRACK_CLOSE,
     TCP_CONNTRACK_LISTEN,       /* obsolete */
#define TCP_CONNTRACK_SYN_SENT2     TCP_CONNTRACK_LISTEN
     TCP_CONNTRACK_MAX,
     TCP_CONNTRACK_IGNORE
};

extern const set_attr 	set_attr_array[];
extern const get_attr 	get_attr_array[];
extern const copy_attr 	copy_attr_array[];
extern const filter_attr 	filter_attr_array[];

extern const set_filter_dump_attr	set_filter_dump_attr_array[];

/* for the snprintf infrastructure */
extern const char *const l3proto2str[AF_MAX];
extern const char *const proto2str[IPPROTO_MAX];
extern const char *const states[TCP_CONNTRACK_MAX];

#ifdef __cplusplus
}
#endif

#endif

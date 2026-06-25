#ifndef _NFCT_PROTOTYPES_H_
#define _NFCT_PROTOTYPES_H_

/*
 * conntrack internal prototypes
 */
void __build_tuple(struct nfnlhdr *req, size_t size, const struct __nfct_tuple *t, const int type);
int __snprintf_conntrack(char *buf, unsigned int len, const struct nf_conntrack *ct, unsigned int type, unsigned int msg_output, unsigned int flags, struct nfct_labelmap *);
int __snprintf_address(char *buf, unsigned int len, const struct __nfct_tuple *tuple, const char *src_tag, const char *dst_tag);
int __snprintf_protocol(char *buf, unsigned int len, const struct nf_conntrack *ct);
int __snprintf_proto(char *buf, unsigned int len, const struct __nfct_tuple *tuple);
int __snprintf_conntrack_default(char *buf, unsigned int len, const struct nf_conntrack *ct, const unsigned int msg_type, const unsigned int flags, struct nfct_labelmap *);
int __snprintf_connlabels(char *buf, unsigned int len, struct nfct_labelmap *map, const struct nfct_bitmask *b, const char *fmt);

enum __nfct_addr {
	__ADDR_SRC = 0,
	__ADDR_DST,
};

const char *__proto2str(uint8_t protonum);
const char *__l3proto2str(uint8_t protonum);

int __callback(struct nlmsghdr *nlh, struct nfattr *nfa[], void *data);

int __setobjopt(struct nf_conntrack *ct, unsigned int option);
int __getobjopt(const struct nf_conntrack *ct, unsigned int option);
int __compare(const struct nf_conntrack *ct1, const struct nf_conntrack *ct2, unsigned int flags);
int __cmp_orig(const struct nf_conntrack *ct1, const struct nf_conntrack *ct2, unsigned int flags);
void __copy_fast(struct nf_conntrack *ct1, const struct nf_conntrack *ct);


int nfct_build_tuple(struct nlmsghdr *nlh, const struct __nfct_tuple *t, int type);
int nfct_parse_tuple(const struct nlattr *attr, struct __nfct_tuple *tuple, int dir, uint32_t *set);

/*
 * expectation internal prototypes
 */
int __snprintf_expect_default(char *buf, unsigned int len, const struct nf_expect *exp, unsigned int msg_type, unsigned int flags);

/*
 * connlabel internal prototypes
 */
const char *__labels_get_path(void);
struct nfct_labelmap *__labelmap_new(const char *);
void __labelmap_destroy(struct nfct_labelmap *);

int __labelmap_get_bit(struct nfct_labelmap *map, const char *name);
const char *__labelmap_get_name(struct nfct_labelmap *map, unsigned int bit);

#endif

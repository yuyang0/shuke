//
// Created by Yu Yang on 2017-01-10
//

#ifndef _CDNS_PROTOCOL_H_
#define _CDNS_PROTOCOL_H_ 1

#include <stdint.h>

#define DEFAULT_LABEL_COUNT 32

typedef struct _dname {
    char *name;
    uint8_t nameLen;
    uint8_t offsets[DEFAULT_LABEL_COUNT];
    /*
     * when the label count smaller than DEFAULT_LABEL_COUNT, then this pointer will point to offsets,
     * otherwise it will point to memory allocated in heap.
     */
    uint8_t *label_offset;
    uint8_t label_count;
} dname_t;

#define PROTO_OK     0
#define PROTO_ERR   -1

#define DNS_HDR_SIZE 12

// limit
#define MAX_LABEL_LEN   (63)
#define MAX_DOMAIN_LEN  (255)
#define MAX_UDP_SIZE    (512)

// rfc 2817
#define MAX_TTL (7 * 86400)
// no rfc
#define MIN_TTL (10)

// for A/AAAA/MX/NS records we need support duplicate records.
#define MAX_DUPLICATE_RECORDS 32

//0 is q,1 is r
#define QR_Q (0)
#define QR_R (1)
#define GET_QR(flag) ((flag & 0x8000) / 0x8000)
#define SET_QR_R(flag) (flag |= 0x8000)
#define SET_QR_Q(flag) (flag &= 0x7fff)
#define GET_OPCODE(flag) ((flag & 0x7800) >> 11)
#define GET_AA(flag) ((flag & 0x0400) / 0x0400)
#define SET_AA(flag) (flag |= 0x0400)
#define GET_TC(flag) ((flag & 0x0200) / 0x0200)
#define SET_TC(flag) (flag |= 0x0200)
#define GET_RD(flag) ((flag & 0x0100) / 0x0100)
#define SET_RD(flag) (flag |= 0x0100)
#define SET_RA(flag) (flag |= 0x0080)
#define GET_ERROR(flag) (flag & 0x7)
#define SET_ERROR(flag,errcode) ((flag) = (((flag) & 0xfff0) + errcode))
#define IS_PTR(os) (os >= 0xc000 && os <= 0xcfff)       //in reply msg
#define GET_OFFSET(offset) (offset & 0x3fff)    //the 2 higher bits set to 0
#define SET_OFFSET(offset) (offset |= 0xc000)
#define IS_EDNS0(flag) (flag > 0x4000 && flag < 0x4fff)

enum {
    DNS_CLASS_IN = 1
};

typedef enum dns_rr_type {
    DNS_TYPE_ANY = 255,   /**< any                                */
    DNS_TYPE_A	= 1,    /**< Host address (A) record.		    */
    DNS_TYPE_NS	= 2,    /**< Authoritative name server (NS)	    */
    DNS_TYPE_MD	= 3,    /**< Mail destination (MD) record.	    */
    DNS_TYPE_MF	= 4,    /**< Mail forwarder (MF) record.	    */
    DNS_TYPE_CNAME	= 5,	/**< Canonical name (CNAME) record.	    */
    DNS_TYPE_SOA	= 6,    /**< Marks start of zone authority.	    */
    DNS_TYPE_MB	= 7,    /**< Mailbox domain name (MB).		    */
    DNS_TYPE_MG	= 8,    /**< Mail group member (MG).		    */
    DNS_TYPE_MR	= 9,    /**< Mail rename domain name.		    */
    DNS_TYPE_NULL	= 10,	/**< NULL RR.				    */
    DNS_TYPE_WKS	= 11,	/**< Well known service description	    */
    DNS_TYPE_PTR	= 12,	/**< Domain name pointer.		    */
    DNS_TYPE_HINFO	= 13,	/**< Host information.			    */
    DNS_TYPE_MINFO	= 14,	/**< Mailbox or mail list information.	    */
    DNS_TYPE_MX	= 15,	/**< Mail exchange record.		    */
    DNS_TYPE_TXT	= 16,	/**< Text string.			    */
    DNS_TYPE_RP	= 17,	/**< Responsible person.		    */
    DNS_TYPE_AFSB	= 18,	/**< AFS cell database.			    */
    DNS_TYPE_X25	= 19,	/**< X.25 calling address.		    */
    DNS_TYPE_ISDN	= 20,	/**< ISDN calling address.		    */
    DNS_TYPE_RT	= 21,	/**< Router.				    */
    DNS_TYPE_NSAP	= 22,	/**< NSAP address.			    */
    DNS_TYPE_NSAP_PTR= 23,	/**< NSAP reverse address.		    */
    DNS_TYPE_SIG	= 24,	/**< Signature.				    */
    DNS_TYPE_KEY	= 25,	/**< Key.				    */
    DNS_TYPE_PX	= 26,	/**< X.400 mail mapping.		    */
    DNS_TYPE_GPOS	= 27,	/**< Geographical position (withdrawn)	    */
    DNS_TYPE_AAAA	= 28,	/**< IPv6 address.			    */
    DNS_TYPE_LOC	= 29,	/**< Location.				    */
    DNS_TYPE_NXT	= 30,	/**< Next valid name in the zone.	    */
    DNS_TYPE_EID	= 31,	/**< Endpoint idenfitier.		    */
    DNS_TYPE_NIMLOC	= 32,	/**< Nimrod locator.			    */
    DNS_TYPE_SRV	= 33,	/**< Server selection (SRV) record.	    */
    DNS_TYPE_ATMA	= 34,	/**< DNS ATM address record.		    */
    DNS_TYPE_NAPTR	= 35,	/**< DNS Naming authority pointer record.   */
    DNS_TYPE_KX	= 36,	/**< DNS key exchange record.		    */
    DNS_TYPE_CERT	= 37,	/**< DNS certificate record.		    */
    DNS_TYPE_A6	= 38,	/**< DNS IPv6 address (experimental)	    */
    DNS_TYPE_DNAME	= 39,	/**< DNS non-terminal name redirection rec. */

    DNS_TYPE_OPT	= 41,	/**< DNS options - contains EDNS metadata.  */
    DNS_TYPE_APL	= 42,	/**< DNS Address Prefix List (APL) record.  */
    DNS_TYPE_DS	= 43,	/**< DNS Delegation Signer (DS)		    */
    DNS_TYPE_SSHFP	= 44,	/**< DNS SSH Key Fingerprint		    */
    DNS_TYPE_IPSECKEY= 45,	/**< DNS IPSEC Key.			    */
    DNS_TYPE_RRSIG	= 46,	/**< DNS Resource Record signature.	    */
    DNS_TYPE_NSEC	= 47,	/**< DNS Next Secure Name.		    */
    DNS_TYPE_DNSKEY	= 48	/**< DNSSEC Key.			    */
} dns_rr_type;

typedef enum dns_rcode {
    DNS_RCODE_OK         = 0,    /**< no error     */
    DNS_RCODE_FORMERR    = 1,    /**< Format error.			    */
    DNS_RCODE_SERVFAIL   = 2,    /**< Server failure.		    */
    DNS_RCODE_NXDOMAIN   = 3,    /**< Name Error.			    */
    DNS_RCODE_NOTIMPL    = 4,    /**< Not Implemented.		    */
    DNS_RCODE_REFUSED    = 5,    /**< Refused.			    */
    DNS_RCODE_YXDOMAIN   = 6,    /**< The name exists.		    */
    DNS_RCODE_YXRRSET    = 7,    /**< The RRset (name, type) exists.	    */
    DNS_RCODE_NXRRSET    = 8,    /**< The RRset (name, type) doesn't exist*/
    DNS_RCODE_NOTAUTH    = 9,    /**< Not authorized.		    */
    DNS_RCODE_NOTZONE    = 10    /**< The zone specified is not a zone.  */
} dns_rcode;

//we always set opcode to 0 at current version.
typedef enum dns_opcode {
    DNS_OPCODE_QUERY    = 0,    /**< Query, most common used */
    DNS_OPCODE_IQUERY   = 1,    /**< Inverse Query, OBSOLETE */
    DNS_OPCODE_STATUS   = 2,    /**< Status */
    DNS_OPCODE_NOTIFY   = 4,    /**< Notify */
    DNS_OPCODE_UPDATE   = 5     /**< Update */
} dns_opcode;

/*
 *
 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                      ID                       |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    QDCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    ANCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    NSCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 |                    ARCOUNT                    |
 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

 *
 */
struct dnsHeader_s {
    uint16_t xid;
    uint16_t flag;
    uint16_t nQd;
    uint16_t nAnRR;
    uint16_t nNsRR;   // only contains NS records
    uint16_t nArRR;
}__attribute__((__packed__));

typedef struct dnsHeader_s dnsHeader_t;

/*
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /          QNAME(var length)                    /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QTYPE                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QCLASS                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
typedef struct dnsQuestion_s {
    char *name;
    uint16_t qType;
    uint16_t qClass;

    size_t nameLen;
    char *humanName;
} dnsQuestion_t;

/*
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /           QNAME(var length)                   /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QTYPE                     |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                     QCLASS                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                                               |
  /                 TTL(32bits)                   /
  /                                               /
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                 RData Length                  |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  |                 RData(var)                    |
  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
typedef struct dnsRR_s {
    char *name;
    uint16_t rrType;
    uint16_t rrClass;
    uint32_t ttl;
    uint16_t rdlength;
    char rdata[];
}dnsRR_t;

typedef struct dnsPacket_s {
    dnsHeader_t *hdr;
    dnsQuestion_t **qd;
    dnsRR_t **ans;
    dnsRR_t **ns;
    dnsRR_t **ar;
}dnsPacket_t;

//
// rdata definition
//

typedef struct {
    uint16_t preference;
    char name[MAX_DOMAIN_LEN];
}MXRecordVal;

typedef struct {
    char *mname;   // primary name server
    char *rname;   // administrator's email address
    uint32_t sn;   // serial number, must increment when zone updated, we simple use timestamp
    // when the slave will try to refresh zone from the master,
    // RFC 1912 recommends 1200 to 43200
    int32_t refresh;
    // time between the retries when slave failed to contact to master.
    // typical values would be 180(3 minutes) to 900(15 minutes) or higher
    int32_t retry;
    // indicates when the zone is no longer authoritative. used by slave only.
    // slaves stop responding authoritatively to queries for the zone
    // when this time has expired and no contact has been made with the master.
    //  RFC 1912 recommends 1209600 to 2419200 seconds (2-4 weeks) to allow for major outages of the zone master
    int32_t expiry;
    int32_t minimum;
} SOARecordVal;

// don't do name compression for target field when return to client
// RFC 2782 recommends to place address records(A, AAAA) of target at the additional section
typedef struct {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    char *target;    // multiple
}SRVRecord;

bool isSupportDnsType(uint16_t type);
int checkLenLabel(char *name, size_t max);
char *abs2relative(char *name, char *origin);
int getNumLabels(char *name);
size_t domainlen(char *len_label);

int strToDNSType(const char *ss);
char *DNSTypeToStr(int ty);

int parseDNSHeader(char *buf, size_t size, uint16_t *xid, uint16_t *flag,
                   uint16_t *nQd, uint16_t *nAn, uint16_t *nNs, uint16_t *nAr);
int dumpDNSHeader(char *buf, size_t size, uint16_t xid, uint16_t flag,
                  uint16_t nQd, uint16_t nAn, uint16_t nNs, uint16_t nAr);

static inline int dnsHeader_load(char *buf, size_t size, dnsHeader_t *hdr) {
    return parseDNSHeader(buf, size, &(hdr->xid), &(hdr->flag), &(hdr->nQd),
                          &(hdr->nAnRR), &(hdr->nNsRR), &(hdr->nArRR));
}
static inline int dnsHeader_dump(dnsHeader_t *hdr, char *buf, size_t size) {
    return dumpDNSHeader(buf, size, hdr->xid, hdr->flag, hdr->nQd, hdr->nAnRR, hdr->nNsRR, hdr->nArRR);
}

int parseDnsQuestion(char *buf, size_t size, char **name, uint16_t *qType, uint16_t *qClass);
int dumpDnsQuestion(char *buf, size_t size, char *name, uint16_t qType, uint16_t qClass);
static inline
int dnsQuestion_load(char *buf, size_t size, dnsQuestion_t *q) {
    return parseDnsQuestion(buf, size, &(q->name), &(q->qType), &(q->qClass));
}

static inline
int dnsQuestion_dump(dnsQuestion_t *q, char *buf, size_t size) {
    return dumpDnsQuestion(buf, size, q->name, q->qType, q->qClass);
}

int parseDnsRRInfo(char *buf, size_t sz, char *name, uint16_t *type, uint16_t *cls,
                   uint32_t *ttl, uint16_t *rdlength, void *rdata);
int dumpDnsRRInfo(char *buf, size_t sz, char *name, uint16_t type,
                  uint16_t cls, uint32_t ttl, uint16_t rdlength, void *rdata);
static inline
int dnsRR_dump(dnsRR_t *rr, char *buf, size_t size) {
    return dumpDnsRRInfo(buf, size, rr->name, rr->rrType,
                         rr->rrClass, rr->ttl, rr->rdlength, rr->rdata);
}

static inline
int dnsRR_load(char *buf, size_t size, dnsRR_t *rr) {
    return parseDnsRRInfo(buf, size, rr->name, &(rr->rrType), &(rr->rrClass),
                          &(rr->ttl), &(rr->rdlength), rr->rdata);
}

int parseDname(char *name, size_t max, dname_t *dname);
void resetDname(dname_t *dname);

#if defined(CDNS_TEST)
int dnsTest(int argc, char *argv[]);
#endif

#endif /* _DNS_H_ */

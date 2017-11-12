//
// Created by yangyu on 11/12/17.
//

#ifndef SHUKE_EDNS_H
#define SHUKE_EDNS_H

#define DNSSEC_OK_MASK  0x8000U         /* DO bit mask */

/*
 * see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
 */
#define OPT_NSID_CODE  3U
#define OPT_DAU_CODE   5U
#define OPT_DHU_CODE   6U
#define OPT_N3U_CODE   7U
#define OPT_CLIENT_SUBNET_CODE 8U
#define OPT_EXPIRE_CODE   9U
#define OPT_COOKIE_CODE   10U
#define OPT_TCP_KEEPALIVE_CODE 11U
#define OPT_PADDING_CODE       12U
#define OPT_CHAIN_CODE         13U

/*
       +------------+--------------+------------------------------+
       | Field Name | Field Type   | Description                  |
       +------------+--------------+------------------------------+
       | NAME       | domain name  | MUST be 0 (root domain)      |
       | TYPE       | u_int16_t    | OPT (41)                     |
       | CLASS      | u_int16_t    | requestor's UDP payload size |
       | TTL        | u_int32_t    | extended RCODE and flags     |
       | RDLEN      | u_int16_t    | length of all RDATA          |
       | RDATA      | octet stream | {attribute,value} pairs      |
       +------------+--------------+------------------------------+

    TTL:
                   +0 (MSB)                            +1 (LSB)
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    0: |         EXTENDED-RCODE        |            VERSION            |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    2: | DO|                           Z                               |
       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 */
typedef struct {
    uint16_t payload_size;
    uint8_t rcode;
    uint8_t version;
    uint16_t flags;
    uint16_t rdlength;
    char *rdata;
} edns_t;

int ednsParse(char *buf, size_t size, edns_t *edns);
int ednsDump(char *buf, int size, edns_t *edns);
#endif //SHUKE_EDNS_H

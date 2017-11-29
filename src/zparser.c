//
// Created by yangyu on 17-2-16.
//
#include "fmacros.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>

#include "str.h"
#include "endianconv.h"
#include "dnspacket.h"
#include "zparser.h"
#include "log.h"
#include "utils.h"
#include "zmalloc.h"

DEF_LOG_MODULE(RTE_LOGTYPE_USER1, "ZPARSER");

#define RECORD_SIZE 8192

static bool isttl(const char *ss);
static bool isclass(const char *ss);
static long parsetime(char *ss);


static inline char *RRParserNextToken(RRParser *psr) {
    if (psr->start_idx < psr->ntokens) return psr->tokens[psr->start_idx++];
    else return NULL;
}

static inline int RRParserRemainTokens(RRParser *psr) {
    return psr->ntokens - psr->start_idx;
}

RRParser *RRParserCreate(char *name, uint32_t ttl, char *dotOrigin) {
    RRParser *psr = zcalloc(sizeof(*psr));
    psr->tokens = psr->data;
    psr->ntokens = 64;
    psr->err = PARSER_OK;

    if (name) strncpy(psr->name, name, MAX_DOMAIN_LEN);
    if (dotOrigin) {
        if (!isAbsDotDomain(dotOrigin)) {
            zfree(psr);
            return NULL;
        }
        strncpy(psr->dotOrigin, dotOrigin, MAX_DOMAIN_LEN);
    }
    psr->ttl = ttl;

    return psr;
}

void RRParserDestroy(RRParser *psr) {
    if (psr == NULL) return;
    if (psr->tokens != psr->data) zfree(psr->tokens);
    zfree(psr);
}

void RRParserReset(RRParser *psr) {
    if (psr->tokens != psr->data) zfree(psr->tokens);
    psr->err = PARSER_OK;
    psr->errstr[0] = 0;
    psr->tokens = psr->data;
    psr->ntokens = 64;
    psr->start_idx = 0;
}

int RRParserSetDotOrigin(RRParser *psr, char *dotOrigin) {
    if (!isAbsDotDomain(dotOrigin)) return ERR_CODE;
    strncpy(psr->dotOrigin, dotOrigin, MAX_DOMAIN_LEN);
    return OK_CODE;
}

static int RRParserTokenize(RRParser *psr, char *s) {
    char *tokens[4096];
    int ntokens = 4096;
    int maxTokens = (int)(sizeof(psr->tokens)/sizeof(char*));
    if (tokenize(s, tokens, &ntokens, " \t") < 0) {
        LOG_ERR("parser error");
        return -1;
    }
    if (ntokens > maxTokens) {
        psr->tokens = zmemdup(tokens, sizeof(char *)*ntokens);
    } else {
        rte_memcpy(psr->tokens, tokens, sizeof(char*) *ntokens);
    }
    psr->ntokens = ntokens;
    return 0;
}

int RRParserParseTextRdata(RRParser *psr, RRSet **rs, zone *z) {
    int err = OK_CODE;
    uint16_t type = psr->type;
    char *tok;

    char buf[4096];
    char *ptr = buf;
    uint16_t rdlength = 0;
    ptr += 2;

    size_t nameLen;
    int remain = RRParserRemainTokens(psr);

    switch (type) {
    case DNS_TYPE_A:
        tok = RRParserNextToken(psr);
        if (tok == NULL) {
            snprintf(psr->errstr, ERR_STR_LEN, "A record needs a ipv4 address");
            goto error;
        }
        char ipv4[4];
        if (str2ipv4(tok, ipv4) == false) {
            snprintf(psr->errstr, ERR_STR_LEN, "%s is an invalid ipv4 address.", tok);
            goto error;
        }
        memcpy(ptr, ipv4, 4);
        ptr += 4;
        break;
    case DNS_TYPE_AAAA:
        tok = RRParserNextToken(psr);
        if (tok == NULL) {
            snprintf(psr->errstr, ERR_STR_LEN, "AAAA record needs a ipv6 address");
            goto error;
        }
        char ipv6[16];
        if (str2ipv6(tok, ipv6) == false) {
            snprintf(psr->errstr, ERR_STR_LEN, "%s is an invalid ipv6 address.", tok);
            goto error;
        }
        memcpy(ptr, ipv6, 16);
        ptr += 16;
        break;
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
        tok = RRParserNextToken(psr);
        if (tok == NULL) {
            snprintf(psr->errstr, ERR_STR_LEN, "need a domain name.");
            goto error;
        }
        dot2lenlabel(tok, NULL);
        if (checkLenLabel(tok, 0) == ERR_CODE) {
            snprintf(psr->errstr, ERR_STR_LEN, "%s is an invalid domain name", tok);
            goto error;
        }
        nameLen = strlen(tok) + 1;
        memcpy(ptr, tok, nameLen);
        ptr += nameLen;
        break;
    case DNS_TYPE_MX:
        if (remain != 2) {
            snprintf(psr->errstr, ERR_STR_LEN, "MX record needs 2 tokens, but got %d.", remain);
            goto error;
        }
        tok = RRParserNextToken(psr);
        int pref = atoi(tok);
        if (pref > 0xffff) {
            snprintf(psr->errstr, ERR_STR_LEN, "preference of MX record is too big(%d)", pref);
            goto error;
        }
        dump16be((uint16_t)pref, ptr);
        ptr+=2;
        tok = RRParserNextToken(psr);
        if (tok == NULL) {
            snprintf(psr->errstr, ERR_STR_LEN, "no name for MX Record");
            goto error;
        }
        dot2lenlabel(tok, NULL);
        if (checkLenLabel(tok, 0) == ERR_CODE) {
            snprintf(psr->errstr, ERR_STR_LEN, "%s is an invalid domain name.", tok);
            goto error;
        }
        nameLen = strlen(tok) + 1;
        memcpy(ptr, tok, nameLen);
        ptr += nameLen;
        break;
    case DNS_TYPE_TXT:
        if (remain < 1) {
            snprintf(psr->errstr, ERR_STR_LEN, "TXT records should at least has 1 token.");
            goto error;
        }
        for (; ; ) {
            tok = RRParserNextToken(psr);
            if (tok == NULL) break;
            tok = strip(tok, "\"");
            size_t txtLen = strlen(tok);
            if (txtLen > 255) {
                snprintf(psr->errstr, ERR_STR_LEN, "txt string is too long %zu", txtLen);
                goto error;
            }
            if (ptr+txtLen+1 - buf >= (int)sizeof(buf)) {
                snprintf(psr->errstr, ERR_STR_LEN, "TXT records is too long");
                goto error;
            }
            *ptr = (uint8_t)txtLen;
            ptr++;
            memcpy(ptr, tok, txtLen);
            ptr += txtLen;
        }
        break;
    case DNS_TYPE_SOA:
        if (remain != 7) {
            snprintf(psr->errstr, ERR_STR_LEN, "SOA record needs 7 tokens, but gives %d field", remain);
            return ERR_CODE;
        }
        tok = RRParserNextToken(psr);
        dot2lenlabel(tok, NULL);
        nameLen = strlen(tok) + 1;
        memcpy(ptr, tok, nameLen);
        ptr += nameLen;

        tok = RRParserNextToken(psr);
        dot2lenlabel(tok, NULL);
        nameLen = strlen(tok) + 1;
        memcpy(ptr, tok, nameLen);
        ptr += nameLen;

        tok = RRParserNextToken(psr);
        uint32_t sn = (uint32_t)strtoul(tok, NULL, 10);
        z->sn = sn;
        dump32be(sn, ptr);
        ptr += 4;

        tok = RRParserNextToken(psr);
        uint32_t refresh = (uint32_t)parsetime(tok);
        z->refresh = refresh;
        dump32be(refresh, ptr);
        ptr += 4;

        tok = RRParserNextToken(psr);
        uint32_t retry = (uint32_t)parsetime(tok);
        z->retry = retry;
        dump32be(retry, ptr);
        ptr += 4;

        tok = RRParserNextToken(psr);
        uint32_t expiry = (uint32_t)parsetime(tok);
        z->expiry = expiry;
        dump32be(expiry, ptr);
        ptr += 4;

        tok = RRParserNextToken(psr);
        uint32_t nx = (uint32_t)parsetime(tok);
        z->nx = nx;
        dump32be(nx, ptr);
        ptr += 4;
        break;
    case DNS_TYPE_SRV:
        if (remain != 4) {
            snprintf(psr->errstr, ERR_STR_LEN, "SRV record needs 4 field, but gives %d field", remain);
            goto error;
        }
        tok = RRParserNextToken(psr);
        int priority = atoi(tok);
        if (priority < 0 || priority > 65535) {
            snprintf(psr->errstr, ERR_STR_LEN, "invalid priority for SRV record");
            goto error;
        }

        tok = RRParserNextToken(psr);
        int weight = atoi(tok);
        if (weight < 0 || weight > 65535) {
            snprintf(psr->errstr, ERR_STR_LEN, "invalid weight for SRV record");
            goto error;
        }

        tok = RRParserNextToken(psr);
        int port = atoi(tok);
        if (port < 0 || port > 65535) {
            snprintf(psr->errstr, ERR_STR_LEN, "invalid port for SRV record.");
            goto error;
        }
        dump16be((uint16_t)priority, ptr);
        ptr += 2;
        dump16be((uint16_t)weight, ptr);
        ptr += 2;
        dump16be((uint16_t)port, ptr);
        ptr += 2;

        tok = RRParserNextToken(psr);
        size_t targetLen = strlen(tok)+1;
        dot2lenlabel(tok, NULL);
        memcpy(ptr, tok, targetLen);
        ptr += targetLen;
        break;
    case DNS_TYPE_PTR:
        break;
    default:
        snprintf(psr->errstr, ERR_STR_LEN, "unsupported dns record type(%d)", type);
        goto error;
    }
    rdlength = (uint16_t )(ptr-buf - 2);
    dump16be(rdlength, buf);
    *rs = RRSetCat(*rs, buf, ptr-buf);

    goto ok;
error:
    err = ERR_CODE;
    psr->err = PARSER_ERR;
ok:
    return err;
}

int RRParserDoParse(RRParser *psr, zone *z, bool check_top_soa) {
    RRSet *rs = NULL;
    int err = OK_CODE;
    uint16_t type = psr->type;
    char *domain = psr->name;
    if (type == DNS_TYPE_SOA) {
        if (z->soa != NULL) {
            snprintf(psr->errstr, ERR_STR_LEN, "syntax Error: Duplicate SOA record.");
            goto error;
        }
        if (strcmp(domain, "@") != 0) {
            snprintf(psr->errstr, ERR_STR_LEN, "syntax Error: domain name for SOA record is invalid");
            goto error;
        }
    }
    // we must ensure only one SOA record stays at top of zone file.
    if (check_top_soa) {
        if (type != DNS_TYPE_SOA && z->soa == NULL) {
            snprintf(psr->errstr, ERR_STR_LEN, "syntax Error: the first record must be SOA record");
            goto error;
        }
    }

    rs = zoneFetchTypeVal(z, domain, type);
    if (rs == NULL) rs = RRSetCreate(type, z->socket_id);
    else rs = RRSetDup(rs, z->socket_id);

    if (psr->ttl > rs->ttl) {
        rs->ttl = psr->ttl;
    }
    // read rdata
    if (RRParserParseTextRdata(psr, &rs, z) == ERR_CODE) {
        goto error;
    }

    if (type == DNS_TYPE_NS && strcmp(domain, "@") == 0) {
        z->ns = rs;
    }
    if (type == DNS_TYPE_SOA) {
        z->soa = rs;
    }
    zoneReplaceTypeVal(z, domain, rs);
    goto ok;

error:
    err = ERR_CODE;
    psr->err = PARSER_ERR;
    RRSetDestroy(rs);
ok:
    return err;
}
/*!
 * parse all text RR fields, including owner name, ttl, class, type, rdata.
 * the parsed data will be stored in zone object.
 *
 * @param psr : the RRParser object.
 * @param ss : the text string of the RR.
 * @param name : the owner name. there are two situations:
 *              1. name is NULL then the ss should start with a owner name or a space.
 *                 this situation is mainly for RR stored in text file.
 *              2. name is not NULL, then ss should ignore owner name and only contain ttl, class(optional), type and rdata.
 *                 this situation is mainly for RR stored in databases(redis, mongodb, etc).
 * @param z : the zone object this RR belongs to.
 * @return OK_CODE if everything is ok otherwise return ERR_CODE.
 */
int RRParserFeed(RRParser *psr, char *ss, char *name, zone *z) {
    bool no_type = true;
    bool check_soa_top = true;
    char *tok;
    int err = OK_CODE;
    RRParserReset(psr);
    if (RRParserTokenize(psr, ss) < 0) {
        goto error;
    }
    if (name != NULL) {
        check_soa_top = false;
        strncpy(psr->name, name, MAX_DOMAIN_LEN);
        if (abs2lenRelative(psr->name, psr->dotOrigin) == ERR_CODE) {
            snprintf(psr->errstr, ERR_STR_LEN, "syntax error: invalid domain name(%s), dotOrigin(%s)", name, psr->dotOrigin);
            goto error;
        }
    } else {
        if (*ss != ' ') {
            strncpy(psr->name, psr->tokens[0], MAX_DOMAIN_LEN);
            if (abs2lenRelative(psr->name, psr->dotOrigin) == ERR_CODE) {
                // LOG_DEBUG("%s %s", psr->tokens[0], psr->dotOrigin);
                snprintf(psr->errstr, ERR_STR_LEN, "%s is not a valid domain name.", psr->tokens[0]);
                goto error;
            }
            psr->start_idx = 1;
        }
    }
    for (int i = 0; i < 3; ++i) {
        tok = RRParserNextToken(psr);
        if (tok == NULL) {
            snprintf(psr->errstr, ERR_STR_LEN, "no field for ttl, class and type");
            goto error;
        }
        if (isttl(tok)) {
            psr->ttl = (uint32_t)atoi(tok);
            if (psr->ttl > MAX_TTL) psr->ttl = MAX_TTL;
        } else if (isclass(tok)) {
            continue;
        } else {    // a type?
            int ret = strToDNSType(tok);
            if (ret == ERR_CODE) {
                snprintf(psr->errstr, ERR_STR_LEN, "%s is not a ttl, class or type", tok);
                goto error;
            }
            psr->type = (uint16_t)ret;
            no_type = false;
            break;
        }
    }
    if (no_type) {
        snprintf(psr->errstr, ERR_STR_LEN, "no type field");
        goto error;
    }
    if (RRParserDoParse(psr, z, check_soa_top) == ERR_CODE) goto error;
    goto ok;
error:
    psr->err = PARSER_ERR;
    err = ERR_CODE;
ok:
    return err;
}

int RRParserFeedRdata(RRParser *psr, char *rdata, char *name, uint32_t ttl, char *type, zone *z) {
    bool check_soa_top = false;
    int err = OK_CODE;
    RRParserReset(psr);
    if (RRParserTokenize(psr, rdata) < 0) {
        goto error;
    }
    strncpy(psr->name, name, MAX_DOMAIN_LEN);
    if (abs2lenRelative(psr->name, psr->dotOrigin) == ERR_CODE) {
        snprintf(psr->errstr, ERR_STR_LEN, "syntax error: invalid domain name(%s), dotOrigin(%s)", name, psr->dotOrigin);
        goto error;
    }
    psr->ttl = ttl;
    int ret = strToDNSType(type);
    if (ret == ERR_CODE) {
        snprintf(psr->errstr, ERR_STR_LEN, "%s is not a type", type);
        goto error;
    }
    psr->type = (uint16_t)ret;

    if (RRParserDoParse(psr, z, check_soa_top) == ERR_CODE) goto error;
    goto ok;
error:
    psr->err = PARSER_ERR;
    err = ERR_CODE;
ok:
    return err;
}

/*!
 * extract sn field from string.
 * @param errstr : used to store error message
 * @param soa : the string contains SOA record(full record or just rdata)
 * @param sn : used to store the result sn
 * @return
 */
int parseSOASn(char *errstr, char *soa, unsigned long *sn) {
    char data[BUFSIZE];
    char *tokens[10];
    int ntokens = 10;
    char *endptr;

    snprintf(data, BUFSIZE, "%s", soa);
    char *ptr = strcasestr(data, " SOA ");
    if (ptr == NULL) {
        ptr = data;
        // snprintf(errstr, ERR_STR_LEN, "not a SOA record. %s.", soa);
        // return PARSER_ERR;
    } else {
        ptr += strlen(" SOA ");
    }
    tokenize(ptr, tokens, &ntokens, " \t");
    if (ntokens != 7) {
        snprintf(errstr, ERR_STR_LEN, "too many tokens in SOA record %s.", soa);
        return PARSER_ERR;
    }

    *sn = strtoul(tokens[2], &endptr, 10);
    if (*endptr != '\0') {
        snprintf(errstr, ERR_STR_LEN, "invalid sn in '%s' please check the data store.", soa);
        return PARSER_ERR;
    }
    return PARSER_OK;
}

/* private functions */
static bool needSkip(char *line) {
    while (*line == ' ' || *line=='\t' || *line=='\v')
        line++;
    return (*line == ';' || *line == '\n' || *line == 0);
}

static bool isttl(const char *ss) {
    return isdigit(ss[0]) != 0;
}

static bool isclass(const char *ss) {
    return strcasecmp(ss, "IN") == 0;
}

static long parsetime(char *ss) {
    long ret = 0;

    char *start = ss;
    char *end;
    while(1) {
        long part = strtol(start, &end, 10);
        if (*end == 0) {
            ret += part;
            break;
        }
        switch (*end) {
        case 'w':
        case 'W':
            part *= (7*24*3600);
            break;
        case 'd':
        case 'D':
            part *= (24*3600);
            break;
        case 'h':
        case 'H':
            part *= 3600;
            break;
        case 'm':
        case 'M':
            part *= 60;
        case 's':
        case 'S':
            break;
        default:
            return ERR_CODE;
        }
        ret += part;
        start = end + 1;
    }
    return ret;
}

// find position of character in string, it will skip escape and literal string(surrounded by ")
static char *findChar(char *start, char c) {
    bool literal = false;
    for (; *start != 0; ++start) {
        if (*start == '\\') {
            if (*++start == 0) break;
            continue;
        }
        if (*start == '"') {
            if (literal) literal = false;
            else literal = true;
            continue;
        }
        if (literal) continue;
        if (*start == c) return start;
    }
    if (literal) {  // unbalance double quotes
        LOG_WARN("unbalanced double quotes");
    }
    return NULL;
}

// replace all invisible character to space.
// ignore escape and literal string
static void replaceInvisibleChar(char *start) {
    bool literal = false;
    for (; *start != 0; ++start) {
        if (*start == '\\') {
            if (*++start == 0) break;
            continue;
        }
        if (*start == '"') {
            if (literal) literal = false;
            else literal = true;
            continue;
        }
        if (literal) continue;
        if (*start == '\v' || *start == '\t' || *start == '\n')
            *start = ' ';
    }
    if (literal) {  // unbalance double quotes
        LOG_WARN("unbalanced double quotes");
    }
}

// find the end position of a line. it will strip the comment and space at the end of line.
static char *findLineEnd(char *start) {
    char *cmt = findChar(start, ';');
    if (cmt == NULL) cmt = start + strlen(start);
    *cmt = 0;
    if (*(cmt - 1) == '\n') *--cmt = 0;
    while (*(cmt - 1) == ' ') *--cmt = 0;
    return cmt;
}

static int readFullRecord(char *errstr, char **ssp, char *buf, size_t sz, int *line_idx) {
    while(1) {
        if (sgets(buf, (int)sz, ssp) == NULL) {
            return EOF_CODE;
        }
        if (needSkip(buf)) {
            (*line_idx)++;
            continue;
        }
        size_t remain;
        char *line_end = findLineEnd(buf);

        char *ptr = line_end;
        char *open, *close;

        open = findChar(buf, '(');
        if (open != NULL) {
            *open = ' ';
            close = findChar(buf, ')');

            if (close != NULL) {
                *close = ' ';
            } else {
                while (close == NULL) {
                    *ptr++ = ' ';
                    remain = sz - (ptr - buf);
                    if (remain <= 0) {
                        snprintf(errstr, ERR_STR_LEN, "Syntax error(line %d): the record is too long(more than %d)", *line_idx, RECORD_SIZE);
                        return ERR_CODE;
                    }
                    if (sgets(ptr, remain, ssp) == NULL) {
                        snprintf(errstr, ERR_STR_LEN, "syntax error(line: %d): no close parenthesis.", *line_idx);
                        return ERR_CODE;
                    }
                    (*line_idx)++;
                    if (needSkip(ptr)) continue;

                    line_end = findLineEnd(ptr);
                    close = findChar(ptr, ')');

                    ptr = line_end;
                }
                *close = ' ';
            }
        }
        break;
    }
    (*line_idx)++;
    // replace all invisible character to space.
    replaceInvisibleChar(buf);
    // LOG_DEBUG("read full record: %s", buf);
    return OK_CODE;
}

// convert absolute domain name(<label dot> format) to relative domain name
// the relative domain will be in <len label> format
int abs2lenRelative(char domain[], char *dotOrigin) {
    if (strcmp(domain, "@") == 0) return OK_CODE;

    if (isAbsDotDomain(domain) == true) {
        if (endscasewith(domain, dotOrigin) == false) {
            return ERR_CODE;
        }
        size_t remain = strlen(domain) - strlen(dotOrigin);
        domain[remain] = 0;
        if (remain == 0) {
            strcpy(domain, "@");
        } else {
            dot2lenlabel(domain, NULL);
            if (checkLenLabel(domain, 0) == ERR_CODE) {
                return ERR_CODE;
            }
        }
    } else {
        // label should endswith dot
        strncat(domain, ".", 2);
        dot2lenlabel(domain, NULL);
        if (checkLenLabel(domain, 0) == ERR_CODE) {
            return ERR_CODE;
        }
    }
    return OK_CODE;
}

// parse the directives(starts with $) at the top of zone files.
static int readDirectives(char *errstr, char **ssp, char *origin, uint32_t *ttl, int *line_idx) {
    char rbuf[RECORD_SIZE];
    char *tokens[8];
    int ntokens = 8;
    int prev_idx = *line_idx;
    char *ss = *ssp;
    int err;
    for (; ((err= readFullRecord(NULL, ssp, rbuf, RECORD_SIZE, line_idx)) == OK_CODE); ss = *ssp, prev_idx=*line_idx) {
        // unget this line
        if (rbuf[0] != '$') {
            *ssp = ss;
            *line_idx = prev_idx;
            return OK_CODE;
        }
        tokenize(rbuf, tokens, &ntokens, " \t");

        if (strcasecmp(tokens[0], "$ORIGIN") == 0) {
            if (ntokens < 2) {
                snprintf(errstr, ERR_STR_LEN, "Syntax error(line %d): no argument for $ORIGIN", *line_idx);
                return ERR_CODE;
            }
            strncpy(origin, tokens[1], 255);
            continue;
        } else if (strcasecmp(tokens[0], "$TTL") == 0) {
            if (ntokens < 2) {
                snprintf(errstr, ERR_STR_LEN, "Syntax error(line %d): no argument for $TTL", *line_idx);
                return ERR_CODE;
            }
            *ttl = (uint32_t) parsetime(tokens[1]);
            continue;
        } else {
            snprintf(errstr, ERR_STR_LEN, "Syntax error(line %d): invalid or unsupported directive %s.", *line_idx, tokens[0]);
            return ERR_CODE;
        }
    }
    if (err != EOF_CODE) err = OK_CODE;
    return err;
}

int loadZoneFromStr(char *errstr, int socket_id, char *zbuf, zone **zpp) {
    char dotOrigin[MAX_DOMAIN_LEN+2] = {0};
    char rbuf[RECORD_SIZE];
    uint32_t default_ttl = 1800;
    zone *z = NULL;
    int err;
    int line_idx = 0;
    RRParser *psr = NULL;
    char *ss = zbuf;

    if(readDirectives(errstr, &ss, dotOrigin, &default_ttl, &line_idx) == ERR_CODE) {
        goto error;
    }
    LOG_DEBUG("origin: %s, default ttl: %d", dotOrigin, default_ttl);
    if (strlen(dotOrigin) == 0) {
        snprintf(errstr, ERR_STR_LEN, "line %d syntax error: no origin", line_idx);
        goto error;
    }
    psr = RRParserCreate("@", default_ttl, dotOrigin);
    z = zoneCreate(dotOrigin, socket_id);
    z->default_ttl = default_ttl;

    while ((err= readFullRecord(errstr, &ss, rbuf, RECORD_SIZE, &line_idx)) == OK_CODE) {
        LOG_DEBUG("line: %s", rbuf);
        if (RRParserFeed(psr, rbuf, NULL, z) == ERR_CODE) {
            snprintf(errstr, ERR_STR_LEN, "Line %d %s", line_idx, psr->errstr);
            goto error;
        }
    }
    if (err != EOF_CODE) goto error;

    *zpp = z;
    goto ok;

error:
    err = ERR_CODE;
    zoneDestroy(z);
ok:
    RRParserDestroy(psr);
    return err;
}

int loadZoneFromFile(int socket_id, const char *fname, zone **zpp) {
    char *zbuf;
    int err;
    char errstr[ERR_STR_LEN];

    zbuf = zreadFile(fname);
    if (zbuf == NULL) {
        LOG_ERROR("Can't read zone file %s.", fname);
        return ERR_CODE;
    }
    err = loadZoneFromStr(errstr, socket_id, zbuf, zpp);
    zfree(zbuf);
    return err;
}

#if defined(SK_TEST)
#include <stdio.h>
#include <stdlib.h>
#include "sds.h"
#include "testhelp.h"

#define UNUSED(x) (void)(x)

int zoneParserTest(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "need conf file\n");
        exit(1);
    }
    test_cond("parse ttl 1", parsetime("2w3d3M2") == 17*(24*3600)+180 + 2);
    test_cond("parse ttl 2", parsetime("2002112") == 2002112);
    {
        char dot_origin[] = "google.com.";
        char domain[255] = "www.google.com.";
        abs2lenRelative(domain, dot_origin);
        test_cond("abs2lenRelative 1", strcmp(domain, "\3www") == 0);

        strcpy(domain, "aa.bb.google.com.");
        abs2lenRelative(domain, dot_origin);
        test_cond("abs2lenRelative 2", strcmp(domain, "\2aa\2bb") == 0);

        strcpy(domain, "google.com.");
        abs2lenRelative(domain, dot_origin);
        test_cond("abs2lenRelative 3", strcmp(domain, "@") == 0);
    }
    char *ss = readFile(argv[3]);
    char buf[1000];
    int idx = 0;
    int err;
    char errstr[ERR_STR_LEN];
    fprintf(stderr, "\n");
    while ((err=readFullRecord(errstr, &ss, buf, 1000, &idx)) == OK_CODE) {
        fprintf(stderr, "l%d:%s \n", idx, buf);
    }
    fprintf(stderr, "\n");

    zone *z;
    loadZoneFromFile(SOCKET_ID_HEAP, argv[3], &z);
    sds s = zoneToStr(z);
    printf("%s\n", s);
    sdsfree(s);

    // {
    //     zone *z = zoneDictFetchVal(zd, "\7example\3com");
    //     sds s = zoneToStr(z);
    //     LOG_DEBUG("%s", s);
    //     sdsfree(s);
    //     zoneDecRef(z);
    // }
    test_report();
    return 0;
}
#endif

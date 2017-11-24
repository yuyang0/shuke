//
// Created by yangyu on 17-11-24.
//

#ifndef SHUKE_ZPARSER_H
#define SHUKE_ZPARSER_H

#include <stdint.h>

#include "defines.h"
#include "zone.h"

#define PARSER_OK    0
#define PARSER_ERR  (-1)

typedef struct {
    int err;
    char errstr[ERR_STR_LEN];

    char *data[64];
    char **tokens;
    int ntokens;
    int start_idx;

    uint16_t type;

    uint32_t ttl;
    // the relative name (len label format)
    char name[MAX_DOMAIN_LEN+2];
    // the dot origin this RR belongs to.
    char dotOrigin[MAX_DOMAIN_LEN+2];
} RRParser;

// parser
RRParser *RRParserCreate(char *name, uint32_t ttl, char *dotOrigin);
void RRParserDestroy(RRParser *psr);
int RRParserSetDotOrigin(RRParser *psr, char *dotOrigin);
int RRParserFeed(RRParser *psr, char *ss, char *name, zone *z);
int RRParserFeedRdata(RRParser *psr, char *rdata, char *name, uint32_t ttl, char *type, zone *z);

int parseSOASn(char *errstr, char *soa, unsigned long *sn);
int abs2lenRelative(char domain[], char *dotOrigin);
int loadZoneFromStr(char *errstr, int socket_id, char *zbuf, zone **zpp);
int loadZoneFromFile(int socket_id, const char *fname, zone **zpp);

#endif //SHUKE_ZPARSER_H

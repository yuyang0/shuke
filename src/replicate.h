//
// Created by yangyu on 6/11/17.
//

#ifndef SHUKE_REPLICATE_H
#define SHUKE_REPLICATE_H

#define REPLICATE_ADD   1
#define REPLICATE_DEL   (1 << 1)

typedef struct {
    int type;
    zone *z;
    char origin[MAX_DOMAIN_LEN];
}replicateLog;

replicateLog *replicateLogCreate(int type, char *origin, zone *z);
void replicateDestroy(replicateLog *l);
void processReplicateLog();

#endif //SHUKE_REPLICATE_H

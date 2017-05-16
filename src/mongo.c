//
// Created by yangyu on 17-3-20.
//

#include "shuke.h"

int initMongo() {
    return OK_CODE;
}

int checkMongo() {
    return OK_CODE;
}

// synchronous get all zone.
int mongoGetAllZone() {
    LOG_INFO(USER1, "Synchronous get all zones");
    return 0;
}

int mongoAsyncReloadAllZone() {
    LOG_INFO(USER1, "Asynchronous get all zones");
    return OK_CODE;
}

int mongoAsyncReloadZone(zoneReloadTask *t) {
    ((void) t);
    LOG_INFO(USER1, "Asynchronous get all zones");
    return OK_CODE;
}

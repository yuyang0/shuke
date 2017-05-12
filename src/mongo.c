//
// Created by yangyu on 17-3-20.
//

#include "shuke.h"

int initMongo() {
    return C_OK;
}

int checkMongo() {
    return C_OK;
}

// synchronous get all zone.
int mongoGetAllZone() {
    LOG_INFO("Synchronous get all zones");
    return 0;
}

int mongoAsyncReloadAllZone() {
    LOG_INFO("Asynchronous get all zones");
    return C_OK;
}

int mongoAsyncReloadZone(zoneReloadTask *t) {
    ((void) t);
    LOG_INFO("Asynchronous get all zones");
    return C_OK;
}

//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-11-28
//
#include "sk_lua.h"
#include "shuke.h"

DEF_LOG_MODULE(RTE_LOGTYPE_USER1, "LUA");

static int sk_lua_var_get(lua_State *L);
static int sk_lua_var_set(lua_State *L);


static void push_qname(lua_State *L, struct context *ctx);
static void push_qtype(lua_State *L, struct context *ctx);
static void push_client_addr(lua_State *L, struct context *ctx);

typedef void pushCommandProc(lua_State *L, struct context *ctx);
typedef struct {
    char *name;
    pushCommandProc *proc;
} pushCommand;

static pushCommand pushCommandTable[] = {
        {(char *)"qname", push_qname},
        {(char *)"qtype", push_qtype},
        {(char *)"client_addr", push_client_addr}
};

static dict *varDict = NULL;

void
sk_lua_inject_variable_api(lua_State *L)
{
    /* {{{ register reference maps */
    lua_newtable(L);    /* sk.var */

    lua_createtable(L, 0, 2 /* nrec */); /* metatable for .var */
    lua_pushcfunction(L, sk_lua_var_get);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, sk_lua_var_set);
    lua_setfield(L, -2, "__newindex");
    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "var");
    if (varDict == NULL) {
        varDict = dictCreate(&dictTypeStringCopyKey, NULL, sk.master_numa_id);

        int numcommands = sizeof(pushCommandTable)/sizeof(pushCommand);
        for (int j = 0; j < numcommands; j++) {
            pushCommand *c = pushCommandTable+j;
            if (dictAdd(varDict, c->name, c) != DICT_OK) {
                LOG_FATAL("can't add push command %s to dict", c->name);
            }
        }
    }
}

static void push_qname(lua_State *L, struct context *ctx) {
    lua_pushstring(L, ctx->name);
}

static void push_qtype(lua_State *L, struct context *ctx) {
    lua_pushinteger(L, ctx->qType);
}

static void push_client_addr(lua_State *L, struct context *ctx) {
    if (! ctx->hasClientSubnetOpt)  {
        lua_pushnil(L);
    } else {
        char addr[128];
        inet_ntop(ctx->cinfo.client_family, ctx->cinfo.client_ip, addr, sizeof(addr));
        lua_pushstring(L, addr);
    }
}

static int
sk_lua_var_get(lua_State *L)
{
    u_char *p;
    size_t len;
    struct context *ctx;

    // LOG_DEBUG("in get var");
    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad variable name");
    }
    p = (u_char *) lua_tolstring(L, -1, &len);
    ctx = &sk.lcore_conf[rte_lcore_id()].ctx;

    pushCommand *cmd = dictFetchValue(varDict, p);
    if (cmd) {
        cmd->proc(L, ctx);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int
sk_lua_var_set(lua_State *L)
{
    return 1;
}

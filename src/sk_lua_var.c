//
// Created by Yu Yang <yyangplus@NOSPAM.gmail.com> on 2017-11-28
//
#include "sk_lua.h"

static int sk_lua_var_get(lua_State *L);
static int sk_lua_var_set(lua_State *L);

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
}

static int
sk_lua_var_get(lua_State *L)
{
    return 1;
}

static int
sk_lua_var_set(lua_State *L)
{
    return 1;
}

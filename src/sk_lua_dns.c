//
// Created by yangyu on 17-11-30.
//

#include "sk_lua.h"
#include "shuke.h"

static void sk_lua_inject_dns_consts(lua_State *L);

void
sk_lua_inject_dns_api(lua_State *L) {
    sk_lua_inject_dns_consts(L);
}

/* static int */
/* sk_lua_exit(lua_State *L) { */
/*     int code; */
/*     code = luaL_checkint(L, 1); */
/*     lua_y */
/* } */

static void
sk_lua_inject_dns_consts(lua_State *L) {
    lua_pushinteger(L, DNS_TYPE_A);
    lua_setfield(L, -2, "DNS_TYPE_A");

    lua_pushinteger(L, DNS_TYPE_AAAA);
    lua_setfield(L, -2, "DNS_TYPE_AAAA");

    lua_pushinteger(L, DNS_TYPE_MX);
    lua_setfield(L, -2, "DNS_TYPE_MX");

    lua_pushinteger(L, DNS_TYPE_TXT);
    lua_setfield(L, -2, "DNS_TYPE_TXT");

    lua_pushinteger(L, DNS_TYPE_SOA);
    lua_setfield(L, -2, "DNS_TYPE_SOA");

    lua_pushinteger(L, DNS_TYPE_NS);
    lua_setfield(L, -2, "DNS_TYPE_NS");

    lua_pushinteger(L, DNS_TYPE_CNAME);
    lua_setfield(L, -2, "DNS_TYPE_CNAME");

    lua_pushinteger(L, DNS_TYPE_SRV);
    lua_setfield(L, -2, "DNS_TYPE_SRV");
}

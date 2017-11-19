//
// Created by yangyu on 11/17/17.
//

#include "sk_lua.h"

static void
sk_lua_inject_all_api(lua_State *L)
{
    lua_createtable(L, 0 /* narr */, 116 /* nrec */);    /* sk.* */

    // lua_pushcfunction(L, ngx_http_lua_get_raw_phase_context);
    // lua_setfield(L, -2, "_phase_ctx");

    sk_lua_inject_log_api(L);

    lua_setglobal(L, "sk");
}

lua_State *sk_lua_new_state() {
    lua_State *L;
    L = luaL_newstate();
    if (L == NULL) {
        return NULL;
    }

    luaL_openlibs(L);
    sk_lua_inject_all_api(L);
    return L;
}

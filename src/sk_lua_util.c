//
// Created by yangyu on 11/17/17.
//

#include "sk_lua.h"
#include "shuke.h"

#ifndef LUA_PATH_SEP
#define LUA_PATH_SEP ";"
#endif

#define AUX_MARK "\1"

static void
sk_lua_set_path(lua_State *L, int tab_idx, const char *fieldname, const char *path, const char *default_path)
{
    const char          *tmp_path;
    const char          *prefix;

    /* XXX here we use some hack to simplify string manipulation */
    tmp_path = luaL_gsub(L, path, LUA_PATH_SEP LUA_PATH_SEP,
                         LUA_PATH_SEP AUX_MARK LUA_PATH_SEP);

    lua_pushstring(L, sk.prefix);
    prefix = lua_tostring(L, -1);
    tmp_path = luaL_gsub(L, tmp_path, "$prefix", prefix);
    tmp_path = luaL_gsub(L, tmp_path, "${prefix}", prefix);
    lua_pop(L, 3);

    LOG_DEBUG(USER1, "tmp_path path: %s", tmp_path);

    luaL_gsub(L, tmp_path, AUX_MARK, default_path);

    lua_remove(L, -2);

    /* fix negative index as there's new data on stack */
    tab_idx = (tab_idx < 0) ? (tab_idx - 1) : tab_idx;
    lua_setfield(L, tab_idx, fieldname);
}

static void
sk_lua_inject_all_api(lua_State *L)
{
    lua_createtable(L, 0 /* narr */, 116 /* nrec */);    /* sk.* */

    // lua_pushcfunction(L, ngx_http_lua_get_raw_phase_context);
    // lua_setfield(L, -2, "_phase_ctx");

    sk_lua_inject_log_api(L);
    sk_lua_inject_variable_api(L);

    lua_setglobal(L, "sk");
}

/* static int panic (lua_State *L) { */
/*     LOG_ERR(USER1, "PANIC: unprotected error in call to Lua API (%s)\n", */
/*             lua_tostring(L, -1)); */
/*     return 0;  /\* return to Lua to abort *\/ */
/* } */

/* static void *sk_lua_alloc (void *ud, void *ptr, size_t osize, size_t nsize) { */
/*     (void)ud; (void)osize;  /\* not used *\/ */
/*     if (nsize == 0) { */
/*         rte_free(ptr); */
/*         return NULL; */
/*     } */
/*     else */
/*         return rte_realloc(ptr, nsize, 0); */
/* } */

lua_State *sk_lua_new_state(struct lua_conf *lconf) {
    lua_State *L;
    const char *old_path;
    const char *new_path;
    size_t old_path_len;

    const char *old_cpath;
    const char *new_cpath;
    size_t old_cpath_len;
    /* L = lua_newstate(sk_lua_alloc, NULL); */
    /* if (L == NULL) { */
    /*     return NULL; */
    /* } */
    /* lua_atpanic(L, &panic); */
    L = luaL_newstate();

    luaL_openlibs(L);
    lua_getglobal(L, "package");
    if (!lua_istable(L, -1)) {
        LOG_ERR(USER1, "the \"package\" table does not exist");
        return NULL;
    }
#ifdef LUA_DEFAULT_PATH
#   define LUA_DEFAULT_PATH_LEN (sizeof(LUA_DEFAULT_PATH) - 1)
    LOG_DEBUG(USER1,
              "lua prepending default package.path with %s",
              LUA_DEFAULT_PATH);

    lua_pushliteral(L, LUA_DEFAULT_PATH ";"); /* package default */
    lua_getfield(L, -2, "path"); /* package default old */
    old_path = lua_tolstring(L, -1, &old_path_len);
    lua_concat(L, 2); /* package new */
    lua_setfield(L, -2, "path"); /* package */
#endif

#ifdef LUA_DEFAULT_CPATH
#   define LUA_DEFAULT_CPATH_LEN (sizeof(LUA_DEFAULT_CPATH) - 1)
    LOG_DEBUG(USER1,
              "lua prepending default package.cpath with %s",
              LUA_DEFAULT_CPATH);

    lua_pushliteral(L, LUA_DEFAULT_CPATH ";"); /* package default */
    lua_getfield(L, -2, "cpath"); /* package default old */
    old_cpath = lua_tolstring(L, -1, &old_cpath_len);
    lua_concat(L, 2); /* package new */
    lua_setfield(L, -2, "cpath"); /* package */
#endif
    if (lconf->package_path) {
        LOG_DEBUG(USER1, "pacakge path %s", lconf->package_path);
        lua_getfield(L, -1, "path"); /* get original package.path */
        old_path = lua_tolstring(L, -1, &old_path_len);

        LOG_DEBUG(USER1, "old path: %s", old_path);

        lua_pushstring(L, lconf->package_path);
        new_path = lua_tostring(L, -1);

        sk_lua_set_path(L, -3, "path", new_path, old_path);

        lua_pop(L, 2);
    }
    if (lconf->package_cpath) {
        lua_getfield(L, -1, "cpath"); /* get original package.cpath */
        old_cpath = lua_tolstring(L, -1, &old_cpath_len);

        LOG_DEBUG(USER1, "old cpath: %s", old_cpath);

        lua_pushstring(L, lconf->package_cpath);
        new_cpath = lua_tostring(L, -1);

        sk_lua_set_path(L, -3, "cpath", new_cpath, old_cpath);

        lua_pop(L, 2);
    }
    lua_pop(L, 1); /* remove the "package" table */

    sk_lua_inject_all_api(L);
    return L;
}

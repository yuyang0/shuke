//
// Created by yangyu on 11/17/17.
//

#include "sk_lua.h"
#include "log.h"

#define RTE_LOGTYPE_LUA RTE_LOGTYPE_USER1

static void sk_lua_inject_log_consts(lua_State *L);
static int sk_lua_log(lua_State *L);
static int log_wrapper(const char *ident, int level, lua_State *L);

void
sk_lua_inject_log_api(lua_State *L) {
    sk_lua_inject_log_consts(L);

    lua_pushcfunction(L, sk_lua_log);
    lua_setfield(L, -2, "log");

    // lua_pushcfunction(L, ngx_http_lua_print);
    // lua_setglobal(L, "print");
}

static void
sk_lua_inject_log_consts(lua_State *L) {
    lua_pushinteger(L, RTE_LOG_EMERG);
    lua_setfield(L, -2, "EMERG");

    lua_pushinteger(L, RTE_LOG_ALERT);
    lua_setfield(L, -2, "ALERT");

    lua_pushinteger(L, RTE_LOG_CRIT);
    lua_setfield(L, -2, "CRIT");

    lua_pushinteger(L, RTE_LOG_ERR);
    lua_setfield(L, -2, "ERR");

    lua_pushinteger(L, RTE_LOG_WARNING);
    lua_setfield(L, -2, "WARN");

    lua_pushinteger(L, RTE_LOG_WARNING);
    lua_setfield(L, -2, "WARNING");

    lua_pushinteger(L, RTE_LOG_NOTICE);
    lua_setfield(L, -2, "NOTICE");

    lua_pushinteger(L, RTE_LOG_INFO);
    lua_setfield(L, -2, "INFO");

    lua_pushinteger(L, RTE_LOG_DEBUG);
    lua_setfield(L, -2, "DEBUG");
}


static int sk_lua_log(lua_State *L) {
    const char                  *msg;
    int                          level;

    level = luaL_checkint(L, 1);
    if (level < RTE_LOG_EMERG || level > RTE_LOG_DEBUG) {
        msg = lua_pushfstring(L, "bad log level: %d", level);
        return luaL_argerror(L, 1, msg);
    }

    /* remove log-level param from stack */
    lua_remove(L, 1);

    return log_wrapper("[lua] ", level, L);
}

static int
log_wrapper(const char *ident, int level, lua_State *L)
{
    u_char              *buf;
    u_char              *p, *q;
    int                  nargs, i;
    size_t               size=0, len;
    int                  type;
    const char          *msg;

    if ((level > rte_logs.level) || !(RTE_LOGTYPE_LUA & rte_logs.type))
        return 0;

    nargs = lua_gettop(L);

    for (i = 1; i <= nargs; i++) {
        type = lua_type(L, i);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                lua_tolstring(L, i, &len);
                size += len;
                break;

            case LUA_TNIL:
                size += sizeof("nil") - 1;
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, i)) {
                    size += sizeof("true") - 1;

                } else {
                    size += sizeof("false") - 1;
                }

                break;

            case LUA_TTABLE:
                if (!luaL_callmeta(L, i, "__tostring")) {
                    return luaL_argerror(L, i, "expected table to have "
                            "__tostring metamethod");
                }

                lua_tolstring(L, -1, &len);
                size += len;
                break;

            case LUA_TLIGHTUSERDATA:
                if (lua_touserdata(L, i) == NULL) {
                    size += sizeof("null") - 1;
                    break;
                }

                continue;

            default:
                msg = lua_pushfstring(L, "string, number, boolean, or nil "
                                              "expected, got %s",
                                      lua_typename(L, type));
                return luaL_argerror(L, i, msg);
        }
    }
    // last zero
    size++;

    buf = lua_newuserdata(L, size);
    p = buf;

    for (i = 1; i <= nargs; i++) {
        type = lua_type(L, i);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                q = (u_char *) lua_tolstring(L, i, &len);
                memcpy(p, q, len);
                p += len;
                break;

            case LUA_TNIL:
                *p++ = 'n';
                *p++ = 'i';
                *p++ = 'l';
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, i)) {
                    *p++ = 't';
                    *p++ = 'r';
                    *p++ = 'u';
                    *p++ = 'e';

                } else {
                    *p++ = 'f';
                    *p++ = 'a';
                    *p++ = 'l';
                    *p++ = 's';
                    *p++ = 'e';
                }

                break;

            case LUA_TTABLE:
                luaL_callmeta(L, i, "__tostring");
                q = (u_char *) lua_tolstring(L, -1, &len);
                memcpy(p, q, len);
                p += len;
                break;

            case LUA_TLIGHTUSERDATA:
                *p++ = 'n';
                *p++ = 'u';
                *p++ = 'l';
                *p++ = 'l';

                break;

            default:
                return luaL_error(L, "impossible to reach here");
        }
    }
    *p++ = '\0';
    if (p - buf > (off_t) size) {
        return luaL_error(L, "buffer error: %d > %d", (int) (p - buf),
                          (int) size);
    }

    rte_log((uint32_t )level, RTE_LOGTYPE_LUA, "%s%s", ident, buf);

    return 0;
}

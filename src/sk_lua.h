//
// Created by yangyu on 11/18/17.
//

#ifndef SHUKE_SK_LUA_H
#define SHUKE_SK_LUA_H

#include <string.h>
#include <stdlib.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

lua_State *sk_lua_new_state();
void sk_lua_inject_log_api(lua_State *L);
#endif //SHUKE_SK_LUA_H

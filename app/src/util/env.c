#include "env.h"

#include <stdlib.h>
#include <string.h>
#include "util/str.h"

char *
sc_get_env(const char *varname) {
#ifdef _WIN32
    wchar_t *w_varname = sc_str_to_wchars(varname);
    if (!w_varname) {
         return NULL;
    }
    const wchar_t *value = _wgetenv(w_varname);
    free(w_varname);
    if (!value) {
        return NULL;
    }

    return sc_str_from_wchars(value);
#else
    const char *value = getenv(varname);
    if (!value) {
        return NULL;
    }

    return strdup(value);
#endif
}

bool
sc_set_env(const char *varname, const char *value) {
#ifdef _WIN32
    wchar_t *w_varname = sc_str_to_wchars(varname);
    if (!w_varname) {
        return false;
    }
    wchar_t *w_value = sc_str_to_wchars(value);
    if (!w_value) {
        free(w_varname);
        return false;
    }
    
    bool ret = _wputenv_s(w_varname, w_value) == 0;
    free(w_varname);
    free(w_value);
    return ret;
#else
    return setenv(varname, value, 1) == 0;
#endif
}

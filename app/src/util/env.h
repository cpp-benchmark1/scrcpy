#ifndef SC_ENV_H
#define SC_ENV_H

#include <stdbool.h>
#include "common.h"

// Return the value of the environment variable (may be NULL).
//
// The returned value must be freed by the caller.
char *
sc_get_env(const char *varname);

// Set an environment variable
// Returns true on success, false on failure.
bool
sc_set_env(const char *varname, const char *value);

#endif

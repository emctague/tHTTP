#include "env.h"

#include <stdio.h>
#include <stdlib.h>
#include "diagnostics.h"

int get_env_integer(const int default_val, const char* env_name, const int min, const int max)
{
    const char* const env_value = getenv(env_name);
    if (env_value == NULL) return default_val;

    const char* to_num_error = NULL;
    const int conv_result = strtonum(env_value, min, max, &to_num_error);

    if (to_num_error != NULL) {
        fprintf(stderr, "Invalid %s: %s", env_name, to_num_error);
        exit(EXIT_INVALID_NUMERIC_ENV_VAR);
    }

    return conv_result;
}

const char* get_env_str(const char* env_name, const char* default_val)
{
    const char* const env_value = getenv(env_name);
    if (env_value == NULL) return default_val;
    return env_value;
}
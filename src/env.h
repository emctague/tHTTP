#pragma once

/// Get an integer environment variable `env_name`.
/// The value of this environment variable must either:
/// - be a valid integer string between `min` and `max`,
///   in which case it will be returned as an int, or
/// - not be provided at all, in which case `default_val` is returned.
/// Otherwise, this will print an error and exit(EXIT_INVALID_NUMERIC_ENV_VAR).
int get_env_integer(int default_val, const char* env_name, int min, int max);

/// Get an environment variable `env_name`, or fall back to a default value.
const char* get_env_str(const char* env_name, const char* default_val);

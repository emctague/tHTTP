#pragma once

/// Check for basic sanity (no root, etc.)
/// Can exit(EXIT_DONT_USE_ROOT).
void security_sanity_check();

/// Enter sandbox mode, surrendering all possible priveleges except fork().
/// Can exit(EXIT_SANDBOX_FAILED).
void security_enter_sandbox();

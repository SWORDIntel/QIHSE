#ifndef QIHSE_SYSTEM_GUARD_H
#define QIHSE_SYSTEM_GUARD_H

#include <stddef.h>
#include <stdbool.h>

void qihse_system_guard_profile(void);
bool qihse_system_guard_check_operation(size_t required_bytes, bool is_brute_force);

#endif // QIHSE_SYSTEM_GUARD_H

#include "qihse.h"

const char* qihse_version(void) {
    return "Quantum Inspire dHilbert Space Expansion Search";
}

const char* qihse_build_info(void) {
    return "QIHSE Build: Heterogeneous compute, RFF kernel, adaptive Grover amplification, L2 collapse";
}

bool qihse_available(void) {
    return true;
}

#include "qihse_ct1_authority_service.h"

#include <stdio.h>
#include <string.h>

/* Status only: never opens fixtures, connects to nodes, or loads credentials. */
int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        puts("Usage: qihse-ct1-authority --status\n"
             "Local prerequisite diagnostics only; --status exits 2 (disabled).\n"
             "Root checkpoint and quote verification alone never grant access.\n"
             "No authorization, consume, signing, provisioning or live check.\n"
             "The root-only source fixture lease does not install a CT HOLD or take over B.");
        return 0;
    }
    if (argc != 2 || strcmp(argv[1], "--status") != 0) {
        fputs("Usage: qihse-ct1-authority --status\n", stderr);
        return 2;
    }
    puts(qihse_ct1_authority_service_diagnostic());
    return 2;
}

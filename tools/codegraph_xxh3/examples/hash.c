#include "qihse_xxh3_inline.h"
#include <stdio.h>
int main(void)
{
    const qx3_backend *b=qx3_backend_get("auto");
    if (!b) { perror("backend"); return 1; }
    char hex[33];
    qx3_hash128_t h=qx3_hash128_inline(b,"abc",3);
    qx3_hex(h,hex);
    printf("%s  backend=%s\n",hex,b->name);
    return 0;
}

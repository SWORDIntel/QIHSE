#include <immintrin.h>
#include <stdio.h>
#include <string.h>

int main() {
    printf("Testing AMX-TILE...\n");
    
    struct __tilecfg {
        unsigned char palette_id;
        unsigned char start_row;
        unsigned char reserved_0[14];
        unsigned short colsb[16];
        unsigned char rows[16];
    };
    
    struct __tilecfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.palette_id = 1;
    
    _tile_loadconfig(&cfg);
    printf("Tile config loaded\n");
    _tile_release();
    printf("✓ AMX-TILE SUCCESS!\n");
    return 0;
}

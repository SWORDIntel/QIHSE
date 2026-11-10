/* Exercise the production metadata decoder without allocating an image. */
#include "../src/spinnaker/qihse_resp_engine.c"
#include <assert.h>

static bool parses(const char* total) {
    const char* fields[] = {"REPL.CT2", "BEGIN", "image-bounds",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "qkp-source", "qkp-target", "11111111111111111111111111111111",
        "10", "12", "4", "7", total,
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333"};
    qihse_resp_arg_t arguments[15];
    for (size_t i = 0; i < 15; ++i) {
        arguments[i].data = (const unsigned char*)fields[i];
        arguments[i].len = strlen(fields[i]);
    }
    qihse_resp_request_t request = {.argc = 15};
    memcpy(request.argv, arguments, sizeof(arguments));
    qihse_resp_ct2_tuple_t tuple;
    bool ok = qihse_resp_ct2_parse_tuple(&request, &tuple);
    if (ok) assert(tuple.total_bytes == strtoull(total, NULL, 10));
    return ok;
}

int main(void) {
    assert(parses("67108864"));
    assert(parses("67284039"));
    assert(parses("9223372036854775807"));
    assert(!parses("0"));
    assert(!parses("9223372036854775808"));
    assert(!parses("18446744073709551615"));
    assert(!parses("18446744073709551616"));
    puts("PASS CT2 metadata accepts images above 64 MiB and rejects unrepresentable offsets");
    return 0;
}

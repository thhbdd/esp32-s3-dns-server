/* Host-only fault injection: force the optional FSST trainer to report OOM.
 * The compiled image must still load and match every rule correctly. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fl_filter.h"
#include "fl_internal.h"

static unsigned failures_injected;
int __real_fl_fsst_build(fl_symtab_t *, const uint8_t *, const uint32_t *, size_t);
int __wrap_fl_fsst_build(fl_symtab_t *t, const uint8_t *sample,
                         const uint32_t *offs, size_t nstr) {
    if (nstr) {
        (void)t;
        (void)sample;
        (void)offs;
        failures_injected++;
        return FL_ERR_NOMEM;
    }
    return __real_fl_fsst_build(t, NULL, NULL, 0);
}

static int check(fl_set_t *set, const char *host, unsigned verdict) {
    fl_req_t req = { host, (uint16_t)strlen(host), 1, 0, NULL };
    fl_result_t result;
    fl_match(set, &req, &result);
    if (result.verdict != verdict) {
        fprintf(stderr, "unexpected verdict on %s: got %u expected %u\n",
                host, result.verdict, verdict);
        return 1;
    }
    return 0;
}

int main(void) {
    const char *rules = "||ads.example.com^\n||tracker.example.org^\n"
                        "@@||safe.example.com^\n||example.com^\n";
    fl_memstore_t staging, image;
    fl_memstore_init(&staging, 16u << 20);
    fl_memstore_init(&image, 16u << 20);
    fl_compile_opts_t opts = {0};
    opts.runs = &staging.st;
    opts.chunk_bytes = 8192;
    fl_compiler_t *compiler = fl_compile_new(&opts);
    if (!compiler) return 1;
    if (fl_compile_begin_source(compiler, "oom-test", 0) < 0) return 2;
    if (fl_compile_feed(compiler, rules, strlen(rules))) return 3;
    if (fl_compile_end_source(compiler)) return 4;
    fl_stats_t st;
    int size = fl_compile_finish(compiler, &image.st, &st);
    if (size <= 0 || failures_injected != 1) {
        fprintf(stderr, "FSST OOM fallback failed: size=%d injected=%u error=%s\n",
                size, failures_injected, fl_compile_error(compiler));
        return 5;
    }
    uint8_t *data = (uint8_t *)dc_malloc_ext((size_t)size);
    if (!data) return 6;
    memcpy(data, image.buf.data, (size_t)size);
    fl_image_t *loaded = NULL;
    if (fl_image_load(data, (size_t)size, true, &loaded)) return 7;
    fl_set_t *set = fl_set_new(&loaded, 1, 1);
    fl_image_unref(loaded);
    if (!set) return 8;
    int error = check(set, "ads.example.com", FL_V_BLOCK) ||
                check(set, "tracker.example.org", FL_V_BLOCK) ||
                check(set, "safe.example.com", FL_V_ALLOW) ||
                check(set, "foo.example.com", FL_V_BLOCK) ||
                check(set, "example.net", FL_V_NONE);
    fl_set_unref(set);
    fl_compile_free(compiler);
    fl_memstore_free(&staging);
    fl_memstore_free(&image);
    if (!error) puts("FSST OOM fallback: image verified and verdicts correct");
    return error;
}

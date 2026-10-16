/*
 * fl_regex.h - bounded regular expression engine (Go RE2 syntax subset).
 *
 * AdGuard Home evaluates every non-trivial rule pattern as a Go RE2 regular
 * expression.  RE2 has no backreferences or lookaround, so every accepted
 * expression can be executed by an automaton in time linear in the input:
 *
 *   regex text --parse--> AST --compile--> Thompson NFA --subset--> DFA
 *
 * The compiler emits either a DFA table (one table lookup per input byte) or,
 * when the DFA would exceed its state budget, a compact NFA program executed
 * by a Pike VM without captures.  Both are serialized into a position
 * independent byte program that lives inside the rule image.
 *
 * Matching semantics: unanchored search, returns true if the expression
 * matches any substring of the subject (like Go's regexp.MatchString).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    FL_RE_ICASE = 1u << 0,    /* (?i) prefix: case-insensitive */
    FL_RE_PREFER_NFA = 1u << 1, /* do not build a DFA (memory saving) */
};

enum {
    FL_RE_OK = 0,
    FL_RE_ESYNTAX = -1,      /* rejected by Go's parser as well */
    FL_RE_EUNSUPPORTED = -2, /* valid for Go but not supported here (e.g. \p{..}) */
    FL_RE_ETOOBIG = -3,      /* exceeds device complexity budget */
    FL_RE_ENOMEM = -4,
};

typedef struct {
    uint16_t dfa_states; /* 0 when an NFA program was emitted */
    /* Longest literal that every match must contain (lowercase).  Used as a
     * sound prefilter: if it is absent from the subject the rule cannot
     * match.  Empty when no literal of length >= 1 is required. */
    char req[64];
    uint8_t req_len;
} fl_re_info_t;

/* Compiles `re[0..len)` and appends the program to `out`.
 * Returns FL_RE_OK or an error; *err receives a static description. */
int fl_re_compile(const char *re, size_t len, unsigned flags, unsigned max_dfa_states,
                  dc_buf_t *out, fl_re_info_t *info, const char **err);

/* Validates a serialized program (bounds) - used when loading images. */
bool fl_re_validate(const uint8_t *prog, size_t avail, size_t *prog_len);

/* Executes a program.  `s` must be lowercase when compiled with FL_RE_ICASE. */
bool fl_re_match(const uint8_t *prog, const uint8_t *s, size_t n);

#ifdef __cplusplus
}
#endif

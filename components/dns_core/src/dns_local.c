/* dns_local.c - local records table (see dns_local.h). */
#include "dns_local.h"

#include <stdlib.h>
#include <string.h>

#include "dc_util.h"
#include "fl_filter.h"

typedef struct {
    char *name; /* lowercase; for wildcards the suffix without "*." */
    uint16_t nlen;
    bool wildcard;
    uint32_t first, n; /* range in recs */
} lent_t;

typedef struct {
    char *name;
    bool wildcard;
    dns_lrec_t rec;
} pending_t;

struct dns_local {
    pending_t *pend;
    unsigned npend, cappend;
    lent_t *ents;
    unsigned nents;
    dns_lrec_t *recs;
    unsigned nrecs;
    uint32_t *hash_tab; /* exact names: index+1 */
    uint32_t hmask;
    unsigned *wild; /* wildcard entries sorted by suffix length desc */
    unsigned nwild;
    bool sealed;
};

dns_local_t *dns_local_new(void) { return (dns_local_t *)dc_calloc(1, sizeof(dns_local_t)); }

void dns_local_free(dns_local_t *l) {
    if (!l) return;
    for (unsigned i = 0; i < l->npend; i++) {
        dc_free(l->pend[i].name);
        dc_free((void *)l->pend[i].rec.rdata);
    }
    dc_free(l->pend);
    for (unsigned i = 0; i < l->nents; i++) dc_free(l->ents[i].name);
    for (unsigned i = 0; i < l->nrecs; i++) dc_free((void *)l->recs[i].rdata);
    dc_free(l->ents);
    dc_free(l->recs);
    dc_free(l->hash_tab);
    dc_free(l->wild);
    dc_free(l);
}

int dns_local_add(dns_local_t *l, const char *domain, const char *type, uint32_t ttl, const char *value,
                  const char **err) {
    if (l->sealed) {
        *err = "table sealed";
        return -1;
    }
    size_t dl = strlen(domain);
    while (dl && domain[dl - 1] == '.') dl--;
    bool wild = dl > 2 && domain[0] == '*' && domain[1] == '.';
    const char *nm = wild ? domain + 2 : domain;
    size_t nl = wild ? dl - 2 : dl;
    if (!nl || nl > 253) {
        *err = "invalid domain";
        return -1;
    }
    dns_lrec_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.ttl = ttl ? ttl : 300;
    if (value && strcmp(value, "-") == 0) {
        rec.type = fl_rr_type_code(type);
        if (!rec.type) {
            *err = "unknown record type";
            return -1;
        }
        rec.passthrough = true;
    } else {
        uint8_t rd[600];
        uint16_t rl = 0;
        int t = fl_encode_rdata(type, value ? value : "", rd, sizeof(rd), &rl, err);
        if (t < 0) return -1;
        rec.type = (uint16_t)t;
        rec.rdlen = rl;
        uint8_t *copy = (uint8_t *)dc_malloc(rl ? rl : 1);
        if (!copy) {
            *err = "out of memory";
            return -1;
        }
        memcpy(copy, rd, rl);
        rec.rdata = copy;
    }
    if (l->npend == l->cappend) {
        unsigned nc = l->cappend ? l->cappend * 2 : 16;
        pending_t *np = (pending_t *)dc_realloc(l->pend, nc * sizeof(pending_t));
        if (!np) {
            dc_free((void *)rec.rdata);
            *err = "out of memory";
            return -1;
        }
        l->pend = np;
        l->cappend = nc;
    }
    char *n = (char *)dc_malloc(nl + 1);
    if (!n) {
        dc_free((void *)rec.rdata);
        *err = "out of memory";
        return -1;
    }
    for (size_t i = 0; i < nl; i++) n[i] = (char)dc_lower((uint8_t)nm[i]);
    n[nl] = 0;
    l->pend[l->npend].name = n;
    l->pend[l->npend].wildcard = wild;
    l->pend[l->npend].rec = rec;
    l->npend++;
    return 0;
}

static int cmp_pend(const void *a, const void *b) {
    const pending_t *x = (const pending_t *)a, *y = (const pending_t *)b;
    if (x->wildcard != y->wildcard) return x->wildcard - y->wildcard;
    return strcmp(x->name, y->name);
}

static uint32_t hstr(const char *s, size_t n) { return dc_fmix32(dc_fnv32(s, n)); }

int dns_local_seal(dns_local_t *l) {
    if (l->sealed) return 0;
    if (!l->npend) {
        l->sealed = true;
        return 0;
    }
    /* everything is allocated first: on failure nothing has changed */
    unsigned n = l->npend;
    uint32_t cap = 16;
    while (cap < n * 2) cap <<= 1;
    unsigned *ord = (unsigned *)dc_malloc(n * sizeof(unsigned));
    dns_lrec_t *recs = (dns_lrec_t *)dc_malloc(n * sizeof(dns_lrec_t));
    lent_t *ents = (lent_t *)dc_calloc(n, sizeof(lent_t));
    uint32_t *htab = (uint32_t *)dc_calloc(cap, sizeof(uint32_t));
    unsigned *wild = (unsigned *)dc_malloc((n + 1) * sizeof(unsigned));
    if (!ord || !recs || !ents || !htab || !wild) {
        dc_free(ord);
        dc_free(recs);
        dc_free(ents);
        dc_free(htab);
        dc_free(wild);
        return -1;
    }
    l->sealed = true;
    l->recs = recs;
    l->ents = ents;
    l->hash_tab = htab;
    l->hmask = cap - 1;
    l->wild = wild;
    /* stable sort by (wildcard, name): records keep insertion order within a name */
    for (unsigned i = 0; i < n; i++) ord[i] = i;
    for (unsigned i = 1; i < n; i++) { /* insertion sort: small tables */
        unsigned v = ord[i], j = i;
        while (j && cmp_pend(&l->pend[ord[j - 1]], &l->pend[v]) > 0) {
            ord[j] = ord[j - 1];
            j--;
        }
        ord[j] = v;
    }
    for (unsigned k = 0; k < n; k++) {
        pending_t *p = &l->pend[ord[k]];
        l->recs[l->nrecs] = p->rec;
        if (l->nents && l->ents[l->nents - 1].wildcard == p->wildcard &&
            strcmp(l->ents[l->nents - 1].name, p->name) == 0) {
            l->ents[l->nents - 1].n++;
            dc_free(p->name);
        } else {
            lent_t *e = &l->ents[l->nents++];
            e->name = p->name;
            e->nlen = (uint16_t)strlen(p->name);
            e->wildcard = p->wildcard;
            e->first = l->nrecs;
            e->n = 1;
        }
        l->nrecs++;
    }
    dc_free(ord);
    dc_free(l->pend);
    l->pend = NULL;
    l->npend = l->cappend = 0;
    /* exact hash table (sized for n >= nents names) */
    for (unsigned i = 0; i < l->nents; i++) {
        lent_t *e = &l->ents[i];
        if (e->wildcard) {
            l->wild[l->nwild++] = i;
            continue;
        }
        uint32_t h = hstr(e->name, e->nlen) & l->hmask;
        while (l->hash_tab[h]) h = (h + 1) & l->hmask;
        l->hash_tab[h] = i + 1;
    }
    for (unsigned i = 1; i < l->nwild; i++) { /* longest suffix first */
        unsigned v = l->wild[i], j = i;
        while (j && l->ents[l->wild[j - 1]].nlen < l->ents[v].nlen) {
            l->wild[j] = l->wild[j - 1];
            j--;
        }
        l->wild[j] = v;
    }
    return 0;
}

unsigned dns_local_count(const dns_local_t *l) { return l ? l->nrecs + l->npend : 0; }

bool dns_local_lookup(const dns_local_t *l, const char *host, size_t hl, dns_lentry_t *out) {
    if (!l || !l->nents) return false;
    uint32_t h = hstr(host, hl) & l->hmask;
    while (l->hash_tab[h]) {
        const lent_t *e = &l->ents[l->hash_tab[h] - 1];
        if (e->nlen == hl && memcmp(e->name, host, hl) == 0) {
            out->recs = &l->recs[e->first];
            out->n = e->n;
            return true;
        }
        h = (h + 1) & l->hmask;
    }
    for (unsigned i = 0; i < l->nwild; i++) {
        const lent_t *e = &l->ents[l->wild[i]];
        if (hl > e->nlen && host[hl - e->nlen - 1] == '.' && memcmp(host + hl - e->nlen, e->name, e->nlen) == 0) {
            out->recs = &l->recs[e->first];
            out->n = e->n;
            return true;
        }
    }
    return false;
}

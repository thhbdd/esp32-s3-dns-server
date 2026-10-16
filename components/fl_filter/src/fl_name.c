/* fl_name.c - hostname helpers, RR type / RCODE tables. */
#include <stdio.h>
#include <string.h>

#include "fl_internal.h"

static bool is_alnum(int c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static bool is_letter(int c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

/* golibs netutil.ValidateHostname (ASCII input; IDN is not converted) */
bool fl_valid_hostname(const char *s, size_t n) {
    if (n == 0 || n > 253) return false;
    size_t i = 0;
    for (;;) {
        size_t st = i;
        while (i < n && s[i] != '.') i++;
        size_t l = i - st;
        if (l == 0 || l > 63) return false;
        const char *lb = s + st;
        if (!is_alnum((unsigned char)lb[0]) || !is_alnum((unsigned char)lb[l - 1])) return false;
        for (size_t k = 1; k + 1 < l; k++)
            if (!is_alnum((unsigned char)lb[k]) && lb[k] != '-') return false;
        if (i == n) {
            /* TLD: not all-numeric */
            bool alldig = true;
            for (size_t k = 0; k < l; k++)
                if (lb[k] < '0' || lb[k] > '9') alldig = false;
            return !alldig;
        }
        i++; /* '.' */
    }
}

/* urlfilter internal/ufnet.IsDomainName */
bool fl_is_domain_name(const char *s, size_t n) {
    if (n > 253) return false;
    size_t i = 0;
    for (;;) {
        size_t st = i;
        while (i < n && s[i] != '.') i++;
        size_t l = i - st;
        const char *lb = s + st;
        if (l == 0 || l > 63) return false;
        if (l >= 4 && memcmp(lb, "xn--", 4) == 0 && l < 8) return false;
        for (size_t k = 0; k < l; k++) {
            int c = (unsigned char)lb[k];
            if (is_alnum(c)) continue;
            if (c != '-') return false;
            if (k == 0 || k == l - 1) return false;
        }
        if (i == n) {
            /* TLD label: >= 2 chars, starts and ends with a letter */
            return l >= 2 && is_letter((unsigned char)lb[0]) && is_letter((unsigned char)lb[l - 1]);
        }
        i++;
    }
}

static const struct {
    const char *n;
    uint16_t t;
} k_types[] = {
    {"A", 1},          {"NS", 2},         {"MD", 3},          {"MF", 4},         {"CNAME", 5},
    {"SOA", 6},        {"MB", 7},         {"MG", 8},          {"MR", 9},         {"NULL", 10},
    {"PTR", 12},       {"HINFO", 13},     {"MINFO", 14},      {"MX", 15},        {"TXT", 16},
    {"RP", 17},        {"AFSDB", 18},     {"X25", 19},        {"ISDN", 20},      {"RT", 21},
    {"NSAP-PTR", 23},  {"SIG", 24},       {"KEY", 25},        {"PX", 26},        {"GPOS", 27},
    {"AAAA", 28},      {"LOC", 29},       {"NXT", 30},        {"EID", 31},       {"NIMLOC", 32},
    {"SRV", 33},       {"ATMA", 34},      {"NAPTR", 35},      {"KX", 36},        {"CERT", 37},
    {"DNAME", 39},     {"OPT", 41},       {"APL", 42},        {"DS", 43},        {"SSHFP", 44},
    {"IPSECKEY", 45},  {"RRSIG", 46},     {"NSEC", 47},       {"DNSKEY", 48},    {"DHCID", 49},
    {"NSEC3", 50},     {"NSEC3PARAM", 51}, {"TLSA", 52},      {"SMIMEA", 53},    {"HIP", 55},
    {"NINFO", 56},     {"RKEY", 57},      {"TALINK", 58},     {"CDS", 59},       {"CDNSKEY", 60},
    {"OPENPGPKEY", 61}, {"CSYNC", 62},    {"ZONEMD", 63},     {"SVCB", 64},      {"HTTPS", 65},
    {"SPF", 99},       {"UINFO", 100},    {"UID", 101},       {"GID", 102},      {"UNSPEC", 103},
    {"NID", 104},      {"L32", 105},      {"L64", 106},       {"LP", 107},       {"EUI48", 108},
    {"EUI64", 109},    {"NXNAME", 128},   {"TKEY", 249},      {"TSIG", 250},     {"IXFR", 251},
    {"AXFR", 252},     {"MAILB", 253},    {"MAILA", 254},     {"ANY", 255},      {"URI", 256},
    {"CAA", 257},      {"AVC", 258},      {"AMTRELAY", 260},  {"RESINFO", 261},  {"TA", 32768},
    {"DLV", 32769},
};

/* miekg/dns StringToType[strings.ToUpper(s)] */
uint16_t fl_rrtype_from_name(const char *s, size_t n) {
    if (n == 0 || n > 16) return 0;
    char up[17];
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        up[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
    }
    up[n] = 0;
    for (size_t i = 0; i < DC_ARRAY_SIZE(k_types); i++)
        if (strcmp(k_types[i].n, up) == 0) return k_types[i].t;
    return 0;
}

static const char *const k_rcodes[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP",
                                       "REFUSED", "YXDOMAIN", "YXRRSET",  "NXRRSET",  "NOTAUTH",
                                       "NOTZONE", "DSOTYPENI"};

int fl_rcode_from_name(const char *s, size_t n) {
    char up[16];
    if (n == 0 || n >= sizeof(up)) return -1;
    for (size_t i = 0; i < n; i++) up[i] = (s[i] >= 'a' && s[i] <= 'z') ? (char)(s[i] - 32) : s[i];
    up[n] = 0;
    for (size_t i = 0; i < DC_ARRAY_SIZE(k_rcodes); i++)
        if (strcmp(up, k_rcodes[i]) == 0) return (int)i;
    /* extended codes (need EDNS) are accepted by AdGuard but unsupported here */
    static const char *const ext[] = {"BADSIG", "BADKEY", "BADTIME", "BADMODE", "BADNAME", "BADALG",
                                      "BADTRUNC", "BADCOOKIE"};
    for (size_t i = 0; i < DC_ARRAY_SIZE(ext); i++)
        if (strcmp(up, ext[i]) == 0) return 16 + (int)i;
    return -1;
}

int fl_name_from_wire(const uint8_t *wire, size_t wire_len, char *out, size_t cap) {
    size_t i = 0, o = 0;
    while (i < wire_len) {
        uint8_t l = wire[i++];
        if (l == 0) break;
        if (l > 63 || i + l > wire_len) return -1;
        if (o) {
            if (o + 1 >= cap) return -1;
            out[o++] = '.';
        }
        for (uint8_t k = 0; k < l; k++) {
            uint8_t b = wire[i + k];
            if (b == '.' || b == ' ' || b == '\'' || b == '@' || b == ';' || b == '(' || b == ')' ||
                b == '"' || b == '\\') {
                if (o + 2 >= cap) return -1;
                out[o++] = '\\';
                out[o++] = (char)b;
            } else if (b < ' ' || b > '~') {
                if (o + 4 >= cap) return -1;
                out[o++] = '\\';
                out[o++] = (char)('0' + b / 100);
                out[o++] = (char)('0' + (b / 10) % 10);
                out[o++] = (char)('0' + b % 10);
            } else {
                if (o + 1 >= cap) return -1;
                out[o++] = (char)dc_lower(b);
            }
        }
        i += l;
    }
    if (o >= cap) return -1;
    out[o] = 0;
    return (int)o;
}

int fl_name_to_wire(const char *name, size_t len, uint8_t *out, size_t cap) {
    size_t o = 0;
    if (len && name[len - 1] == '.' && !(len >= 2 && name[len - 2] == '\\')) len--;
    if (len == 0) {
        if (cap < 1) return -1;
        out[0] = 0;
        return 1;
    }
    size_t i = 0;
    while (i <= len) {
        size_t lpos = o++;
        if (lpos >= cap) return -1;
        unsigned l = 0;
        while (i < len && name[i] != '.') {
            uint8_t b = (uint8_t)name[i++];
            if (b == '\\' && i < len) {
                if (i + 2 < len + 0 && name[i] >= '0' && name[i] <= '9' && name[i + 1] >= '0' &&
                    name[i + 1] <= '9' && name[i + 2] >= '0' && name[i + 2] <= '9') {
                    unsigned v = (unsigned)(name[i] - '0') * 100 + (unsigned)(name[i + 1] - '0') * 10 +
                                 (unsigned)(name[i + 2] - '0');
                    if (v > 255) return -1;
                    b = (uint8_t)v;
                    i += 3;
                } else {
                    b = (uint8_t)name[i++];
                }
            }
            if (o >= cap || ++l > 63) return -1;
            out[o++] = b;
        }
        if (l == 0) return -1; /* empty label */
        out[lpos] = (uint8_t)l;
        if (i >= len) break;
        i++; /* '.' */
        if (i == len) return -1;
    }
    if (o >= cap || o + 1 > 255) return -1;
    out[o++] = 0;
    return (int)o;
}

size_t fl_reverse_name(const char *host, size_t n, char *out) {
    /* split on unescaped dots */
    uint16_t starts[128], ends[128];
    size_t nl = 0, st = 0;
    for (size_t i = 0; i < n; i++) {
        if (host[i] == '\\') {
            i += (i + 1 < n && host[i + 1] >= '0' && host[i + 1] <= '9') ? 3 : 1;
            continue;
        }
        if (host[i] == '.') {
            if (nl < 128) {
                starts[nl] = (uint16_t)st;
                ends[nl++] = (uint16_t)i;
            }
            st = i + 1;
        }
    }
    if (nl < 128) {
        starts[nl] = (uint16_t)st;
        ends[nl++] = (uint16_t)n;
    }
    size_t o = 0;
    for (size_t k = nl; k-- > 0;) {
        size_t l = ends[k] - starts[k];
        memcpy(out + o, host + starts[k], l);
        o += l;
        if (k) out[o++] = '.';
    }
    return o;
}

static const char *const k_ctags[FL_CTAG_COUNT] = {
    "device_audio",  "device_camera",        "device_gameconsole", "device_laptop", "device_nas",
    "device_other",  "device_pc",            "device_phone",       "device_printer",
    "device_securityalarm", "device_tablet", "device_tv",          "os_android",    "os_ios",
    "os_linux",      "os_macos",             "os_other",           "os_windows",    "user_admin",
    "user_child",    "user_regular",
};

int fl_ctag_from_name(const char *s, size_t n) {
    for (int i = 0; i < FL_CTAG_COUNT; i++)
        if (strlen(k_ctags[i]) == n && memcmp(k_ctags[i], s, n) == 0) return i;
    return -1;
}

const char *fl_ctag_name(int tag) { return tag >= 0 && tag < FL_CTAG_COUNT ? k_ctags[tag] : "?"; }

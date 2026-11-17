/* self-contained snprintf/vsnprintf for mbedtls debug output. */
#include <stdarg.h>
#include <stddef.h>

typedef struct { char *buf; size_t pos; size_t cap; } ob_t;

static void pch(ob_t *o, char c)
{
    if (o->pos < o->cap) o->buf[o->pos] = c;
    o->pos++;
}

static void pstr(ob_t *o, const char *s)
{
    if (s == 0) s = "(null)";
    while (*s) pch(o, *s++);
}

static void pnum(ob_t *o, unsigned long long v, unsigned int base, const char *digits)
{
    char tmp[24];
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v) { tmp[n++] = digits[v % base]; v /= base; }
    while (n) pch(o, tmp[--n]);
}

static int fmt(ob_t *o, const char *format, va_list *ap)
{
    const char *p = format;
    while (*p) {
        if (*p != '%') { pch(o, *p++); continue; }
        p++;
        if (*p == 0) break;
        if (*p == '%') { pch(o, '%'); p++; continue; }
        while (*p == '-' || *p == '+' || *p == ' ' || *p == '#') p++;
        if (*p == '0') p++;
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') { p++; while (*p >= '0' && *p <= '9') p++; }
        if (*p == 'l' || *p == 'h') p++;
        if (*p == 'd') {
            int v = va_arg(*ap, int);
            if (v < 0) { pch(o, '-'); v = -v; }
            pnum(o, (unsigned long long)(unsigned int)v, 10u, "0123456789");
            p++;
        } else if (*p == 'u') {
            pnum(o, (unsigned long long)va_arg(*ap, unsigned int), 10u, "0123456789");
            p++;
        } else if (*p == 'x') {
            pnum(o, (unsigned long long)va_arg(*ap, unsigned int), 16u, "0123456789abcdef");
            p++;
        } else if (*p == 'X') {
            pnum(o, (unsigned long long)va_arg(*ap, unsigned int), 16u, "0123456789ABCDEF");
            p++;
        } else if (*p == 'p') {
            unsigned long long v = (unsigned long long)(size_t)va_arg(*ap, void *);
            pch(o, '0'); pch(o, 'x');
            pnum(o, v, 16u, "0123456789abcdef");
            p++;
        } else if (*p == 'c') {
            pch(o, (char)(int)va_arg(*ap, int));
            p++;
        } else if (*p == 's') {
            pstr(o, va_arg(*ap, const char *));
            p++;
        } else {
            pch(o, '?');
            p++;
        }
    }
    return (int)o->pos;
}

int mbed_snprintf_impl(char *s, size_t n, const char *format, ...)
{
    va_list ap;
    ob_t o;
    int r;
    va_start(ap, format);
    o.buf = s; o.pos = 0; o.cap = n ? n - 1u : 0u;
    r = fmt(&o, format, &ap);
    if (n) { size_t t = (o.pos < n) ? o.pos : (n - 1u); s[t] = 0; }
    va_end(ap);
    return r;
}

int mbed_vsnprintf_impl(char *s, size_t n, const char *format, va_list ap)
{
    ob_t o;
    int r;
    o.buf = s; o.pos = 0; o.cap = n ? n - 1u : 0u;
    r = fmt(&o, format, &ap);
    if (n) { size_t t = (o.pos < n) ? o.pos : (n - 1u); s[t] = 0; }
    return r;
}

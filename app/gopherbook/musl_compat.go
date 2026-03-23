//go:build linux

package main

/*
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen) {
    (void)destlen; return memcpy(dest, src, len);
}
void *__memset_chk(void *dest, int c, size_t len, size_t destlen) {
    (void)destlen; return memset(dest, c, len);
}
void *__memmove_chk(void *dest, const void *src, size_t len, size_t destlen) {
    (void)destlen; return memmove(dest, src, len);
}
int __printf_chk(int flag, const char *fmt, ...) {
    (void)flag; va_list ap; va_start(ap, fmt); int r = vprintf(fmt, ap); va_end(ap); return r;
}
int __fprintf_chk(FILE *fp, int flag, const char *fmt, ...) {
    (void)flag; va_list ap; va_start(ap, fmt); int r = vfprintf(fp, fmt, ap); va_end(ap); return r;
}
int __vfprintf_chk(FILE *fp, int flag, const char *fmt, va_list ap) {
    (void)flag; return vfprintf(fp, fmt, ap);
}
int __snprintf_chk(char *str, size_t maxlen, int flag, size_t slen, const char *fmt, ...) {
    (void)flag; (void)slen; va_list ap; va_start(ap, fmt); int r = vsnprintf(str, maxlen, fmt, ap); va_end(ap); return r;
}
int __vsnprintf_chk(char *str, size_t maxlen, int flag, size_t slen, const char *fmt, va_list ap) {
    (void)flag; (void)slen; return vsnprintf(str, maxlen, fmt, ap);
}
ssize_t __read_chk(int fd, void *buf, size_t count, size_t buflen) {
    (void)buflen; return read(fd, buf, count);
}
long __sysconf(int name) {
    return sysconf(name);
}
*/
import "C"

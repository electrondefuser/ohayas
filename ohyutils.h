#ifndef _OHY_UTILS_H
#define _OHY_UTILS_H

#include "linux/kernel.h"
#include "linux/string.h"
#include "linux/sched.h"

__attribute__((unused)) 
static inline int ohy_strncmp(const char *s1, const char *s2, size_t n)
{
    if (n == 0)
        return (0);
    do {
        if (*s1 != *s2++)
            return (*(unsigned char *)s1 - *(unsigned char *)--s2);
        if (*s1++ == 0)
            break;
    } while (--n != 0);
    return (0);
}

__attribute__((unused))
static inline size_t ohy_strlen(const char *s)
{
    size_t len = 0;
    while(*s++) len++;
    return len;
}

__attribute__((unused))
static inline char* ohy_strstr(const char *s, const char *find)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0') {
        len = ohy_strlen(find);
        do {
            do {
                if ((sc = *s++) == '\0')
                    return 0;
            } while (sc != c);
        } while (ohy_strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}

__attribute__((unused))
static inline size_t ohy_strlcpy(char *dst, const char *src, size_t siz)
{
    char *d = dst;
    const char *s = src;
    size_t n = siz;

    if (n != 0) {
        while (--n != 0) {
            if ((*d++ = *s++) == '\0')
                break;
        }
    }

    if (n == 0) {
        if (siz != 0)
            *d = '\0';		/* NUL-terminate dst */
        while (*s++)
            ;
    }
    return(s - src - 1);
}

__attribute__((unused))
static inline int ohy_strends(const char* str, const char* suffix)
{
    size_t lenstr;
    size_t lensuffix;

    if (!str || !suffix)
        return 0;

    lenstr = ohy_strlen(str);
    lensuffix = ohy_strlen(suffix);
    if (lensuffix >  lenstr)
        return 0;
    return ohy_strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

__attribute__((unused))
static inline int ohy_get_proc_uid(void)
{
    const struct cred * m_cred = current_cred();
    kuid_t uid = m_cred->uid;
    int m_uid = uid.val;

    if(m_uid > 10000)
        return true;

    return false;
}

#endif
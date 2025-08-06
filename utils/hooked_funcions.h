#include <unistd.h>

#ifndef _HOOKED_FUNCTIONS_H
#define _HOOKED_FUNCTIONS_H

extern int (*real_write)(int fd, const void *buf, size_t count);
extern int (*real_read)(int fd, void *buf, size_t count);

#endif
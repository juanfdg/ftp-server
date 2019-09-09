#ifndef FTPSERVER_COMMON_H
#define FTPSERVER_COMMON_H

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void error(char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        fprintf(stderr, "%s: ", strerror(errno));
        vfprintf(stderr, fmt, args);
    } else {
        perror("");
    }
    va_end(args);
    exit(1);
}

#endif //FTPSERVER_COMMON_H

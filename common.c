#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"


void raise_error(char *client, char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        fprintf(stderr, "(ERROR)");
        if (client) {
            fprintf(stderr, "[%s]", client);
        }
        fprintf(stderr, " ");
        if (errno) {
            fprintf(stderr, "%s: ", strerror(errno));
        }
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
    } else {
        perror("");
    }
    exit(1);
}


void log_error(char *client, char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        fprintf(stderr, "(ERROR)");
        if (client) {
            fprintf(stderr, "[%s]", client);
        }
        fprintf(stderr, " ");
        if (errno) {
            fprintf(stderr, "%s: ", strerror(errno));
        }
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
    } else {
        perror("");
    }
    va_end(args);
}


void log_warning(char *client, char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        printf("WARNING");
        if (client) {
            printf("[%s]", client);
        }
        printf(" ");
        vprintf(fmt, args);
        printf("\n");
    } else {
        perror("");
    }
}


void log_info(char *client, char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        printf("INFO");
        if (client) {
            printf("[%s]", client);
        }
        printf(" ");
        vprintf(fmt, args);
        printf("\n");
    } else {
        perror("");
    }
}


void log_debug(char *client, char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        printf("DEBUG");
        if (client) {
            printf("[%s]", client);
        }
        printf(" ");
        vprintf(fmt, args);
        printf("\n");
    } else {
        perror("");
    }
}
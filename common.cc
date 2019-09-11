#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include "common.h"


void raise_error(const char*client, const char*fmt, ...) {
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


void log_error(const char*client, const char*fmt, ...) {
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


void log_warning(const char*client, const char*fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        printf("(WARNING)");
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


void log_info(const char*client, const char*fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        printf("(INFO)");
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


void log_debug(const char*client, const char*fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        printf("(DEBUG)");
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


int send_message(int sockfd, u_int8_t type, int session_id, std::string payload) {
    if (payload.length() > BUFFER_SIZE) {
        log_error(NULL, "Payload size bigger than buffer limit of %d bytes", BUFFER_SIZE);
        return -1;
    }
    message msg;
    msg.type = type;
    msg.session_id = session_id;
    msg.len = payload.length();
    strncpy(msg.payload, payload.c_str(), payload.length());
    int s_type = sizeof(msg.type),
        s_session_id = sizeof(msg.session_id),
        s_len = sizeof(msg.len),
        s_payload = sizeof(msg.payload);
    char *buf = (char*)malloc(s_type+s_session_id+s_len+s_payload);
    memcpy(buf, &msg.type, s_type);
    memcpy(buf+s_type, &msg.session_id, s_session_id);
    memcpy(buf+s_type+s_session_id, &msg.len, s_len);
    memcpy(buf+s_type+s_session_id+s_len, &msg.payload, s_payload);
    int n = write(sockfd, buf, sizeof(message));
    free(buf);
    return n;
}


int read_message(int sockfd, message *msg) {
    char *buf = (char*)malloc(sizeof(message));
    int n = read(sockfd, buf, sizeof(message));
    free(buf);
    int s_type = sizeof(msg->type),
        s_session_id = sizeof(msg->session_id),
        s_len = sizeof(msg->len),
        s_payload = sizeof(msg->payload);
    memcpy(&msg->type, buf, s_type);
    memcpy(&msg->session_id, buf+s_type, s_session_id);
    memcpy(&msg->len, buf+s_type+s_session_id, s_len);
    memcpy(&msg->payload, buf+s_type+s_session_id+s_len, s_payload);
    return n;
}


void broken_protocol(int sockfd){
    log_error(NULL, "Message received out of protocol");
    close(sockfd);
}
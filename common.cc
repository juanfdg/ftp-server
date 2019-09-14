#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include "common.h"


void raise_error(int session_id, const char*fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        fprintf(stderr, "(ERROR)");
        if (session_id > 0) {
            fprintf(stderr, "[%d]", session_id);
        }
        fprintf(stderr, " ");
        if (errno) {
            fprintf(stderr, "%s: ", strerror(errno));
            errno = 0;
        }
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
    } else {
        perror("");
    }
    exit(1);
}


void log_error(int session_id, const char*fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        fprintf(stderr, "(ERROR)");
        if (session_id > 0) {
            fprintf(stderr, "[%d]", session_id);
        }
        fprintf(stderr, " ");
        if (errno) {
            fprintf(stderr, "%s: ", strerror(errno));
            errno = 0;
        }
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
    } else {
        perror("");
    }
    va_end(args);
}


void log_warning(int session_id, const char*fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        printf("(WARNING)");
        if (session_id > 0) {
            printf("[%d]", session_id);
        }
        printf(" ");
        vprintf(fmt, args);
        printf("\n");
    } else {
        perror("");
    }
}


void log_info(int session_id, const char*fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        printf("(INFO)");
        if (session_id > 0) {
            printf("[%d]", session_id);
        }
        printf(" ");
        vprintf(fmt, args);
        printf("\n");
    } else {
        perror("");
    }
}


void log_debug(int session_id, const char*fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if(fmt) {
        printf("(DEBUG)");
        if (session_id > 0) {
            printf("[%d]", session_id);
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
        log_error(session_id, "Payload size bigger than buffer limit of %d bytes", BUFFER_SIZE);
        return -1;
    }
    message msg;
    bzero(&msg, sizeof(message));
    msg.type = type;
    msg.session_id = session_id;
    msg.len = payload.length();
    strncpy(msg.payload, payload.c_str(), payload.length());

    int s_type = sizeof(msg.type),
        s_session_id = sizeof(msg.session_id),
        s_len = sizeof(msg.len),
        s_payload = msg.len;
    int s_buf = s_type+s_session_id+s_len+s_payload;

    char *buf = (char*)malloc(s_buf);
    bzero(buf, s_buf);
    memcpy(buf, &msg.type, s_type);
    memcpy(buf+s_type, &msg.session_id, s_session_id);
    memcpy(buf+s_type+s_session_id, &msg.len, s_len);
    memcpy(buf+s_type+s_session_id+s_len, &msg.payload, s_payload);

    int n = write(sockfd, buf, s_buf);
    if (n < 0) {
        log_error(session_id, "Error writing to socket");
    }
    free(buf);
    return n;
}


int send_binary(int sockfd, u_int8_t type, int session_id, int len, const char *buf) {
    if (len > BUFFER_SIZE) {
        log_error(session_id, "Payload size bigger than buffer limit of %d bytes", BUFFER_SIZE);
        return -1;
    }
    message msg;
    bzero(&msg, sizeof(message));
    msg.type = type;
    msg.session_id = session_id;
    msg.len = len;
    memcpy(msg.payload, buf, len);

    int s_type = sizeof(msg.type),
        s_session_id = sizeof(msg.session_id),
        s_len = sizeof(msg.len),
        s_payload = len;
    int s_buf = s_type+s_session_id+s_len+s_payload;

    char *msg_buf = (char*)malloc(s_buf);
    bzero(msg_buf, s_buf);
    memcpy(msg_buf, &msg.type, s_type);
    memcpy(msg_buf+s_type, &msg.session_id, s_session_id);
    memcpy(msg_buf+s_type+s_session_id, &msg.len, s_len);
    memcpy(msg_buf+s_type+s_session_id+s_len, &msg.payload, s_payload);

    int n = write(sockfd, msg_buf, s_buf);
    printf("message:%d\n%s\n", msg_buf[0], msg_buf);
    if (n < 0) {
        log_error(session_id, "Error writing to socket");
    }
    free(msg_buf);
    return n;
}


int read_message(int sockfd, int session_id, message *msg) {
    bzero(msg, sizeof(message));
    char *buf = (char*)malloc(sizeof(message));
    bzero(buf, BUFFER_SIZE);

    int n = read(sockfd, buf, sizeof(message));
    if (n < 0) {
        log_error(session_id, "Error reading from socket");
        free(buf);
        return n;
    }

    int s_type = sizeof(msg->type),
        s_session_id = sizeof(msg->session_id),
        s_len = sizeof(msg->len),
        s_payload = sizeof(msg->payload);
    memcpy(&msg->type, buf, s_type);
    memcpy(&msg->session_id, buf+s_type, s_session_id);
    memcpy(&msg->len, buf+s_type+s_session_id, s_len);
    memcpy(&msg->payload, buf+s_type+s_session_id+s_len, s_payload);
    printf("%d\n", msg->type);
    free(buf);
    return n;
}


void broken_protocol(int sockfd, int session_id){
    log_error(session_id, "Message received out of protocol");
    close(sockfd);
}
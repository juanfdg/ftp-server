#ifndef FTPSERVER_COMMON_H
#define FTPSERVER_COMMON_H

#define BUFFER_SIZE 1000

#include <stdint.h>

/* Protocol */
enum MessageType {
    // Connection management
    OPEN_REQUEST,
    OPEN_ACCEPT,
    OPEN_REFUSE,
    CLOSE,

    // Navigation and listing of directories
    CD_REQUEST,
    CD_ACCEPT,
    CD_REFUSE,
    LS_REQUEST,
    LS_ACCEPT,
    LS_REFUSE,
    PWD_REQUEST,
    PWD_REPLY,

    // Directory manipulation
    MK_REQUEST,
    MK_ACCEPT,
    MK_REFUSE,
    RM_REQUEST,
    RM_ACCEPT,
    RM_REFUSE,

    // File manipulation
    GET_REQUEST,
    GET_REFUSE,

    PUT_REQUEST,
    PUT_ACCEPT,
    PUT_REFUSE,
    PUT_WARN,
    PUT_CONFIRM,
    PUT_ABORT,

    DEL_REQUEST,
    DEL_ACCEPT,
    DEL_REFUSE,

    TRANSFER_REQUEST,
    TRANSFER_OK,
    TRANSFER_ERROR,
    TRANSFER_END
};

struct message {
    uint8_t type;
    uint16_t session_id;
    uint16_t len;
    char payload[BUFFER_SIZE];
};
typedef struct message message;

int send_message(int sockfd, u_int8_t type, uint16_t session_id, std::string payload);
int send_binary(int sockfd, u_int8_t type, uint16_t session_id, uint16_t len, const char *buf);
int read_message(int sockfd, uint16_t session_id, message *msg);
void broken_protocol(int sockfd, uint16_t session_id);


/* Logging */
void raise_error(uint16_t session_id, const char *fmt, ...);
void log_error(uint16_t session_id, const char *fmt, ...);
void log_warning(uint16_t session_id, const char *fmt, ...);
void log_info(uint16_t session_id, const char *fmt, ...);

#endif //FTPSERVER_COMMON_H

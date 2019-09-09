#ifndef FTPSERVER_COMMON_H
#define FTPSERVER_COMMON_H

#define BUFFER_SIZE 100000

/* Logging */
void raise_error(char *client, char *fmt, ...);
void log_error(char *client, char *fmt, ...);
void log_warning(char *client, char *fmt, ...);
void log_info(char *client, char *fmt, ...);
void log_debug(char *client, char *fmt, ...);


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

    // Directory manipulation
    MK_REQUEST,
    MK_ACCEPT,
    MK_REFUSE,
    RM_REQUEST,
    RM_ACCEPT,
    RM_REFUSE,

    // File manipulation
    PUT_INIT_REQUEST,
    PUT_INIT_ACCEPT,
    PUT_INIT_REFUSE,

    GET_INIT_REQUEST,
    GET_INIT_REFUSE,

    TRANSFER_REQUEST,
    TRANSFER_OK,
    TRANSFER_ERROR,
    TRANSFER_END_REQUEST,
    TRANSFER_END_ACCEPT,
    TRANSFER_END_ERROR,
};

struct message {
    size_t size;
    __uint8_t type;
    char *payload;
};

#endif //FTPSERVER_COMMON_H

#ifndef FTPSERVER_COMMON_H
#define FTPSERVER_COMMON_H

#define BUFFER_SIZE 10000

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
    GET_INIT_REQUEST,
    GET_INIT_REFUSE,

    PUT_INIT_REQUEST,
    PUT_INIT_ACCEPT,
    PUT_INIT_REFUSE,

    DEL_REQUEST,
    DEL_ACCEPT,
    DEL_REFUSE,

    TRANSFER_REQUEST,
    TRANSFER_OK,
    TRANSFER_ERROR,
    TRANSFER_END_REQUEST,
    TRANSFER_END_ACCEPT,
    TRANSFER_END_ERROR,
};

struct message {
    u_int8_t type;
    int session_id;
    int len;
    char payload[BUFFER_SIZE];
};
typedef struct message message;

int send_message(int sockfd, u_int8_t type, int session_id, std::string payload);
int read_message(int sockfd, int session_id, message *msg);
void broken_protocol(int sockfd, int session_id);


/* Logging */
void raise_error(int session_id, const char *fmt, ...);
void log_error(int session_id, const char *fmt, ...);
void log_warning(int session_id, const char *fmt, ...);
void log_info(int session_id, const char *fmt, ...);
void log_debug(int session_id, const char *fmt, ...);

#endif //FTPSERVER_COMMON_H

#ifndef FTPSERVER_COMMON_H
#define FTPSERVER_COMMON_H

/* Logging */
void raise_error(char *client, char *fmt, ...);
void log_error(char *client, char *fmt, ...);
void log_warning(char *client, char *fmt, ...);
void log_info(char *client, char *fmt, ...);
void log_debug(char *client, char *fmt, ...);



#endif //FTPSERVER_COMMON_H

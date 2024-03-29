#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <iostream>
#include <fstream>
#include <string>

#include "common.h"

#define SUCCESS 1
#define FAIL -1
#define QUIT 0

#define DOT_FREQUENCY 100000

// Network variables
int sockfd, portno;
struct sockaddr_in serv_addr;
struct hostent *server;
uint16_t session_id;

// Get user input
int get_input();

// Connection management
void open_session(std::string hostname);
void close_session();

// Directories navigation and listing
void change_dir(std::string path);
void list_files(std::string path);
void get_pwd();

// Directories manipulation
void make_dir(std::string path);
void remove_dir(std::string path);

// File manipulation
void get_file(std::string path);
void put_file(std::string path);
void delete_file(std::string path);


int main(int argc, char *argv[]) {
    while(get_input() != QUIT);
    return 0;
}


int get_input() {
    printf(">>> ");
    std::string input, command, arg;
    std::getline(std::cin, input);
    *input.end() = '\0';
    // Separate command from argument
    int pos = input.find(' ');
    command = input.substr(0, pos);
    if (pos > 0) {
        arg = input.substr(pos + 1);
    }

    if(command == "open") {
        if (arg.empty()) {
            log_error(0, "Usage: open <server>");
            return FAIL;
        }
        open_session(arg);
        return SUCCESS;
    } else if (command == "close") {
        close_session();
        return SUCCESS;
    } else if (command == "cd") {
        if (arg.empty()) {
            log_error(0, "Usage: cd <dirname>");
            return FAIL;
        }
        change_dir(arg);
    } else if (command == "ls") {
        if (arg.empty()) {
            list_files(".");
            return FAIL;
        } else {
            list_files(arg);
        }
        return SUCCESS;
    } else if (command == "pwd") {
        get_pwd();
    } else if (command == "mkdir") {
        if (arg.empty()) {
            log_error(0, "Usage: mkdir <dirname>");
            return FAIL;
        }
        make_dir(arg);
        return SUCCESS;
    } else if (command == "rmdir") {
        if (arg.empty()) {
            log_error(0, "Usage: rmdir <dirname>");
            return FAIL;
        }
        remove_dir(arg);
        return SUCCESS;
    } else if (command == "get") {
        if (arg.empty()) {
            log_error(0, "Usage: get <dirname>");
            return FAIL;
        }
        get_file(arg);
        return SUCCESS;
    } else if (command == "put") {
        if (arg.empty()) {
            log_error(0, "Usage: put <dirname>");
            return FAIL;
        }
        put_file(arg);
        return SUCCESS;
    } else if (command == "delete") {
        if (arg.empty()) {
            log_error(0, "Usage: delete <dirname>");
            return FAIL;
        }
        delete_file(arg);
        return SUCCESS;
    } else if (command == "quit") {
        close_session();
        return QUIT;
    } else {
        log_error(0, "Command %s not recognized", command.c_str());
        return FAIL;
    }
}


void open_session(std::string hostname) {
    // Can't open if already in session
    if (session_id != 0) {
        log_error(0, "Already in a open session");
        return;
    }

    // Resolving server address
    server = gethostbyname(hostname.c_str());
    if (server == NULL) {
        log_error(0, "No host %s", hostname.c_str());
        return;
    }
    portno = 2121;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error(0, "Could not open socket");
        return;
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);
    serv_addr.sin_port = htons(portno);

    // Connect to server
    if (connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0) {
        log_error(0, "Could not connect to %s:%d", hostname.c_str(), portno);
        return;
    } else {
        log_info(0, "Connected to %s:%d", hostname.c_str(), portno);
    }


    // Request user and password
    std::string user, password, payload;
    printf("username: ");
    std::getline(std::cin, user);
    printf("password: ");
    std::getline(std::cin, password);
    payload = user + "\n" + password;
    // Send open session request
    int n;
    n = send_message(sockfd, OPEN_REQUEST, 0, payload);
    if (n < 0) {
        log_error(0, "Error writing to socket");
        return;
    }

    // Receive response from server
    message msg;
    read_message(sockfd, 0, &msg);

    if (msg.type == OPEN_REFUSE) {
        log_error(0, "Connection refused: %s", msg.payload);
        close(sockfd);
    } else if (msg.type == OPEN_ACCEPT) {
        log_info(0, "Connection accepted. Session ID: %d", msg.session_id);
        session_id = msg.session_id;
    } else {
        broken_protocol(sockfd, 0);
    }
}


void close_session() {
    log_info(0, "Session closed");
    send_message(sockfd, CLOSE, 0, "");
    close(sockfd);
    session_id = 0;
}


void change_dir(std::string path) {
    send_message(sockfd, CD_REQUEST, 0, path);
    message msg;
    read_message(sockfd, 0, &msg);

    if (msg.type == CD_REFUSE) {
        log_error(0, "%s", msg.payload);
    } else if (msg.type == CD_ACCEPT) {
        log_info(0, "Changed dir: %s", msg.payload);
    } else {
        broken_protocol(sockfd, 0);
    }
}


void list_files(std::string path) {
    send_message(sockfd, LS_REQUEST, 0, path);
    message msg;
    read_message(sockfd, 0, &msg);

    if (msg.type == LS_REFUSE) {
        log_error(0, "%s", msg.payload);
    } else if (msg.type == LS_ACCEPT) {
        log_info(0, "Dir contents:\n%s", msg.payload);
    } else {
        broken_protocol(sockfd, 0);
    }
}


void get_pwd() {
    send_message(sockfd, PWD_REQUEST, 0, "");
    message msg;
    read_message(sockfd, 0, &msg);
    if (msg.type == PWD_REPLY) {
        log_info(0, "Current dir: %s", msg.payload);
    } else {
        broken_protocol(sockfd, 0);
    }
}


void make_dir(std::string path) {
    send_message(sockfd, MK_REQUEST, 0, path);
    message msg;
    read_message(sockfd, 0, &msg);

    if (msg.type == MK_REFUSE) {
        log_error(0, "%s", msg.payload);
    } else if (msg.type == MK_ACCEPT) {
        log_info(0, "Created dir: %s", msg.payload);
    } else {
        broken_protocol(sockfd, 0);
    }
}


void remove_dir(std::string path) {
    send_message(sockfd, RM_REQUEST, 0, path);
    message msg;
    read_message(sockfd, 0, &msg);

    if (msg.type == RM_REFUSE) {
        log_error(0, "%s", msg.payload);
    } else if (msg.type == RM_ACCEPT) {
        log_info(0, "Removed dir: %s", msg.payload);
    } else {
        broken_protocol(sockfd, 0);
    }
}


void get_file(std::string path) {
    path = "./" + path;
    FILE *file = fopen(path.c_str(), "w");
    if (file == NULL) {
        log_error(0, "Could not open file");
        return;
    }
    send_message(sockfd, GET_REQUEST, 0, path);
    int n;
    message msg;
    read_message(sockfd, 0, &msg);
    if (msg.type == GET_REFUSE) {
        log_error(0, msg.payload);
    } else {
        log_info(0, "Receiving remote file");
        int chunks = 0;
        while (msg.type == TRANSFER_REQUEST) {
            n = fwrite(msg.payload, msg.len, 1, file);
            fseek(file, 0, SEEK_END);
            if (n == EOF && errno != 0) {
                send_message(sockfd, TRANSFER_ERROR, 0, "Error writing to file");
                log_error(0, "Error writing to file");
                fclose(file);
                return;
            } else {
                if (chunks == 0) {
                    printf(".");
                    fflush(stdout);
                }
                chunks = (chunks + 1) % DOT_FREQUENCY;
                send_message(sockfd, TRANSFER_OK, 0, "");
                read_message(sockfd, 0, &msg);
            }
        }
        if (msg.type == TRANSFER_END) {
            printf("\n");
            log_info(0, "File transmission ended");
        } else if (msg.type == TRANSFER_ERROR) {
            log_error(0, msg.payload);
        } else {
            broken_protocol(sockfd, 0);
        }
    }
    fclose(file);
}


void put_file(std::string path) {
    path = "./" + path;
    FILE *file = fopen(path.c_str(), "r");
    if (file == NULL) {
        log_error(0, "Could not open file");
        return;
    }
    send_message(sockfd, PUT_REQUEST, 0, path);
    message response;
    read_message(sockfd, 0, &response);
    if (response.type == PUT_WARN) {
        log_warning(0, "Remote file already exists. Would you like to overwrite?(y/N)");
        char resp;
        scanf("%c", &resp);
        getchar(); // Consume new line
        if (resp == 'y' || resp == 'Y') {
            send_message(sockfd, PUT_CONFIRM, 0, "");
            read_message(sockfd, 0, &response);
        } else {
            send_message(sockfd, PUT_ABORT, 0, "");
            fclose(file);
            return;
        }
    }

    if (response.type == PUT_REFUSE) {
        log_error(0, response.payload);
        fclose(file);
        return;
    } else if (response.type == PUT_ACCEPT) {
        log_info(0, "Sending local file");
    } else {
        broken_protocol(sockfd, 0);
        fclose(file);
        return;
    }

    char file_buf[BUFFER_SIZE];
    int n, chunks = 0;
    while ((n = fread(file_buf, 1, BUFFER_SIZE, file)) > 0) {
        send_binary(sockfd, TRANSFER_REQUEST, 0, n, file_buf);
        read_message(sockfd, 0, &response);
        if (response.type == TRANSFER_ERROR) {
            log_error(0, response.payload);
            fclose(file);
            return;
        } else if (response.type == TRANSFER_OK) {
            if (chunks == 0) {
                printf(".");
                fflush(stdout);
            }
            chunks = (chunks + 1) % DOT_FREQUENCY;
        } else {
            broken_protocol(sockfd, 0);
            fclose(file);
            return;
        }
    }

    if (ferror(file)) {
        std::string pld = "Error reading from file";
        log_error(0, pld.c_str());
        send_message(sockfd, TRANSFER_ERROR, 0, pld);
    } else {
        printf("\n");
        log_info(0, "File transmission ended");
        send_message(sockfd, TRANSFER_END, 0, "");
    }
    fclose(file);
}


void delete_file(std::string path) {
    send_message(sockfd, DEL_REQUEST, 0, path);
    message msg;
    read_message(sockfd, 0, &msg);

    if (msg.type == DEL_REFUSE) {
        log_error(0, "%s", msg.payload);
    } else if (msg.type == DEL_ACCEPT) {
        log_info(0, "Removed file: %s", msg.payload);
    } else {
        broken_protocol(sockfd, 0);
    }
}

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

// General use variables
std::string pwd;
int session_id;

// Network variables
int sockfd, portno;
struct sockaddr_in serv_addr;
struct hostent *server;

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


int main(int argc, char *argv[]) {
    session_id = 0;
    while(get_input() != QUIT);
    return 0;
}


int get_input() {
    std::string input, command, arg;
    std::getline(std::cin, input);
    // Separate command from argument
    int pos = input.find(' ');
    command = input.substr(0, pos);
    arg = input.substr(pos+1);

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
        remove_dir(arg);
        return SUCCESS;
    } else if (command == "put") {
        if (arg.empty()) {
            log_error(0, "Usage: put <dirname>");
            return FAIL;
        }
        remove_dir(arg);
        return SUCCESS;
    } else if (command == "delete") {
        if (arg.empty()) {
            log_error(0, "Usage: delete <dirname>");
            return FAIL;
        }
        remove_dir(arg);
        return SUCCESS;
    } else if (command == "quit") {
            close_session();
            return QUIT;
    } else {
        log_error(session_id, "Command %s not recognized", command.c_str());
        return FAIL;
    }
}


void open_session(std::string hostname) {
    // Resolving server address
    server = gethostbyname(hostname.c_str());
    if (server == NULL) {
        log_error(session_id, "No host %s", hostname.c_str());
        return;
    }
    portno = 2121;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error(session_id, "Couldn't open socket");
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
        log_error(0, "Couldn't connect to %s:%d", hostname.c_str(), portno);
        return;
    } else {
        log_info(session_id, "Connected to %s:%d", hostname.c_str(), portno);
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
        log_error(session_id, "Error writing to socket");
        return;
    }

    // Receive response from server
    message msg;
    read_message(sockfd, session_id, &msg);

    if (msg.type == OPEN_REFUSE) {
        log_error(session_id, "Connection refused: %s", msg.payload);
        close(sockfd);
    } else if (msg.type == OPEN_ACCEPT) {
        log_info(session_id, "Connection accepted. Session ID: %d", msg.session_id);
        pwd = "/";
    } else {
        broken_protocol(sockfd, 0);
    }
}


void close_session() {
    log_info(session_id, "Session closed");
    send_message(sockfd, CLOSE, session_id, "");
    close(sockfd);
    session_id = 0;
    pwd = "/";
}


void change_dir(std::string path) {
    send_message(sockfd, CD_REQUEST, session_id, path);
    message msg;
    read_message(sockfd, session_id, &msg);

    if (msg.type == CD_REFUSE) {
        log_error(session_id, "%s", msg.payload);
    } else if (msg.type == CD_ACCEPT) {
        log_info(session_id, "Changed dir: %s", msg.payload);
        pwd = msg.payload;
    } else {
        broken_protocol(sockfd, 0);
    }
}


void list_files(std::string path) {
    send_message(sockfd, LS_REQUEST, session_id, path);
    message msg;
    read_message(sockfd, session_id, &msg);

    if (msg.type == LS_REFUSE) {
        log_error(session_id, "%s", msg.payload);
    } else if (msg.type == LS_ACCEPT) {
        log_info(session_id, "Dir contents:\n%s", msg.payload);
    } else {
        broken_protocol(sockfd, 0);
    }
}


void get_pwd() {
    send_message(sockfd, PWD_REQUEST, session_id, "");
    message msg;
    read_message(sockfd, session_id, &msg);
    if (msg.type == PWD_REPLY) {
        log_info(session_id, "Current dir: %s", msg.payload);
    } else {
        broken_protocol(sockfd, 0);
    }
}


void make_dir(std::string path) {
    send_message(sockfd, MK_REQUEST, session_id, path);
    message msg;
    read_message(sockfd, session_id, &msg);

    if (msg.type == MK_REFUSE) {
        log_error(session_id, "%s", msg.payload);
    } else if (msg.type == MK_ACCEPT) {
        log_info(session_id, "Created dir: %s", msg.payload);
    } else {
        broken_protocol(sockfd, 0);
    }
}


void remove_dir(std::string path) {
    send_message(sockfd, RM_REQUEST, session_id, path);
    message msg;
    read_message(sockfd, session_id, &msg);

    if (msg.type == RM_REFUSE) {
        log_error(session_id, "%s", msg.payload);
    } else if (msg.type == RM_ACCEPT) {
        log_info(session_id, "Removed dir: %s", msg.payload);
    } else {
        broken_protocol(sockfd, 0);
    }
}
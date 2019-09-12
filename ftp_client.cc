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

int sockfd, portno;
struct sockaddr_in serv_addr;
struct hostent *server;

// Get user input
int get_input();

// Connection management
void open_session(const char *hostname);
void close_session();

int main(int argc, char *argv[]) {
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
            log_error(NULL, "Usage: open <server>");
            return FAIL;
        }
        open_session(arg.c_str());
        return SUCCESS;
    } else if(command == "close") {
        close_session();
        return SUCCESS;
    } else if(command == "quit") {
        return QUIT;
    } else {
        log_error(NULL, "Command %s not recognized", command.c_str());
        return FAIL;
    }
}


void open_session(const char *hostname) {
    // Resolving server address
    server = gethostbyname(hostname);
    if (server == NULL) {
        log_error(NULL, "No host %s", hostname);
        return;
    }
    portno = 2121;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        log_error(NULL, "Couldn't open socket");
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
        log_error(NULL, "Couldn't connect to %s:%d", hostname, portno);
        return;
    } else {
        log_info(NULL, "Connected to %s:%d", hostname, portno);
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
        log_error(NULL, "Error writing to socket");
        return;
    }

    // Receive response from server
    message msg;
    n = read_message(sockfd, &msg);
    if (n < 0) {
        log_error(NULL, "Error reading from socket");
        return;
    }
    if (msg.type == OPEN_REFUSE) {
        log_error(NULL, "Connection refused: %s", msg.payload);
        close(sockfd);
    } else if (msg.type == OPEN_ACCEPT) {
        log_info(NULL, "Connection accepted. Session ID: %d", msg.session_id);
    } else {
        broken_protocol(sockfd);
    }
}


void close_session(){
    int n;
    n = send_message(sockfd, CLOSE, 0, "");
    if (n < 0) {
        log_error(NULL, "Error writing to socket");
        return;
    }
    log_info("123", "Session closed");
    close(sockfd);
}


#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"

#define COMMAND_LEN 100

int sockfd, portno;
struct sockaddr_in serv_addr;
struct hostent *server;
char buffer[BUFFER_SIZE];

// Get user input
int get_input();

// Connection management
void open_section(char *hostname);
void close_section();

int main(int argc, char *argv[]) {
    while(get_input());
    return 0;
}


int get_input() {
    char command[COMMAND_LEN];
    char *arg = NULL;
    fgets(command,COMMAND_LEN-1,stdin);
    int i;
    // Separate command from argument
    for (i = 0; command[i]!='\0'; i++) {
        if(command[i+1] == ' ') {
            command[i+1] = '\0';
            if(i+1 < COMMAND_LEN) {
                arg = &command[i+2];
            }
        } else if (command[i+1] == '\n' || command[i+1] == EOF){
            command[i+1] = '\0';
        }
    }
    // Format arg string to end at first space
    if (arg != NULL) {
        sscanf(arg, "%s", arg);
    }

    if(strcmp(command, "open") == 0) {
        if (arg == NULL) {
            log_error(NULL, "Usage: open <server>");
            return -1;
        }

        open_section(arg);
    } else if(strcmp(command, "close") == 0) {
        close_section();
    } else if(strcmp(command, "quit") == 0) {
        return 0;
    } else {
        log_error(NULL, "Command %s not recognized", command);
        return -1;
    }
}

void open_section(char *hostname) {
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
    if (connect(sockfd, &serv_addr, sizeof(serv_addr)) < 0) {
        log_error(NULL, "Couldn't connect to %s:%d", hostname, portno);
        return;
    } else {
        log_info(NULL, "Connected to %s:%d", hostname, portno);
    }

    // Send and receive messages
    int n;
    fgets(buffer,BUFFER_SIZE-1,stdin);
    n = write(sockfd, buffer, strlen(buffer));
    if (n < 0) {
        log_error(NULL, "Error writing to socket");
        return;
    }
    bzero(buffer,BUFFER_SIZE);
    n = read(sockfd, buffer, strlen(buffer));
    if (n < 0) {
        log_error(NULL, "Error reading from socket");
        return;
    }
    log_info(NULL, "Reply received: %s\n", buffer);
}


void close_section(){
    close(sockfd);
}
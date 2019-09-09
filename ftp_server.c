#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <pwd.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "common.h"

#define BASE_PATH_LEN 100

const char *BASE_DIR_FROM_HOME = "/ftp";
int sockfd, newsockfd, portno;
struct sockaddr_in serv_addr, cli_addr;
socklen_t clilen;
char buffer[BUFFER_SIZE];

/* File system auxiliar functions */
// Base directories
void get_base_dir(char *base_path, int len);

int main() {
    // Determine base directory for all users
    char base_path[BASE_PATH_LEN];
    get_base_dir(base_path, BASE_PATH_LEN);
    log_info(NULL, "Base directory at: %s", base_path);

    // Open socket with AF_INET family and TCP protocol
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        raise_error(NULL, "Couldn't open socket");

    // Bind socket to internet server address
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 2121;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        raise_error(NULL, "Couldn't bind socket to address %s:%d", inet_ntoa(serv_addr.sin_addr), portno);
    else
        log_info(NULL, "Server listening at %s:%d", inet_ntoa(serv_addr.sin_addr), portno);

    // Listen for connections with backlog queue size set to 5
    listen(sockfd,5);

    // Handle SIGCHILD to prevent zombie child processes
    signal(SIGCHLD, SIG_IGN);

    // Main loop for base server process
    while (1) {
        // Block until receive a connection request to accept
        clilen = sizeof(cli_addr);
        bzero((char *) &cli_addr, clilen);
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0)
            raise_error(NULL, "Couldn't accept new connection");
        if (fork() == 0) {
            log_info(NULL, "Accepted connection from: %s:%d", inet_ntoa(cli_addr.sin_addr), cli_addr.sin_port);
            break;
        }
        else
            close(newsockfd);
    }

    // Read messages from client at child process
    int n;
    bzero(buffer, BUFFER_SIZE+1);
    n = read(newsockfd,buffer,BUFFER_SIZE);
    if (n < 0)
        raise_error(NULL, "Error reading from socket");
    log_info(NULL, "Message received: %s", buffer);
    sprintf(buffer, "message received");
    n = write(newsockfd,buffer,BUFFER_SIZE);
    if (n < 0)
        raise_error(NULL, "Error writing to socket");
    else
        log_info(NULL, "Sent message: %s", buffer);

    return 0;
}


void get_base_dir(char *base_path, int len) {
    struct passwd* pw = getpwuid(getuid());
    const char *home_dir = pw->pw_dir;
    strncpy(base_path, home_dir, len);
    strncat(base_path, BASE_DIR_FROM_HOME, len);
    base_path[len] = '\0';
    DIR *base_dir = opendir(base_path);
    if (base_dir) {
        closedir(base_dir);
    } else if (errno == ENOENT) {
        int pid = fork();
        if (pid > 0) {
            waitpid(pid, NULL, 0);
        } else {
            char *args[] = {"mkdir", "-p", base_path, NULL};
            execv("/bin/mkdir", args);
        }
    }
}

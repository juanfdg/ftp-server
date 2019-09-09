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


const char *BASE_DIR_FROM_HOME = "/ftp";

/* File system auxiliar functions */
// Base directories
void get_base_dir(char *base_path);

int main() {
    // Determine base directory for all users
    char base_path[100];
    get_base_dir(base_path);
    log_info(NULL, "Base directory at: %s", base_path);

    // Sockets initialization
    int sockfd, newsockfd, portno;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;

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
        raise_error(NULL, "Couldn't bind socket to address %d:%d", serv_addr.sin_addr.s_addr, serv_addr.sin_port);
    else
        log_info(NULL, "Server listening at %d:%d", serv_addr.sin_addr.s_addr, portno);

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
            log_info(NULL, "Accepted connection from: %d:%d", cli_addr.sin_addr.s_addr, cli_addr.sin_port);
            break;
        }
        else
            close(newsockfd);
    }

    // Read messages from client at child process
    char buffer[100000]; //Maximum of 100MB per message
    int n;
    bzero(buffer, 100001);
    n = read(newsockfd,buffer,100000);
    if (n < 0)
        raise_error(NULL, "Error reading from socket");
    log_info("Message received: %s", buffer);
    sprintf(buffer, "message received");
    n = write(newsockfd,buffer,100000);
    if (n < 0)
        raise_error(NULL, "Error reading from socket");

    return 0;
}


void get_base_dir(char *base_path) {
    struct passwd* pw = getpwuid(getuid());
    const char *home_dir = pw->pw_dir;
    strcpy(base_path, home_dir);
    strcat(base_path, BASE_DIR_FROM_HOME);
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

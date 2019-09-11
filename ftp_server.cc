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
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <vector>

#include <iostream>

#include "common.h"

const std::string BASE_DIR_FROM_HOME("/ftp");
int sockfd, newsockfd, portno;
struct sockaddr_in serv_addr, cli_addr;
socklen_t clilen;

/* File system auxiliar functions */
// Base directories
std::string get_base_dir();

/* Connection management */
void open(const char *payload);


int main() {
    // Determine base directory for all users
    std::string base_path = get_base_dir();
    log_info(NULL, "Base directory at: %s", base_path.c_str());

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
            close(sockfd);
            sockfd = newsockfd;
            break;
        }
        else
            close(newsockfd);
    }

    // Read client messages loop
    while (1) {
        int n;
        message msg;
        n = read_message(sockfd, &msg);
        if (n < 0)
            raise_error(NULL, "Error reading from socket");
        if (msg.type == OPEN_REQUEST) {
            open(msg.payload);
        } else if (msg.type == CLOSE) {
            log_info(NULL, "Session %d closed", 123);
            close(sockfd);
            break;
        } else {
            broken_protocol(sockfd);
            exit(1);
        }
    }

    return 0;
}


std::string get_base_dir() {
    std::string base_path;
    struct passwd* pw = getpwuid(getuid());
    base_path =  std::string(pw->pw_dir) + BASE_DIR_FROM_HOME;
    DIR *base_dir = opendir(base_path.c_str());
    if (base_dir) {
        closedir(base_dir);
    } else if (errno == ENOENT) {
        int pid = fork();
        if (pid > 0) {
            waitpid(pid, NULL, 0);
        } else {
            char * args[] = {"mkdir", "-p", NULL, NULL};
            args[2] = (char*)base_path.c_str();
            execv("/bin/mkdir", args);
        }
    }
    return base_path;
}


void open(const char *payload) {
    // Parse user and password
    std::string pld, user, passwd;
    pld = payload;
    int pos = pld.find('\n');
    user = pld.substr(0, pos);
    passwd = pld.substr(pos+1);

    // Authentication
    if (user == "simba" && passwd == "123") {
        int session_id = 123;
        send_message(sockfd, OPEN_ACCEPT, session_id, "");
        log_info("123", "Opened new session: %d", session_id);
    } else {
        char pld[] = "Username or password incorrect";
        log_error(NULL, "%s", pld);
        send_message(sockfd, OPEN_REFUSE, 0, pld);
        close(sockfd);
    }
}
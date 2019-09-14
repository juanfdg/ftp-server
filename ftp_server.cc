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
#include <vector>

#include <iostream>
#include <string>
#include <vector>

#include "common.h"

// General use variables
const std::string BASE_DIR_FROM_HOME("/ftp");
std::string base_path;
std::vector<std::string> pwd;
int session_id;

// Network variables
int sockfd, portno;
struct sockaddr_in serv_addr, cli_addr;
socklen_t clilen;

/* File system auxiliar functions */
// Base directories
void get_base_dir();

/* Connection management */
void open(std::string payload);

/* Directories navigation and listing */
void change_dir(std::string payload);
void list_files(std::string payload);
std::string get_pwd();


int main() {
    session_id = 0;

    // Determine base directory for all users
    get_base_dir();
    log_info(session_id, "Base directory at: %s", base_path.c_str());

    // Open socket with AF_INET family and TCP protocol
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        raise_error(session_id, "Couldn't open socket");

    // Bind socket to internet server address
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 2121;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        raise_error(session_id, "Couldn't bind socket to address %s:%d", inet_ntoa(serv_addr.sin_addr), portno);
    else
        log_info(session_id, "Server listening at %s:%d", inet_ntoa(serv_addr.sin_addr), portno);

    // Listen for connections with backlog queue size set to 5
    listen(sockfd,5);

    // Handle SIGCHILD to prevent zombie child processes
    signal(SIGCHLD, SIG_IGN);

    // Main loop for base server process
    while (1) {
        // Block until receive a connection request to accept
        clilen = sizeof(cli_addr);
        bzero((char *) &cli_addr, clilen);
        int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0)
            raise_error(session_id, "Couldn't accept new connection");
        if (fork() == 0) {
            log_info(session_id, "Accepted connection from: %s:%d", inet_ntoa(cli_addr.sin_addr), cli_addr.sin_port);
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
        n = read_message(sockfd, session_id, &msg);
        if (n < 0)
            raise_error(session_id, "Error reading from socket");
        if (msg.type == OPEN_REQUEST) {
            open(msg.payload);
        } else if (msg.type == CLOSE) {
            log_info(session_id, "Session %d closed", 123);
            close(sockfd);
            break;
        } else if (msg.type == CD_REQUEST) {
            change_dir(msg.payload);
        } else if (msg.type == LS_REQUEST) {
            list_files(msg.payload);
        } else if (msg.type == PWD_REQUEST) {
            send_message(sockfd, PWD_REPLY, session_id, get_pwd());
        } else {
            broken_protocol(sockfd);
            exit(1);
        }
    }

    return 0;
}


void get_base_dir() {
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
}


void open(std::string payload) {
    // Parse user and password
    std::string user, passwd;
    int pos = payload.find('\n');
    user = payload.substr(0, pos);
    passwd = payload.substr(pos+1);

    // Authentication
    if (user == "simba" && passwd == "123") {
        session_id = 123;
        send_message(sockfd, OPEN_ACCEPT, session_id, "");
        log_info(session_id, "Opened new session: %d", session_id);
    } else {
        char pld[] = "Username or password incorrect";
        log_error(session_id, "%s", pld);
        send_message(sockfd, OPEN_REFUSE, 0, pld);
        exit(1);
    }
}


std::string get_pwd() {
    std::string pwd_str = "~";
    for (int i = 0; i < pwd.size(); ++i) {
        pwd_str += "/" + pwd[i];
    }
    return pwd_str;
}


void change_dir(std::string payload) {
    std::string clean_path, substr;
    std::vector<std::string> new_pwd = pwd;
    int ini, end;
    ini = end = 0;
    while (end != -1 && ini < payload.size()) {
        end = payload.find('/', ini);
        if (end == 0) {
            ++ini;
            continue;
        } else if (end == -1) {
            substr = payload.substr(ini);
        } else {
            substr = payload.substr(ini, (end-ini));
        }
        if (substr == "..") {
            // Forbid access outside base folder
            if (new_pwd.empty()) {
                send_message(sockfd, CD_REFUSE, session_id, "Forbidden access outside base server folder");
                return;
            }
            new_pwd.pop_back();
        } else if (substr != ".") {
            new_pwd.push_back(substr);
        }
        ini = end + 1;
    }
    clean_path = base_path;
    for (int i = 0; i < new_pwd.size(); ++i) {
        clean_path += "/" + new_pwd[i];
    }
    DIR *new_dir = opendir(clean_path.c_str());
    if (new_dir) {
        closedir(new_dir);
        pwd.clear();
        pwd = new_pwd;
        send_message(sockfd, CD_ACCEPT, session_id, get_pwd());
        log_info(session_id, "Changed dir: %s", get_pwd().c_str());
    } else if (errno == ENOENT) {
        send_message(sockfd, CD_REFUSE, session_id, "No such directory");
    }
}


void list_files(std::string payload) {
    std::string clean_path, substr;
    std::vector<std::string> new_pwd = pwd;
    int ini, end;
    ini = end = 0;
    while (end != -1 && ini < payload.size()) {
        end = payload.find('/', ini);
        if (end == 0) {
            ++ini;
            continue;
        } else if (end == -1) {
            substr = payload.substr(ini);
        } else {
            substr = payload.substr(ini, (end-ini));
        }
        if (substr == "..") {
            // Forbid access outside base folder
            if (new_pwd.empty()) {
                send_message(sockfd, LS_REFUSE, session_id, "Forbidden access outside base server folder");
                return;
            }
            new_pwd.pop_back();
        } else if (substr != ".") {
            new_pwd.push_back(substr);
        }
        ini = end + 1;
    }
    clean_path = base_path;
    for (int i = 0; i < new_pwd.size(); ++i) {
        clean_path += "/" + new_pwd[i];
    }
    DIR *d = opendir(clean_path.c_str());
    struct dirent *dir;
    std::string listing;
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            listing += dir->d_name;
            listing += "\n";
        }
        closedir(d);
        send_message(sockfd, LS_ACCEPT, session_id, listing);
    } else if (errno == ENOENT) {
        send_message(sockfd, LS_REFUSE, session_id, "No such directory");
    }
}
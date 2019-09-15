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
#include <time.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "common.h"

// General use variables
const char BASE_DIR_FROM_HOME[] = "/ftp";
const char PASSWD_FILE[] = "/.passwd";
std::string base_path;
std::vector<std::string> pwd;
uint16_t session_id;

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

/* Directories manipulation */
void make_dir(std::string payload);
void remove_dir(std::string payload);

/* Files manipulation */
void send_file(std::string payload);
void recv_file(std::string payload);
void delete_file(std::string payload);


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
            log_info(session_id, "Session %d closed", session_id);
            close(sockfd);
            break;
        } else if (msg.type == CD_REQUEST) {
            change_dir(msg.payload);
        } else if (msg.type == LS_REQUEST) {
            list_files(msg.payload);
        } else if (msg.type == PWD_REQUEST) {
            send_message(sockfd, PWD_REPLY, session_id, get_pwd());
        } else if (msg.type == MK_REQUEST) {
            make_dir(msg.payload);
        } else if (msg.type == RM_REQUEST) {
            remove_dir(msg.payload);
        } else if (msg.type == GET_REQUEST) {
            send_file(msg.payload);
        } else if (msg.type == PUT_REQUEST) {
            recv_file(msg.payload);
        } else if (msg.type == DEL_REQUEST) {
            delete_file(msg.payload);
        } else {
                broken_protocol(sockfd, session_id);
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

    // Open passwords file
    std::fstream passwd_stream((base_path + PASSWD_FILE).c_str(), std::fstream::in);
    std::string line, cur_user, cur_passwd;

    // Authentication
    while(std::getline(passwd_stream, line)) {
        pos = line.find(':');
        cur_user = line.substr(0,pos);
        cur_passwd = line.substr(pos+1);
        if (user == cur_user && passwd == cur_passwd) {
            session_id = (uint16_t)time(NULL);
            send_message(sockfd, OPEN_ACCEPT, session_id, "");
            log_info(session_id, "Opened new session: %d", session_id);
            return;
        }
    }

    // No authentication found
    char pld[] = "Username or password incorrect";
    log_error(session_id, "%s", pld);
    send_message(sockfd, OPEN_REFUSE, 0, pld);
    exit(1);
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
        std::string pld = "Cannot enter dir '" + clean_path + "': No such directory";
        send_message(sockfd, CD_REFUSE, session_id, pld);
        log_error(session_id, pld.c_str());
    }  else {
        std::string pld = "Cannot enter dir '" + clean_path + "': Unknown error";
        send_message(sockfd, CD_REFUSE, session_id, pld);
        log_error(session_id, pld.c_str());
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
    } else {
        std::string pld = "Unknown error";
        send_message(sockfd, LS_REFUSE, session_id, pld);
        log_error(session_id, pld.c_str());
    }
}


void make_dir(std::string payload) {
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
                send_message(sockfd, MK_REFUSE, session_id, "Forbidden access outside base server folder");
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
    if (d) {
        closedir(d);
        std::string pld = "Cannot make dir '" + clean_path + "': File exists";
        send_message(sockfd, MK_REFUSE, session_id, pld);
    } else if (errno == ENOENT) {
        int pid = fork();
        if (pid > 0) {
            waitpid(pid, NULL, 0);
            send_message(sockfd, MK_ACCEPT, session_id, clean_path);
            log_info(session_id, "Created dir: %s", clean_path.c_str());
        } else {
            char * args[] = {"mkdir", "-p", NULL, NULL};
            args[2] = (char*)clean_path.c_str();
            execv("/bin/mkdir", args);
        }
    } else {
        std::string pld = "Cannot make dir '" + clean_path + "': Unknown error";
        send_message(sockfd, MK_REFUSE, session_id, pld);
        log_error(session_id, pld.c_str());
    }
}


void remove_dir(std::string payload) {
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
                send_message(sockfd, RM_REFUSE, session_id, "Forbidden access outside base server folder");
                return;
            }
            new_pwd.pop_back();
        } else if (substr != ".") {
            new_pwd.push_back(substr);
        }
        ini = end + 1;
    }
    if (new_pwd.size() < pwd.size() || new_pwd == pwd) {
        send_message(sockfd, RM_REFUSE, session_id, "Cannot remove current or parent directory");
        return;
    }
    clean_path = base_path;
    for (int i = 0; i < new_pwd.size(); ++i) {
        clean_path += "/" + new_pwd[i];
    }
    DIR *d = opendir(clean_path.c_str());
    if (d) {
        closedir(d);
        int pid = fork();
        if (pid > 0) {
            waitpid(pid, NULL, 0);
            send_message(sockfd, RM_ACCEPT, session_id, clean_path);
            log_info(session_id, "Removed dir: %s", clean_path.c_str());
        } else {
            char * args[] = {"rm", "-rf", NULL, NULL};
            args[2] = (char*)clean_path.c_str();
            execv("/bin/rm", args);
        }
    } else if (errno == ENOENT) {
        std::string pld = "Cannot remove dir '" + clean_path + "': No such file";
        send_message(sockfd, RM_REFUSE, session_id, pld);
        log_error(session_id, pld.c_str());
    } else {
        std::string pld = "Cannot remove dir '" + clean_path + "': Unknown error";
        send_message(sockfd, RM_REFUSE, session_id, pld);
        log_error(session_id, pld.c_str());
    }
}


void send_file(std::string payload) {
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
                send_message(sockfd, GET_REFUSE, session_id, "Forbidden access outside base server folder");
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
    FILE *file = fopen(clean_path.c_str(), "r");
    char file_buf[BUFFER_SIZE];
    message response;
    if (file) {
        log_info(session_id, "Starting to send file: %s", clean_path.c_str());
        int n;
        while ((n = fread(file_buf, 1, BUFFER_SIZE, file)) > 0) {
            send_binary(sockfd, TRANSFER_REQUEST, session_id, n, file_buf);
            read_message(sockfd, session_id, &response);
            if (response.type == TRANSFER_ERROR) {
                log_error(session_id, response.payload);
                fclose(file);
                return;
            } else if (response.type != TRANSFER_OK) {
                broken_protocol(sockfd, session_id);
                exit(1);
            }
        }

        if (ferror(file)) {
            std::string pld = "Error reading from file";
            log_error(session_id, pld.c_str());
            send_message(sockfd, TRANSFER_ERROR, session_id, pld);
        } else {
            log_info(session_id, "File transmission ended");
            send_message(sockfd, TRANSFER_END, session_id, "");
        }
    } else if (errno == ENOENT) {
        std::string pld = "Cannot send file '" + clean_path + "'";
        send_message(sockfd, GET_REFUSE, session_id, pld + ": No such file");
        log_error(session_id, pld.c_str());
    } else {
        std::string pld = "Cannot send file '" + clean_path + "'";
        send_message(sockfd, GET_REFUSE, session_id, pld + ": Unknown error");
        log_error(session_id, pld.c_str());
    }
    fclose(file);
}


void recv_file(std::string payload) {
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
                send_message(sockfd, PUT_REFUSE, session_id, "Forbidden access outside base server folder");
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

    FILE *file = fopen(clean_path.c_str(), "r");
    message msg;
    if (file) {
        send_message(sockfd, PUT_WARN, session_id, "");
        log_warning(session_id, "File '%s' already exists.", clean_path.c_str());
        read_message(sockfd, session_id, &msg);
        if (msg.type == PUT_ABORT) {
            log_info(session_id, "File transfer aborted");
            fclose(file);
            return;
        } else if (msg.type != PUT_CONFIRM) {
            broken_protocol(sockfd, 0);
            fclose(file);
            exit(1);
        }
        fclose(file);
    }

    file = fopen(clean_path.c_str(), "w");
    if (file) {
        send_message(sockfd, PUT_ACCEPT, session_id, "");
        log_info(session_id, "Starting to receive file: %s", clean_path.c_str());
        int n;
        read_message(sockfd, session_id, &msg);
        while (msg.type == TRANSFER_REQUEST) {
            n = fwrite(msg.payload, msg.len, 1, file);
            fseek(file, 0, SEEK_END);
            if (n == EOF && errno != 0) {
                send_message(sockfd, TRANSFER_ERROR, session_id, "Error writing to file");
                log_error(session_id, "Error writing to file");
                fclose(file);
                return;
            } else {
                send_message(sockfd, TRANSFER_OK, session_id, "");
                read_message(sockfd, session_id, &msg);
            }
        }
        if (msg.type == TRANSFER_END) {
            printf("\n");
            log_info(session_id, "File transmission ended");
        } else if (msg.type == TRANSFER_ERROR) {
            log_error(session_id, msg.payload);
        } else {
            broken_protocol(sockfd, 0);
        }
    } else {
        send_message(sockfd, PUT_REFUSE, session_id, "Could not open file");
        log_error(session_id, "Could not open file");
    }
    fclose(file);
}


void delete_file(std::string payload) {
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
                send_message(sockfd, DEL_REFUSE, session_id, "Forbidden access outside base server folder");
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
    FILE *f = fopen(clean_path.c_str(), "r");
    if (f) {
        fclose(f);
        int pid = fork();
        if (pid > 0) {
            waitpid(pid, NULL, 0);
            send_message(sockfd, DEL_ACCEPT, session_id, clean_path);
            log_info(session_id, "Removed file: %s", clean_path.c_str());
        } else {
            char * args[] = {"rm", NULL, NULL};
            args[1] = (char*)clean_path.c_str();
            execv("/bin/rm", args);
        }
    } else if (errno == ENOENT) {
        std::string pld = "Cannot remove file '" + clean_path + "': No such file";
        send_message(sockfd, DEL_REFUSE, session_id, pld);
        log_error(session_id, pld.c_str());
    }
}
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"

int main(int argc, char *argv[]) {
    int sockfd, portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    if (argc < 3) {
        printf("usage: ftp <hostname> <port>");
        exit(1);
    }

    // Resolving server address
    server = gethostbyname(argv[1]);
    if (server == NULL)
        raise_error(NULL, "No host %s", argv[1]);

    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        raise_error(NULL, "Couldn't open socket");

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);
    serv_addr.sin_port = htons(portno);

    // Connect to server
    if (connect(sockfd, &serv_addr, sizeof(serv_addr)) < 0)
        raise_error(NULL, "Couldn't connect to %d:%d", serv_addr.sin_addr.s_addr, serv_addr.sin_port);

    // Send and receive messages
    char buffer[100000];
    int n;
    bzero(buffer, strlen(buffer));
    fgets(buffer,100000,stdin);
    n = write(sockfd, buffer, strlen(buffer));
    if (n < 0)
        raise_error(NULL, "Error writing to socket");
    bzero(buffer,100000);
    n = read(sockfd, buffer, strlen(buffer));
    if (n < 0)
        raise_error(NULL, "Error reading from socket");
    log_info("Reply received: %s\n", buffer);


    return 0;
}
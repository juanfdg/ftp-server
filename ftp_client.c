#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "common.h"

int main(int argc, char *argv[]) {
    int sockfd, portno;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    if (argc < 3)
        error("usage: ftp <hostname> <port>");

    // Resolving server address
    server = gethostbyname(argv[1]);
    if (server == NULL)
        error("ERROR no such host");

    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);
    serv_addr.sin_port = htons(portno);

    // Connect to server
    if (connect(sockfd,&serv_addr,sizeof(serv_addr)) < 0)
        error("ERROR connecting");

    // Send and receive messages
    char buffer[100000];
    int n;
    bzero(buffer,100000);
    fgets(buffer,100000,stdin);
    n = write(sockfd,buffer,strlen(buffer));
    if (n < 0)
        error("ERROR writing to socket");
    bzero(buffer,100000);
    n = read(sockfd,buffer,100000);
    if (n < 0)
        error("ERROR reading from socket");
    printf("%s\n", buffer);
    return 0;
}
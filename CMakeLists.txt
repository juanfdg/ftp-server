cmake_minimum_required(VERSION 2.8)
project(FTPServer C)

add_executable(ftp-server ftp_server.c common.h common.c)
add_executable(ftp-client ftp_client.c common.h common.c)
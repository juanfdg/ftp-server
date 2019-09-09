cmake_minimum_required(VERSION 2.8)
project(FTPServer C)

add_executable(ftp-server ftp_server.c common.h)
add_executable(ftp ftp_client.c common.h)
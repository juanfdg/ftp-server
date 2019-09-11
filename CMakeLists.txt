cmake_minimum_required(VERSION 2.8)
project(FTPServer)

add_executable(ftp-server ftp_server.cc common.h common.cc)
add_executable(ftp-client ftp_client.cc common.h common.cc)
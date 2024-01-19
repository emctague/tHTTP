cmake_minimum_required(VERSION 3.27)
project(TinyHTTP C)

set(CMAKE_C_STANDARD 23)

add_executable(TinyHTTP
        src/main.c
        src/blob.h
        src/blob.c
        src/env.c
        src/env.h
        src/diagnostics.h
        src/security.c
        src/security.h
        src/diagnostics.c
        src/socket.c
        src/socket.h)

# Asynchronous Web Server

A C-based web server that uses advanced I/O operations, supporting asynchronous file handling, non-blocking sockets, zero-copying, and multiplexing. The server serves files from specific directories, utilizing sendfile for static files and asynchronous operations for dynamic files. It operates on the epoll API, responding to client requests with proper HTTP protocol following, closing connections after successful file transmission.

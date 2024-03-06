// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <sys/eventfd.h>
#include <libaio.h>
#include <errno.h>

#include "aws.h"
#include "utils/util.h"
#include "utils/debug.h"
#include "utils/sock_util.h"
#include "utils/w_epoll.h"

/* server socket file descriptor */
static int listenfd;

/* epoll file descriptor */
static int epollfd;

static int aws_on_path_cb(http_parser *p, const char *buf, size_t len)
{
	struct connection *conn = (struct connection *)p->data;

	memcpy(conn->request_path, buf, len);
	conn->request_path[len] = '\0';
	conn->have_path = 1;

	return 0;
}

static void connection_prepare_send_reply_header(struct connection *conn)
{
	/* TODO: Prepare the connection buffer to send the reply header. */
	sprintf(conn->send_buffer, "HTTP/1.1 200 OK Content-Length: %ld\r\n\r\n", conn->file_size);
	conn->send_len = strlen(conn->send_buffer);
}

static void connection_prepare_send_404(struct connection *conn)
{
	/* TODO: Prepare the connection buffer to send the 404 header. */
	sprintf(conn->send_buffer, "HTTP/1.1 404 Not Found Content-Length: %ld\r\n\r\n", conn->file_size);
	conn->send_len = strlen(conn->send_buffer);
}

static enum resource_type connection_get_resource_type(struct connection *conn)
{
	/* TODO: Get resource type depending on request path/filename. Filename should
	 * point to the static or dynamic folder.
	 */
	if (strstr(conn->filename, AWS_ABS_STATIC_FOLDER) != NULL)
		return RESOURCE_TYPE_STATIC;
	return RESOURCE_TYPE_DYNAMIC;
}


struct connection *connection_create(int sockfd)
{
	/* TODO: Initialize connection structure on given socket. */
	struct connection *conn;

	conn = malloc(sizeof(struct connection));
	DIE(conn == NULL, "malloc");

	conn->sockfd = sockfd;
	memset(conn->filename, 0, BUFSIZ);
	memset(conn->recv_buffer, 0, BUFSIZ);
	memset(conn->send_buffer, 0, BUFSIZ);
	memset(conn->request_path, 0, BUFSIZ);

	return conn;
}

void connection_start_async_io(struct connection *conn)
{
	/* TODO: Start asynchronous operation (read from file).
	 * Use io_submit(2) & friends for reading data asynchronously.
	 */
}

void connection_remove(struct connection *conn)
{
	/* TODO: Remove connection handler. */
	close(conn->sockfd);

	if (conn->fd != -1)
		close(conn->fd);

	free(conn);
}

void handle_new_connection(void)
{
	/* TODO: Handle a new connection request on the server socket. */
	int rc, sockfd;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	struct connection *new_connection;

	/* TODO: Accept new connection. */
	sockfd = accept(listenfd, (SSA *) &addr, &addrlen);
	DIE(sockfd < 0, "accept");

	/* TODO: Set socket to be non-blocking. */
	int current_status, new_status;

	current_status = fcntl(sockfd, F_GETFL, 0);

	new_status = fcntl(sockfd, F_SETFL, current_status | O_NONBLOCK);
	DIE(new_status != 0, "fcntl");

	/* TODO: Instantiate new connection handler. */
	new_connection = connection_create(sockfd);

	/* TODO: Add socket to epoll. */
	rc = w_epoll_add_ptr_in(epollfd, sockfd, new_connection);
	DIE(rc < 0, "w_epoll_add_ptr_in");

	/* TODO: Initialize HTTP_REQUEST parser. */
	http_parser_init(&new_connection->request_parser, HTTP_REQUEST);
}

void receive_data(struct connection *conn)
{
	/* TODO: Receive message on socket.
	 * Store message in recv_buffer in struct connection.
	 */
	ssize_t bytes_recv;

	conn->recv_len = 0;

	do {
		bytes_recv = recv(conn->sockfd, conn->recv_buffer + conn->recv_len, BUFSIZ - conn->recv_len, 0);

		if (bytes_recv != -1)
			conn->recv_len += bytes_recv;
		else
			break;
	} while (bytes_recv != 0);
}

int connection_open_file(struct connection *conn)
{
	/* TODO: Open file and update connection fields. */
	conn->filename[0] = '.';
	strcat(conn->filename, conn->request_path);
	conn->fd = open(conn->filename, O_RDWR);

	if (conn->fd == -1) {
		conn->file_size = 0;
	} else {
		struct stat buff;

		fstat(conn->fd, &buff);
		conn->file_size = buff.st_size;
	}

	return conn->fd;
}

void connection_complete_async_io(struct connection *conn)
{
	/* TODO: Complete asynchronous operation; operation returns successfully.
	 * Prepare socket for sending.
	 */
}

int parse_header(struct connection *conn)
{
	/* TODO: Parse the HTTP header and extract the file path. */
	/* Use mostly null settings except for on_path callback. */
	http_parser_settings settings_on_path = {
		.on_message_begin = 0,
		.on_header_field = 0,
		.on_header_value = 0,
		.on_path = aws_on_path_cb,
			.on_url = 0,
		.on_fragment = 0,
		.on_query_string = 0,
		.on_body = 0,
		.on_headers_complete = 0,
		.on_message_complete = 0
	};

	conn->request_parser.data = conn;

	http_parser_execute(&conn->request_parser, &settings_on_path, conn->recv_buffer, conn->recv_len);
	return 0;
}

enum connection_state connection_send_static(struct connection *conn)
{
	/* TODO: Send static data using sendfile(2). */
	int bytes_sent;
	long offset;

	offset = 0;

	while (conn->file_size != 0) {
		bytes_sent = sendfile(conn->sockfd, conn->fd, &offset, conn->file_size);
		if (bytes_sent != -1)
			conn->file_size -= bytes_sent;
	}

	return STATE_DATA_SENT;
}

int connection_send_data(struct connection *conn)
{
	/* May be used as a helper function. */
	/* TODO: Send as much data as possible from the connection send buffer.
	 * Returns the number of bytes sent or -1 if an error occurred
	 */
	int bytes_sent, total_sent;

	total_sent = 0;

	while (conn->send_len != 0) {
		bytes_sent = send(conn->sockfd, conn->send_buffer + total_sent, conn->send_len, 0);
		if (bytes_sent != -1) {
			conn->send_len -= bytes_sent;
			total_sent += bytes_sent;
		}
	}

	return 0;
}

int connection_send_dynamic(struct connection *conn)
{
	/* TODO: Read data asynchronously.
	 * Returns 0 on success and -1 on error.
	 */
	conn->eventfd = eventfd(0, 0);
	conn->piocb[0] = &conn->iocb;

	io_set_eventfd(conn->piocb[0], conn->eventfd);

	io_setup(1, &conn->ctx);

	int offset, read_write_size;
	struct io_event event;

	offset = 0;

	while (conn->file_size > 0) {
		// if file_size bigger than BUFSIZ read and write BUFSIZ bytes, else read and wirte file_size bytes
		if (conn->file_size > BUFSIZ)
			read_write_size = BUFSIZ;
		else
			read_write_size = conn->file_size;

		char buff[BUFSIZ];

		memset(buff, 0, read_write_size);

		// init async read operation
		io_prep_pread(conn->piocb[0], conn->fd, buff, read_write_size, offset);

		// start async read operation
		io_submit(conn->ctx, 1, conn->piocb);

		// wait for read operation to finish
		io_getevents(conn->ctx, 1, 1, &event, NULL);

		// init async write operation
		io_prep_pwrite(conn->piocb[0], conn->sockfd, buff, read_write_size, 0);

		// start async write operation
		io_submit(conn->ctx, 1, conn->piocb);

		// wait for write operation to finish
		io_getevents(conn->ctx, 1, 1, &event, NULL);

		conn->file_size -= read_write_size;
		offset += read_write_size;
	}

	io_destroy(conn->ctx);
	return 0;
}


void handle_input(struct connection *conn)
{
	/* TODO: Handle input information: may be a new message or notification of
	 * completion of an asynchronous I/O operation.
	 */
	int rc;

	receive_data(conn);
	parse_header(conn);

	rc = connection_open_file(conn);

	if (rc == -1)
		connection_prepare_send_404(conn);
	else
		connection_prepare_send_reply_header(conn);

	rc = w_epoll_update_ptr_out(epollfd, conn->sockfd, conn);
	DIE(rc < 0, "w_epoll_update_ptr_out");
}

void handle_output(struct connection *conn)
{
	/* TODO: Handle output information: may be a new valid requests or notification of
	 * completion of an asynchronous I/O operation or invalid requests.
	 */
	int rc;

	// send header
	connection_send_data(conn);

	// if header is of type HTTP 200 OK, send file content
	if (conn->fd != -1) {
		if (connection_get_resource_type(conn) == RESOURCE_TYPE_STATIC)
			connection_send_static(conn);
		else
			connection_send_dynamic(conn);
	}

	rc = w_epoll_remove_ptr(epollfd, conn->sockfd, conn);
	DIE(rc < 0, "w_epoll_remove_ptr");
	connection_remove(conn);
}

void handle_client(uint32_t event, struct connection *conn)
{
	/* TODO: Handle new client. There can be input and output connections.
	 * Take care of what happened at the end of a connection.
	 */
	if (event & EPOLLIN)
		handle_input(conn);
	else if (event & EPOLLOUT)
		handle_output(conn);
}

int main(void)
{
	int rc;

	/* TODO: Initialize asynchronous operations. */

	/* TODO: Initialize multiplexing. */
	epollfd = w_epoll_create();
	DIE(epollfd < 0, "w_epoll_create");

	/* TODO: Create server socket. */
	listenfd = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);
	DIE(listenfd < 0, "tcp_create_listener");

	/* TODO: Add server socket to epoll object*/
	rc = w_epoll_add_fd_in(epollfd, listenfd);
	DIE(rc < 0, "w_epoll_add_fd_in");

	/* Uncomment the following line for debugging. */
	// dlog(LOG_INFO, "Server waiting for connections on port %d\n", AWS_LISTEN_PORT);

	/* server main loop */
	while (1) {
		struct epoll_event rev;

		/* TODO: Wait for events. */
		rc = w_epoll_wait_infinite(epollfd, &rev);
		DIE(rc < 0, "w_epoll_wait_infinite");

		/* TODO: Switch event types; consider
		 *   - new connection requests (on server socket)
		 *   - socket communication (on connection sockets)
		 */
		if (rev.data.fd == listenfd) {
			if (rev.events & EPOLLIN)
				handle_new_connection();
		} else {
			handle_client(rev.events, (struct connection *) rev.data.ptr);
		}
	}

	return 0;
}


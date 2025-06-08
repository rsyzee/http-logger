#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <memory>
#include <mutex>
#include <string>
#include <queue>
#include <unordered_map>

enum eChunkProcState : int
{
	eParseLen,
	eParseData,
	eParseDone
};

struct chunk_hdr
{
	eChunkProcState ch_state;
	size_t remaining_length;
};


/*
	TODO :
	Using better buffer management
	Pre-computed hash table for common headers
*/

struct http_req
{
	time_t time_stamp;

	size_t remaining_length;
	size_t content_length;

	std::string host;
	std::string method;
	std::string uri;

	struct chunk_hdr chunk_data;
	bool chunked_body;
};

struct http_res
{
	struct chunk_hdr chunk_data;
	bool chunked_body;
	int status_code;
	size_t remaining_length;
	size_t content_length;
};

struct sock_ctx
{
	std::mutex _mtx;
	std::string send_buf;
	std::string recv_buf;
	std::string dst_buf;

	bool req_hdr_parsed;
	bool res_hdr_parsed;

	std::queue<struct http_req> req_queue;
	http_res res_data;
};

struct log_ctx
{
	FILE *file_handle;
	std::mutex _mtx;
	std::unordered_map<int, std::shared_ptr<struct sock_ctx>> socks_map;
};

static std::unique_ptr<struct log_ctx> g_ctx = nullptr;
static std::mutex g_init_mtx;
static volatile bool g_need_exit = false;

static void log_exit (void)
{
	if (!g_ctx)
		return;

	g_need_exit = true;
	if (g_ctx->file_handle)
	{
		fclose(g_ctx->file_handle);
		g_ctx->file_handle = nullptr;
	}

	g_ctx.reset();
	g_ctx = nullptr;

}

static void init_log (void)
{
	try
	{
		std::lock_guard<std::mutex> _lock(g_init_mtx);
		const char *log_file;

		if (g_ctx)
			return;

		log_file = getenv("GWLOG_PATH");
		if (!log_file)
			return;

		g_ctx = std::move(std::make_unique<struct log_ctx>());
		g_ctx->file_handle = fopen(log_file, "a");

		if (!g_ctx->file_handle)
		{
			log_exit();
			return;
		}

		setvbuf(g_ctx->file_handle, NULL, _IOLBF, 0);
	}
	catch (...)
	{
		log_exit();
		return;
	}
}

static void write_to_file(struct sock_ctx *ctx, struct http_req *req)
{
	struct tm tm_info;
	char time_str[20];

	localtime_r(&req->time_stamp, &tm_info);
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);
	fprintf(g_ctx->file_handle, "[%s] DST : %s | HOST : %s | REQ : %s %s | RET : %d\n",
		time_str, ctx->dst_buf.data(), req->host.data(), req->method.data(),
		req->uri.data(), ctx->res_data.status_code);

	ctx->req_queue.pop();
}

static int parse_http_req_header(struct sock_ctx *ctx, http_req *req)
{
	char *start = ctx->send_buf.data();
	char *current, *next = NULL, *end = NULL;
	int cnt_line = 0;

	while (1)
	{
		cnt_line++;
		if (!end)
		{
			end = strstr(start, "\r\n\r\n");
			if (!end)
				return -1;

			end += 4;
			current = start;
		}
		else
		{
			current = next;
			if (!current)
				return -2;
		}

		next = strstr(current, "\r\n");
		if (!next)
			return -2;

		if (next + 2 == end)
			break;

		*next = '\0'; /* null termination per CRLF */
		next += 2;

		char* val = strchr(current, ':');
		/* match on ':' separator ...:xxx */
		if (cnt_line == 1 && !val)
		{
			char *uri = strchr(current, ' ');
			/* match on xxx[ ]/uri */
			if (!uri)
				return -2;

			*uri = '\0'; /* null termination. to parse method */
			uri++;
			if (*uri != '/')
				return -2;

			char *ver = strstr(uri, " HTTP/1.");
			/* validate HTTP 1.x */
			if (!ver)
				return -2;

			*ver = '\0';

			req->method = current;
			req->uri = uri;
			continue;
		}

		if (!val || !current)
			return -2;

		*val = '\0';
		val++;
		while (isspace(*val))
			val++;

		char *key = current;

		if (!strcasecmp("host", key))
		{
			req->host = val;
		}
		else if (!strcasecmp("content-length", key))
		{
			char *endptr;
			req->content_length = strtoull(val, &endptr, 10);
			req->remaining_length = req->content_length;

			if (*endptr != '\0')
				return -2;
		}
		else if (!strcasecmp(key, "transfer-encoding"))
		{
			if (strcasestr(val, "chunked"))
			{
				req->chunked_body = true;
				req->chunk_data.ch_state = eParseLen;
			}

			req->content_length = (uint64_t)-1;
		}
	}

	req->time_stamp = time(nullptr);
	ctx->req_queue.push(std::move(*req));
	ctx->send_buf.erase(0, end - start);

	if (!req->content_length)
		ctx->req_hdr_parsed = false;
	else
		ctx->req_hdr_parsed = true;

	return 1;
}

static int validate_http_method_hdr (struct sock_ctx *ctx, size_t len)
{
	if (len == 0)
		return -1;

	static const char *methods_pattern[] =
	{
		"GET /",
		"POST /",
		"PUT /",
		"HEAD /",
		"DELETE /",
		"OPTIONS /",
		"PATCH /",
	};

	size_t mlen, cmpl;
	for (const auto& c : methods_pattern)
	{
		mlen = strlen(c);
		cmpl = len > mlen ? mlen : len;
		if (!memcmp(&ctx->send_buf[0], c, cmpl))
		{
			if (cmpl < mlen)
				return -1;

			return 0;
		}
	}

	return -2;
}

static bool is_hex_char(const char *c)
{
	for (; *c; c++)
		if (!std::isxdigit(*c))
			return false;

	return true;
}

static int parse_chunked_body(std::string& buf, struct chunk_hdr *chunk)
{
	if (buf.length() == 0)
		return -1;

	while (1)
	{
		if (chunk->ch_state == eParseLen)
		{
			char *c, *end = &buf[buf.length()];

			if (buf.length() < 3)
				return -1;

			c = strchr(buf.data(), '\r');
			if (!c)
			{
				if (buf.length() > 8)
					return -2;

				if (!is_hex_char(&buf[0]))
					return -2;

				return -1;
			}

			if (&c[1] >= end)
				return -1; /* expecting LF */

			if (c[1] != '\n')
				return -2;

			*c = '\0';
			size_t chunk_len;

			try
			{
				chunk_len = std::stoul(buf, nullptr, 16);
			}
			catch (...)
			{
				return -2;
			}

			if (chunk_len == 0)
			{
				chunk->ch_state = eParseDone;
				buf.erase(0, c - &buf[0] + 2);
				continue;
			}

			chunk->remaining_length = chunk_len + 2;
			buf.erase(0, c - &buf[0] + 2);
			chunk->ch_state = eParseData;
			/* size_t next_chunk = c - &buf[0] + 2 + chunk_size + 2; */
			continue;
		}
		else if (chunk->ch_state == eParseData)
		{
			if (buf.length() < chunk->remaining_length)
			{
				chunk->remaining_length -= buf.length();
				buf.clear();
				buf.shrink_to_fit();
				return -1;
			}

			buf.erase(0, chunk->remaining_length);
			chunk->remaining_length = 0;
			chunk->ch_state = eParseLen;
			continue;
		}
		else if (chunk->ch_state == eParseDone)
		{
			if (buf.length() < 2)
				return -1;

			if (buf[0] != '\r' || buf[1] != '\n')
				return -2;

			buf.erase(0, 2);
			return 0;
		}
		else
		{
			return -2;
		}
	}
}

static int parse_http_req_body (struct sock_ctx *ctx)
{
	struct http_req *req = &ctx->req_queue.back();

	if (req->chunked_body)
	{
		int ret;
		ret = parse_chunked_body(ctx->send_buf, &req->chunk_data);

		if (ret < 0)
			return ret;

		ctx->req_hdr_parsed = false;
		return 0;
	}

	if (req->remaining_length > ctx->send_buf.length())
	{
		req->remaining_length -= ctx->send_buf.length();
		ctx->send_buf.clear();
		ctx->send_buf.shrink_to_fit();
		ctx->req_hdr_parsed = true;
		return -1;
	}
	else
	{
		ctx->send_buf.erase(0, req->remaining_length);
		ctx->req_hdr_parsed = false; /* reset to parse next header */
		req->remaining_length = 0;
		return 0;
	}
}

static int parse_http_res_header(struct sock_ctx *ctx, http_res *res)
{
	char *start = ctx->recv_buf.data();
	char *current, *next = NULL, *end = NULL;
	int cnt_line = 0;

	while (1)
	{
		cnt_line++;
		if (!end)
		{
			end = strstr(start, "\r\n\r\n");
			if (!end)
				return -1; /* need more data. */

			end += 4;
			current = start;
		}
		else
		{
			current = next;
			if (!current)
				return -2;
		}

		next = strstr(current, "\r\n");
		if (!next)
			return -2;

		if (next + 2 == end)
			break;

		*next = '\0'; /* null termination per line \r\n */
		next += 2;

		char* val = strchr(current, ':');
		if (cnt_line == 1 && !val)
		{
			char *s = strchr(current, ' ');
			if (!s)
				return -2;

			*s = '\0';
			s++;

			res->status_code = (s[0] - '0') * 100 +
							   (s[1] - '0') * 10 +
							   (s[2] - '0');

			if (res->status_code < 100 || res->status_code > 599)
				return -2;

			continue;
		}

		if (!val || !current)
			return -2;

		*val = '\0';
		val++;
		while (isspace(*val))
			val++;

		char *key = current;

		if (!strcasecmp(key, "content-length"))
		{
			char *endptr;
			res->content_length = strtoull(val, &endptr, 10);
			res->remaining_length = res->content_length;
			if (*endptr != '\0')
				return -2;
		}
		else if (!strcasecmp(key, "transfer-encoding"))
		{
			if (strcasestr(val, "chunked"))
			{
				res->chunked_body = true;
				res->chunk_data.ch_state = eParseLen;
			}

			res->content_length = (uint64_t)-1;
		}
	}

	ctx->recv_buf.erase(0, end - start);
	if (!res->content_length)
		ctx->res_hdr_parsed = false;
	else
		ctx->res_hdr_parsed = true;

	return 0;
}

static int parse_http_res_body (struct sock_ctx *ctx, struct http_res *res)
{
	if (res->chunked_body)
	{
		int ret;
		ret = parse_chunked_body(ctx->recv_buf, &res->chunk_data);

		if (ret < 0)
			return ret;

		ctx->res_hdr_parsed = false;
		return 0;
	}

	if (res->remaining_length > ctx->recv_buf.length())
	{
		res->remaining_length -= ctx->recv_buf.length();
		ctx->recv_buf.clear();
		ctx->recv_buf.shrink_to_fit();
		ctx->res_hdr_parsed = true;
		return -1;
	}
	else
	{
		ctx->recv_buf.erase(0, res->remaining_length);
		ctx->res_hdr_parsed = false; /* reset to parse next header */
		res->remaining_length = 0;
		return 0;
	}
}

static void __rm_sock_handle(struct log_ctx *ctx, int fd)
{
	auto it = ctx->socks_map.find(fd);
	if (it != ctx->socks_map.end())
		ctx->socks_map.erase(it);
}

static void rm_sock_handle(struct log_ctx *ctx, int fd)
{
	std::lock_guard<std::mutex> lock(ctx->_mtx);
	__rm_sock_handle(ctx, fd);
}

static void __handle_socket(struct log_ctx *ctx, int fd, int domain, int type)
{
	if (!g_ctx || g_need_exit)
		return;

	if (!(domain == AF_INET || domain == AF_INET6))
		return;

	if (!(type & SOCK_STREAM))
		return;

	try
	{
		auto sock_ctx = std::make_unique<struct sock_ctx>();
		std::lock_guard<std::mutex> lock(ctx->_mtx);
		auto it = ctx->socks_map.find(fd);
		if (it == ctx->socks_map.end())
			ctx->socks_map[fd] = std::move(sock_ctx);
	}
	catch (...)
	{
		log_exit();
	}
}

static void __handle_connect(struct log_ctx *ctx, int sockfd,
				const struct sockaddr *addr, int ret)
{
	if (!g_ctx || g_need_exit)
		return;

	if (ret != 0 && ret != -EINPROGRESS)
		return;

	try
	{
		std::shared_ptr<struct sock_ctx> sock_ctx;
		{
			std::lock_guard<std::mutex> lock(ctx->_mtx);
			auto it = ctx->socks_map.find(sockfd);

			if (it == ctx->socks_map.end())
				return;

			sock_ctx = it->second;
		}

		std::lock_guard<std::mutex> lock(sock_ctx->_mtx);

		auto& dst_buf = sock_ctx->dst_buf;
		dst_buf.resize(INET6_ADDRSTRLEN + 7);

		uint16_t port = 0;
		size_t len = 0;

		switch (addr->sa_family)
		{
			case AF_INET:
			{
				auto sa4 = reinterpret_cast<const sockaddr_in*>(addr);
				inet_ntop(AF_INET, &sa4->sin_addr, dst_buf.data(), INET_ADDRSTRLEN);

				port = ntohs(sa4->sin_port);
				len = strlen(dst_buf.data());
			}
			break;

			case AF_INET6:
			{
				auto sa6 = reinterpret_cast<const sockaddr_in6*>(addr);
				port = ntohs(sa6->sin6_port);

				dst_buf[0] = '[';
				inet_ntop(AF_INET6, &sa6->sin6_addr, &dst_buf[1], INET6_ADDRSTRLEN);
				len = strlen(dst_buf.data());
				dst_buf[len] = ']';
				len++;
			}
			break;

			default:
			rm_sock_handle(ctx, sockfd);
			return;
		}

		dst_buf[len] = ':';
		snprintf(dst_buf.data() + len + 1, dst_buf.length() - len - 1, "%u", port);
	}
	catch (...)
	{
		log_exit();
	}
}

static void __handle_send(struct log_ctx *ctx, int fd, const char *buf, size_t len)
{
	if (!g_ctx || g_need_exit)
		return;

	try
	{
		std::shared_ptr<struct sock_ctx> ref;
		{
			std::lock_guard<std::mutex> lock(ctx->_mtx);
			auto it = ctx->socks_map.find(fd);
			if (it == ctx->socks_map.end())
				return;

			ref = it->second;
		}

		std::lock_guard<std::mutex> lock(ref->_mtx);
		sock_ctx *sock_ctx = ref.get();

		sock_ctx->send_buf.append(buf, len);
		struct http_req req{};
		auto &buf = sock_ctx->send_buf;

		while (buf.length() > 0)
		{
			if (!sock_ctx->req_hdr_parsed)
			{
				int ret;
				ret = validate_http_method_hdr(sock_ctx, buf.length());

				if (ret == -1)
					return;

				if (ret < 0)
				{
					rm_sock_handle(ctx, fd);
					return;
				}

				ret = parse_http_req_header(sock_ctx, &req);

				if (ret == -1)
					return;

				if (ret < 0)
				{
					rm_sock_handle(ctx, fd);
					return;
				}

				continue;
			}
			else
			{
				int ret;
				ret = parse_http_req_body(sock_ctx);

				if (ret == -1)
					return;

				if (ret < 0)
				{
					rm_sock_handle(ctx, fd);
					return;
				}
			}
		}
	}
	catch (...)
	{
		log_exit();
	}
}

static void __handle_recv(struct log_ctx *ctx, int fd, const char *buf, size_t len)
{
	if (!g_ctx || g_need_exit)
		return;

	try
	{
		std::shared_ptr<struct sock_ctx> ref;
		{
			std::lock_guard<std::mutex> lock(ctx->_mtx);
			auto it = ctx->socks_map.find(fd);
			if (it == ctx->socks_map.end())
				return;

			ref = it->second;
		}

		std::lock_guard<std::mutex> lock(ref->_mtx);
		sock_ctx *sock_ctx = ref.get();
		sock_ctx->recv_buf.append(buf, len);
		struct http_res *res = &sock_ctx->res_data;

		while (sock_ctx->recv_buf.length() > 0)
		{
			if (!sock_ctx->res_hdr_parsed)
			{
				if (sock_ctx->req_queue.empty())
					return;

				int ret = 0;
				ret = parse_http_res_header(sock_ctx, res);

				if (ret == -1)
					return;

				if (ret < 0)
				{
					rm_sock_handle(ctx, fd);
					return;
				}

				write_to_file(sock_ctx, &sock_ctx->req_queue.front());
				continue;
			}
			else
			{
				int ret;
				ret = parse_http_res_body(sock_ctx, res);

				if (ret == -1)
					return;

				if (ret < 0)
				{
					rm_sock_handle(ctx, fd);
					return;
				}
			}
		}
	}
	catch (...)
	{
		log_exit();
	}
}

void __handle_close(struct log_ctx *ctx, int fd)
{
	if (!g_ctx || g_need_exit)
		return;

	try
	{
		rm_sock_handle(ctx, fd);
	}
	catch (...)
	{
		log_exit();
	}
}

extern "C" {


int socket(int domain, int type, int protocol)
{
	int ret;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_socket), "D" (domain), "S" (type), "d" (protocol)
		: "rcx", "r11", "memory"
	);

	if (ret < 0)
	{
		errno = -ret;
		return -1;
	}

	if (!g_ctx)
		init_log();

	__handle_socket(g_ctx.get(), ret, domain, type);
	return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_connect), "D" (sockfd), "S" (addr), "d" (addrlen)
		: "rcx", "r11", "memory"
	);


	__handle_connect(g_ctx.get(), sockfd, addr, ret);
	if (ret < 0)
	{
		errno = -ret;
		return -1;
	}

	return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
				const struct sockaddr *dst_addr, socklen_t addrlen)
{
	long ret;

	register int __flags __asm__ ("%r10") = flags;
	register const struct sockaddr *__dst_addr __asm__ ("%r8") = dst_addr;
	register socklen_t __addrlen __asm__ ("%r9") = addrlen;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_sendto), "D" (sockfd), "S" (buf), "d" (len), "r" (__flags),
		  "r" (__dst_addr), "r" (__addrlen)
		: "rcx", "r11", "memory"
	);

	if (ret < 0)
	{
		errno = -ret;
		return -1;
	}

	__handle_send(g_ctx.get(), sockfd, (const char *)buf, ret);
	return ret;
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
			 struct sockaddr *src_addr, socklen_t *addrlen)
{
	long ret;

	register int __flags __asm__ ("%r10") = flags;
	register struct sockaddr *__src_addr __asm__ ("%r8") = src_addr;
	register socklen_t *__addrlen __asm ("%r9") = addrlen;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_recvfrom), "D" (fd), "S" (buf), "d" (len), "r" (__flags),
		  "r" (__src_addr), "r" (__addrlen)
		: "rcx", "r11", "memory"
	);

	if (ret < 0)
	{
		errno = -ret;
		return -1;
	}

	__handle_recv(g_ctx.get(), fd, (const char *)buf, ret);
	return ret;
}

ssize_t write(int fd, const void* buf, size_t len)
{
	long ret;
	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_write), "D" (fd), "S" (buf), "d" (len)
		: "rcx", "r11", "memory"
	);

	if (ret < 0)
	{
		errno = -ret;
		return -1;
	}

	__handle_send(g_ctx.get(), fd, (const char *)buf, ret);
	return ret;
}

ssize_t read(int fd, void *buf, size_t len)
{
	long ret;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_read), "D" (fd), "S" (buf), "d" (len)
		: "rcx", "r11", "memory"
	);

	if (ret < 0)
	{
		errno = -ret;
		return -1;
	}

	__handle_recv(g_ctx.get(), fd, (const char *)buf, ret);
	return ret;
}

int close(int fd)
{
	int ret;
	__handle_close(g_ctx.get(), fd);

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_close), "D" (fd)
		: "rcx", "r11", "memory"
	);

	if (ret < 0)
	{
		errno = -ret;
		return -1;
	}

	return ret;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	return recvfrom(fd, buf, len, flags, nullptr, 0);
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	return sendto(fd, buf, len, flags, nullptr, 0);
}

} // extern "C"

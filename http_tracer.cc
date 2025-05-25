#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <memory>
#include <queue>
#include <unordered_map>
#include <mutex>
#include <regex>


struct http_req
{
	time_t time_stamp;
	std::string host;
	std::string method;
	std::string uri;
};

struct http_res
{
	int status_code;
	size_t content_length;
};

struct sock_ctx
{
	std::string send_buf;
	std::string recv_buf;
	std::string dst_buf;

	std::queue<struct http_req> req_queue;
	http_res res_data;
};

struct log_ctx
{
	FILE *file_handle;
	std::mutex _mtx;
	std::unordered_map<int, std::unique_ptr<struct sock_ctx>> socks_map;
};

static std::unique_ptr<struct log_ctx> g_ctx = nullptr;
static std::mutex g_init_mtx;
static volatile bool g_need_exit = false;

static void log_exit (void)
{
	if (!g_ctx)
		return;

	if (g_ctx->file_handle)
	{
		fclose(g_ctx->file_handle);
		g_ctx->file_handle = nullptr;
	}

	g_need_exit = true;
	g_ctx.reset();
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
	}
	catch (...)
	{
		log_exit();
		return;
	}
}

static void write_to_file(struct sock_ctx *ctx, struct http_req *req)
{
	struct tm tm_info{};
	localtime_r(&req->time_stamp, &tm_info);

	char time_str[20];
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);
	fprintf(g_ctx.get()->file_handle, "[%s] DST : %s | HOST : %s | REQ : %s %s | RET : %d\n", time_str, ctx->dst_buf.c_str(), req->host.c_str(), req->method.c_str(), req->uri.c_str(), ctx->res_data.status_code);
}

static bool parse_http_req_header(struct sock_ctx *ctx, http_req *req)
{
	static std::regex req_hdr (
		R"(^([A-Z]+)\s+(\S+)\s+HTTP/1\.[01]\r\n)"  // Method, URI, HTTP version
		R"([Hh][Oo][Ss][Tt]:\s*([^\r\n]+)\r\n)",    // Host header
		std::regex::optimize
	);

	std::smatch match_rgx;
	if (std::regex_search(ctx->send_buf, match_rgx, req_hdr))
	{
		req->method = std::move(match_rgx[1]);
		req->uri = std::move(match_rgx[2]);
		req->host = std::move(match_rgx[3]);

		return true;
	}

	return false;
}

static size_t parse_http_res_header(struct sock_ctx *ctx, size_t hdr_len) noexcept
{
	if (hdr_len == 0 || ctx->recv_buf.size() < hdr_len) return 0;

	static std::regex code_ret(R"(HTTP/1\.[01]\s+(\d+)\s+)", std::regex::optimize);
	static std::regex cl_hdr(R"((?:^|\r\n)Content-Length:\s*(\d+))", std::regex::icase | std::regex::optimize);
	static std::regex chunked_hdr(R"(Transfer-Encoding:\s*chunked)", std::regex::icase | std::regex::optimize);

	std::smatch m;
	std::string headers = ctx->recv_buf.substr(0, hdr_len - 4);
	if (std::regex_search(headers, m, code_ret))
	{
		ctx->res_data.status_code = stoi(m[1]);

		if (std::regex_search(headers, m, chunked_hdr))
		{
			size_t chunk_pos = hdr_len;
			while (1)
			{
				size_t size_end_pos = ctx->recv_buf.find("\r\n", chunk_pos);
				if (size_end_pos == std::string::npos)
					return 0; //Need more data.

				size_t chunk_size = 0;
				std::string size_str = ctx->recv_buf.substr(chunk_pos, size_end_pos - chunk_pos);

				try
				{
					chunk_size = std::stoul(size_str, nullptr, 16);
				}
				catch (...)
				{
					return 0;
				}

				if (chunk_size == 0)
				{
					return size_end_pos + 4;
				}

				size_t next_chunk = size_end_pos + 2 + chunk_size + 2;
				if (ctx->recv_buf.length() < next_chunk)
					return 0; //Need more data.

				chunk_pos = next_chunk;
			}
		}

		if (std::regex_search(headers, m, cl_hdr))
			ctx->res_data.content_length = stoul(m[1]);

		return hdr_len + ctx->res_data.content_length;
	}

	return 0;
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

static void hook_handle_socket(struct log_ctx *ctx, int fd, int domain, int type)
{
	if (!g_ctx || g_need_exit)
		return;

	if (!(domain == AF_INET || domain == AF_INET6) || !(type & SOCK_STREAM))
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

static void hook_handle_connect(struct log_ctx *ctx, int sockfd, const struct sockaddr *addr)
{
	if (!g_ctx || g_need_exit)
		return;

	try
	{
		std::lock_guard<std::mutex> lock(ctx->_mtx);
		auto it = ctx->socks_map.find(sockfd);

		if (it == ctx->socks_map.end())
			return;

		auto& dst_buf = it->second->dst_buf;
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
			ctx->socks_map.erase(it);
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

static void hook_handle_out(struct log_ctx *ctx, int fd, const char *buf, size_t len)
{
	if (!g_ctx || g_need_exit)
		return;

	try
	{
		std::lock_guard<std::mutex> lock(ctx->_mtx);
		auto it = ctx->socks_map.find(fd);
		if (it == ctx->socks_map.end())
			return;

		sock_ctx *sock_ctx = it->second.get();
		sock_ctx->send_buf.append(buf, len);

		size_t end = sock_ctx->send_buf.find("\r\n\r\n");
		if (end == std::string::npos)
			return;

		while (1)
		{
			struct http_req req;

			if (parse_http_req_header(sock_ctx, &req))
			{
				req.time_stamp = time(nullptr);
				sock_ctx->req_queue.push(std::move(req));
				sock_ctx->send_buf.erase(0, end + 4);
			}
			else
			{
				break;
			}
		}
	}
	catch (...)
	{
		log_exit();
	}

}

static void hook_handle_in(struct log_ctx *ctx, int fd, const char *buf, size_t len)
{
	if (!g_ctx || g_need_exit)
		return;

	try
	{
		std::lock_guard<std::mutex> lock(ctx->_mtx);
		auto it = ctx->socks_map.find(fd);
		if (it == ctx->socks_map.end())
			return;

		sock_ctx *sock_ctx = it->second.get();
		sock_ctx->recv_buf.append(buf, len);

		size_t end_header = sock_ctx->recv_buf.find("\r\n\r\n");
		if (end_header == std::string::npos)
			return;

		end_header += 4;

		while (1)
		{
			size_t parsed_len = 0;

			if ((parsed_len = parse_http_res_header(sock_ctx, end_header)) <= 0 || sock_ctx->recv_buf.length() < parsed_len)
				break;

			if (sock_ctx->req_queue.empty())
				break;

			write_to_file(sock_ctx, &sock_ctx->req_queue.front());
			sock_ctx->req_queue.pop();
			sock_ctx->recv_buf.erase(0, parsed_len);
		}
	}
	catch (...)
	{
		log_exit();
	}
}

void hook_handle_close(struct log_ctx *ctx, int fd)
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

	hook_handle_socket(g_ctx.get(), ret, domain, type);
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


	hook_handle_connect(g_ctx.get(), sockfd, addr);
	if (ret < 0)
	{
		errno = -ret;
		return -1;
	}

	return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dst_addr, socklen_t addrlen)
{
	long ret;

	register int __flags __asm__ ("%r10") = flags;
	register const struct sockaddr *__dst_addr __asm__ ("%r8") = dst_addr;
	register socklen_t __addrlen __asm__ ("%r9") = addrlen;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_sendto), "D" (sockfd), "S" (buf), "d" (len), "r" (__flags), "r" (__dst_addr), "r" (__addrlen)
		: "rcx", "r11", "memory"
	);

	if (ret < 0)
	{
		errno = -ret;
		return -1;
	}

	hook_handle_out(g_ctx.get(), sockfd, (const char *)buf, ret);
	return ret;
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	long ret;

	register int __flags __asm__ ("%r10") = flags;
	register struct sockaddr *__src_addr __asm__ ("%r8") = src_addr;
	register socklen_t *__addrlen __asm ("%r9") = addrlen;

	__asm__ volatile (
		"syscall"
		: "=a" (ret)
		: "a" (__NR_recvfrom), "D" (fd), "S" (buf), "d" (len), "r" (__flags), "r" (__src_addr), "r" (__addrlen)
		: "rcx", "r11", "memory"
	);

	if (ret < 0)
	{
		errno = -ret;
		return -1;
	}

	hook_handle_in(g_ctx.get(), fd, (const char *)buf, ret);
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

	hook_handle_out(g_ctx.get(), fd, (const char *)buf, ret);
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

	hook_handle_in(g_ctx.get(), fd, (const char *)buf, ret);
	return ret;
}

int close(int fd)
{
	int ret;
	hook_handle_close(g_ctx.get(), fd);

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
	return recvfrom(fd, buf, len, flags, 0, 0);
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
	return sendto(fd, buf, len, flags, 0, 0);
}

} // extern "C"

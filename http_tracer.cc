#include <cstdio>
#include <cstdlib>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <mutex>
#include <string>
#include <regex>
#include <ctime>

struct sock_ctx
{
    //HTTP_REQ
    time_t req_time;
    std::string dst_str;
    std::string tx_buf;
    std::string host;
    std::string method;
    std::string uri;

    //HTTP_RES
    int status;
    std::string rx_buf;
    bool http_detected;
};

struct log_ctx
{
    FILE *file_handle;
    std::mutex _mtx;
    std::unordered_map<int, std::unique_ptr<sock_ctx>> socks_map;
};

static std::unique_ptr<log_ctx> g_ctx = nullptr;
static std::mutex g_init_mtx;
static volatile bool g_need_exit = false;

static void log_exit(void)
{
    if (g_ctx)
    {
        if (g_ctx->file_handle)
        {
			fclose(g_ctx->file_handle);
			g_ctx->file_handle = nullptr;
		}

        g_need_exit = true;
        g_ctx.reset();
    }

}

static void init_log(void)
{
	try {
		std::lock_guard<std::mutex> lock(g_init_mtx);
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

	} catch (...) {
		log_exit();
	}
}

static void write_to_file(struct log_ctx *main_ctx, struct sock_ctx* sock_ctx)
{
    struct tm tm_info;
    localtime_r(&sock_ctx->req_time, &tm_info);
    char time_str[20];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);
    fprintf(main_ctx->file_handle, "[%s] DST : %s | HOST : %s | REQ : %s %s | RET : %d\n", time_str, sock_ctx->dst_str.c_str(), sock_ctx->host.c_str(), sock_ctx->method.c_str(), sock_ctx->uri.c_str(), sock_ctx->status);
}

static bool parse_http_req(struct sock_ctx *ctx)
{
    static std::regex http_pattern(R"(^(GET|POST|PUT|DELETE|HEAD) (\S+) HTTP/1\.[01]\r\n)");
    static std::regex header_pattern(R"((?:\r\n|^)host:\s*([^\r\n]+))", std::regex::icase | std::regex::optimize);

    std::smatch m;
    const auto& buf = ctx->tx_buf;

    if (std::regex_search(buf, m, http_pattern))
    {
        ctx->method = m[1];
        ctx->uri = m[2];

        std::sregex_iterator it(buf.begin(), buf.end(), header_pattern);
        std::sregex_iterator end;

        while (it != end)
        {
            if (!it->empty())
            {
                std::smatch host_match = *it;
                ctx->host = (*it)[1].str();
                break;
            }

            it++;
        }
        return true;
    }

    return false;
}

static bool parse_http_res(struct sock_ctx *ctx)
{
    static std::regex re(R"(HTTP/1\.[01] (\d{3}))");
    std::smatch m;
    if (std::regex_search(ctx->rx_buf, m, re))
    {
        ctx->status = stoi(m[1]);
        return true;
    }

    return false;
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

    try {

    if ((domain == AF_INET || domain == AF_INET6) and (type & SOCK_STREAM))
    {

        auto sock_ctx = std::make_unique<struct sock_ctx>();
        //sock_ctx->dst_ip.reserve(INET6_ADDRSTRLEN);

        std::lock_guard<std::mutex> lock(ctx->_mtx);
        auto it = ctx->socks_map.find(fd);
	    if (it == ctx->socks_map.end())
            ctx->socks_map[fd] = std::move(sock_ctx);

        return;
    }

    __rm_sock_handle(ctx, fd);

    } catch (...) {
        log_exit();
    }
}


static void hook_handle_connect(struct log_ctx *ctx, int sockfd, const struct sockaddr *addr)
{
    if (!g_ctx || g_need_exit)
		return;

    try {

    std::lock_guard<std::mutex> lock(ctx->_mtx);
    auto it = ctx->socks_map.find(sockfd);
    if (it == ctx->socks_map.end())
        return;

    char ip_str[INET6_ADDRSTRLEN];
    char dst_tmp[INET6_ADDRSTRLEN + 7];
    uint16_t port = 0;

    switch (addr->sa_family)
    {
        case AF_INET:
        {
            auto sa4 = reinterpret_cast<const sockaddr_in*>(addr);
            inet_ntop(AF_INET, &sa4->sin_addr, ip_str, INET_ADDRSTRLEN);
            port = ntohs(sa4->sin_port);
            snprintf(dst_tmp, sizeof(dst_tmp), "%s:%d", ip_str, port);
        }
        break;

        case AF_INET6:
        {
            auto sa6 = reinterpret_cast<const sockaddr_in6*>(addr);
            inet_ntop(AF_INET6, &sa6->sin6_addr, ip_str, sizeof(ip_str));
            port = ntohs(sa6->sin6_port);
            snprintf(dst_tmp, sizeof(dst_tmp), "[%s]:%d", ip_str, port);
        }
        break;

        default:
        ctx->socks_map.erase(it);
        return;
    }

    it->second->dst_str = dst_tmp;

    } catch (...) {
        log_exit();
    }

}

static void hook_handle_send(struct log_ctx *ctx, int fd, const char *buf, ssize_t len)
{
    if (!g_ctx || g_need_exit)
		return;

    try {

    std::lock_guard<std::mutex> lock(ctx->_mtx);
    auto it = ctx->socks_map.find(fd);
    if (it == ctx->socks_map.end())
        return;

    sock_ctx *sock_ctx = it->second.get();

    if (sock_ctx->tx_buf.size() + len > 4096) sock_ctx->tx_buf.clear();
    sock_ctx->tx_buf.append(buf, len);

    if (!sock_ctx->http_detected)
    {
        if (parse_http_req(sock_ctx))
        {
            sock_ctx->http_detected = true;
            sock_ctx->req_time = time(nullptr);
            return;
        }

        ctx->socks_map.erase(it);

    }

    } catch (...) {
        log_exit();
    }

}

static void hook_handle_recv(struct log_ctx *ctx, int fd, const char *buf, ssize_t len)
{
    if (!g_ctx || g_need_exit)
		return;

    try {

    std::lock_guard<std::mutex> lock(ctx->_mtx);
    auto it = ctx->socks_map.find(fd);
    if (it == ctx->socks_map.end() || !it->second->http_detected)
        return;

    sock_ctx *sock_ctx = it->second.get();

    if (sock_ctx->rx_buf.size() + len > 4096) sock_ctx->rx_buf.clear();

    sock_ctx->rx_buf.append(buf, len);

    if (!parse_http_res(sock_ctx))
    {
        //__rm_sock_handle(ctx, fd);
        return;
    }

    write_to_file(ctx, sock_ctx);

    sock_ctx->tx_buf.clear();
    sock_ctx->rx_buf.clear();
    sock_ctx->status = 0;

    } catch (...) {
        log_exit();
    }
}

void hook_handle_close(struct log_ctx *ctx, int fd)
{
    if (!g_ctx || g_need_exit)
		return;

    try {
        rm_sock_handle(ctx, fd);
    } catch (...) {
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

    if (ret < 0) {
        errno = -ret;
        return -1;
    } else {
        if (!g_ctx)
			init_log();

        hook_handle_socket(g_ctx.get(), ret, domain, type);
    }

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
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dst_addr, socklen_t addrlen)
{
    register int __flags __asm__ ("%r10") = flags;
	register const struct sockaddr *__dst_addr __asm__ ("%r8") = dst_addr;
	register socklen_t __addrlen __asm__ ("%r9") = addrlen;
	long ret;

    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (__NR_sendto), "D" (sockfd), "S" (buf), "d" (len), "r" (flags), "r" (dst_addr), "r" (addrlen)
        : "rcx", "r11", "memory"
    );

    hook_handle_send(g_ctx.get(), sockfd, (const char *)buf, len);

    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
    long ret;
    register int __flags __asm__ ("%r10") = flags;
	register struct sockaddr *__src_addr __asm__ ("%r8") = src_addr;
	register socklen_t *__addrlen __asm__ ("%r9") = addrlen;

    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (__NR_recvfrom), "D" (fd), "S" (buf), "d" (len), "r" (__flags), "r" (__src_addr), "r" (__addrlen)
        : "rcx", "r11", "memory"
    );

    hook_handle_recv(g_ctx.get(), fd, (const char *)buf, len);

    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

int close(int fd)
{
    long ret;
    hook_handle_close(g_ctx.get(), fd);

    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (__NR_close), "D" (fd)
        : "rcx", "r11", "memory"
    );

    if (ret < 0) {
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

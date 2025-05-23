#include <asm/unistd_64.h>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <queue>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <mutex>
#include <string>
#include <regex>
#include <ctime>
#include <utility>

struct http_req
{
    time_t time_stamp;
    std::string host;
    std::string method;
    std::string uri;
};

struct sock_ctx
{
    std::string send_buf;
    std::string recv_buf;
    std::string dst_buf;

    std::queue<struct http_req> http_req_queue;

    int status;
    size_t content_length;
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
    fprintf(g_ctx.get()->file_handle, "[%s] DST : %s | HOST : %s | REQ : %s %s | RET : %d\n", time_str, ctx->dst_buf.c_str(), req->host.c_str(), req->method.c_str(), req->uri.c_str(), ctx->status);
}

static bool parse_http_req(struct sock_ctx *ctx, http_req *req, size_t& hdr_end)
{
    static std::regex method_pattern(R"(^(GET|POST|PUT|DELETE|HEAD) (\S+) HTTP/1\.[01]\r\n)");
    static std::regex host_pattern(R"((?:\r\n|^)Host:\s*([^\r\n]+))", std::regex::icase | std::regex::optimize);

    std::smatch m;
    const auto& buf = ctx->send_buf;

    if (std::regex_search(buf, m, method_pattern))
    {
        hdr_end = buf.find("\r\n\r\n", m.position() + m.length());
        if (hdr_end == std::string::npos)
            return false;

        hdr_end += 4;

        req->method = std::move(m[1]);
        req->uri = std::move(m[2]);

        std::string headers_part = buf.substr(0, hdr_end);
        std::sregex_iterator it(buf.begin(), buf.end(), host_pattern);
        std::sregex_iterator end;

        while (it != end)
        {
            if (!it->empty())
            {
                std::smatch host_match = *it;
                req->host = (*it)[1].str();
                return true;
            }

            it++;
        }
    }

    return false;
}

static size_t parse_http_res(struct sock_ctx *ctx, size_t hdr_end)
{
    static std::regex code_ret(R"(HTTP/1\.[01] (\d{3}))");
    static std::regex cl_hdr(R"(^Content-Length:\s*(\d+))", std::regex::icase | std::regex::optimize);

    std::smatch m;
    size_t n_pos = 0;

    if (std::regex_search(ctx->recv_buf, m, code_ret))
    {
        n_pos = m.position() + m.length();
        ctx->status = stoi(m[1]);

        std::string headers = ctx->recv_buf.substr(0, hdr_end);
        if (std::regex_search(headers, m, cl_hdr))
            ctx->content_length = stoul(m[1]);

        return hdr_end + ctx->content_length + 4 ;
    }

    return -1;
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

    try
    {
        if (!(domain == AF_INET || domain == AF_INET6) || !(type & SOCK_STREAM))
        {
            __rm_sock_handle(ctx, fd);
            return;
        }

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

        it->second->dst_buf = dst_tmp;
    }
    catch (...)
    {
        log_exit();
    }
}

static void hook_handle_out(struct log_ctx *ctx, int fd, const char *buf, ssize_t len)
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

        while (1)
        {
            struct http_req req;
            size_t endpos;
            if (parse_http_req(sock_ctx, &req, endpos))
            {
                req.time_stamp = time(nullptr);
                sock_ctx->http_req_queue.push(std::move(req));
                sock_ctx->send_buf.erase(0, endpos);
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

static void hook_handle_in(struct log_ctx *ctx, int fd, const char *buf, ssize_t len)
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

        while (1)
        {
            size_t end_header = sock_ctx->recv_buf.find("\r\n\r\n");
            if (end_header == std::string::npos)
                break;

            size_t parsed_len = 0;

            if ((parsed_len = parse_http_res(sock_ctx, end_header)) > 0 && !sock_ctx->http_req_queue.empty())
            {
                write_to_file(sock_ctx, &sock_ctx->http_req_queue.front());
                sock_ctx->recv_buf.erase(0, parsed_len);
                sock_ctx->http_req_queue.pop();
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
    else
    {
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

    hook_handle_out(g_ctx.get(), sockfd, (const char *)buf, len);

    if (ret < 0)
    {
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
    register socklen_t *__addrlen __asm ("%r9") = addrlen;

    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (__NR_recvfrom), "D" (fd), "S" (buf), "d" (len), "r" (__flags), "r" (__src_addr), "r" (__addrlen)
        : "rcx", "r11", "memory"
    );

    hook_handle_in(g_ctx.get(), fd, (const char *)buf, len);

    if (ret < 0)
    {
        errno = -ret;
        return -1;
    }

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

    hook_handle_out(g_ctx.get(), fd, (const char *)buf, len);

    if (ret < 0)
    {
        errno = -ret;
        return -1;
    }

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

    hook_handle_in(g_ctx.get(), fd, (const char *)buf, len);

    if (ret < 0)
    {
        errno = -ret;
        return -1;
    }

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

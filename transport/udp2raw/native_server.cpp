#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "fd_manager.h"
#include "native_backend.h"
#include "native_attach.h"
#include "native_so.h"
#include <memory>

int server_on_timer_multi(conn_info_t &);
int server_on_udp_recv(conn_info_t &, fd64_t);

namespace {
std::map<fd64_t, std::unique_ptr<ev_io>> udp_watchers;

void udp_ready(struct ev_loop *, ev_io *watcher, int) {
    const auto id = watcher->u64;
    if (!fd_manager.exist(id)) return;
    // One event loop owns fd_manager, connection state and UDP watchers.
    server_on_udp_recv(*fd_manager.get_info(id).p_conn_info, id);
}

void raw_ready(struct ev_loop *, ev_async *, int) {
    native_drain_packets(nullptr);
}

void tick(struct ev_loop *, ev_timer *, int) {
    native_so_server_tick();
    conn_manager.clear_inactive();
    for (auto &entry : conn_manager.mp) {
        auto &connection = *entry.second;
        if (connection.state.server_current_state == server_ready)
            server_on_timer_multi(connection);
    }
}
}

void native_watch_udp(fd64_t id) {
    auto watcher = std::make_unique<ev_io>();
    watcher->u64 = id;
    ev_io_init(watcher.get(), udp_ready, fd_manager.to_fd(id), EV_READ);
    ev_io_start(g_default_loop, watcher.get());
    udp_watchers.emplace(id, std::move(watcher));
}

void native_unwatch_udp(fd64_t id) {
    auto entry = udp_watchers.find(id);
    if (entry == udp_watchers.end()) return;
    ev_io_stop(g_default_loop, entry->second.get());
    udp_watchers.erase(entry);
}

// The native backend does not operate at Ethernet frame level.
int handle_lower_level(raw_info_t &) {
    mylog(log_fatal, "--lower-level is unavailable in the native backend\n");
    myexit(-1);
    return -1;
}

int server_event_loop() {
    g_default_loop = ev_default_loop(0);
    if (!g_default_loop) myexit(-1);
    if (local_addr.get_type() != AF_INET) {
        mylog(log_fatal, "native milestone 1 supports IPv4 only\n");
        myexit(-1);
    }
    if (local_addr.inner.ipv4.sin_addr.s_addr != 0) {
        bind_addr_used = 1;
        bind_addr.v4 = local_addr.inner.ipv4.sin_addr.s_addr;
    }
    // Reserve the port without making Windows perform the TCP handshake.
    if (!native_attached() && try_to_list_and_bind2(bind_fd, local_addr) != 0) {
        mylog(log_fatal, "native server port is occupied\n");
        myexit(-1);
    }
    ev_async_init(&async_watcher, raw_ready);
    ev_async_start(g_default_loop, &async_watcher);
    init_raw_socket();
    init_filter(local_addr.get_port());
    ev_timer timer;
    ev_timer_init(&timer, tick, 0, timer_interval / 1000.0);
    ev_timer_start(g_default_loop, &timer);
    mylog(log_info, "native server listening at %s\n", local_addr.get_str());
    ev_run(g_default_loop, 0);
    return 0;
}

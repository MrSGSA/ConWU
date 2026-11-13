# ConWU Phantun 承载

使用 Phantun 的 `fake-tcp` 协议栈，将已由 ConWU 认证加密的数据报放入 TCP 格式报文。它不提供真正 TCP 的重传、流控或 TLS。

来源：`dndx/phantun` 的 0.8.1 系列，以及 `zcb617/phantun-client-win` 提交 `4a18c5621122d068e74ac44a70570416944747b3` 的跨平台接口和 Windows 兼容修改。保留上游 MIT / Apache-2.0 许可。

ConWU 适配使用 WinDivert 或 Linux 原生捕获，不创建额外 TUN，也不接管系统默认路由。ConWU 管理端口所有权、共享接收器、配对、加密和进程生命周期；此组件只处理承载。网络双方都需要支持 Phantun 的 ConWU 版本。

本地修改包括：固定且已独占的客户端源端口、输入长度验证、连接数量上限、关闭时的并发处理，以及本机父进程退出保护。Phantun 的正常握手和数据格式保留。

Windows 构建使用 `cargo build --release --target x86_64-pc-windows-msvc`；运行时使用随 ConWU 提供的官方 WinDivert 2.2.2 DLL 和签名驱动。

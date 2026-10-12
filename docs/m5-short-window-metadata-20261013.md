# 短窗口观察的元数据与有效期

2026-10-13。准确提交 `c2ce2b8` 的 0.5.5 首次完整 Package 在 TCP observer 第三轮的联合断言失败；整包未生成，也未发布。失败报告和此前通过的分项保持在 `out/evidence/failed-package-055-c2ce2b8`，摘要 `artifacts/m9-package55-first-failure-20261013.json`。首轮断言没有输出各分量，不能追溯断定唯一失败原因。

源码有可确认的缺口：`TcpShapeProbe` 在检查 2 秒新鲜度后，仍对每个证据分别枚举所有网卡及其属性，再返回结果。元数据操作可能阻塞，形成“检查时有效，返回时已经过期”。本次把同一源地址的 InterfaceId 只解析一次，放在短窗口登记与首 SYN 之前；路由检查随后进行。封装结果之后再核对本机有效期。原 2 秒边界、观察窗口、20 秒准备上限、协议报文和各项包预算均未放宽。

更新后的 TCP observer 共 272 项通过，30 个同源短窗口的最大本机源年龄 **878.9292ms**；它们不是 30 个独立 NAT 分配窗口。新增受控 2200ms 元数据延迟用例确认延迟发生于首 SYN 前，返回两个同源结果仍在 2 秒内；慢登记/读取、过期代次、旧服务、冲突来源等负例继续拒绝且不泄漏 tuple/引用。

产物为 `artifacts/m5-fresh-metadata-first-20261013.json` 与 `m3-tcp-observer-final-20261013.log`。实际 HTTPS 与 TCP helper 是回环 I/O，原始 SYN 的 broker 是内存夹具；无公网 NAT、WinDivert native 承载或校园网 TCP 分类结论。此前首轮完整 Package 的失败保留；新的准确提交仍需完整回归、正式打包和相应真机 Gate。

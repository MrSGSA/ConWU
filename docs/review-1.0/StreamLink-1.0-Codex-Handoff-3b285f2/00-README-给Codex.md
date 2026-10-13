# StreamLink 1.0 / Codex 交接入口

基于用户提供的完整源码3b285f2及最终交接材料；执行规格日期2026-10-13。

## 使用

将本目录放到真实StreamLink Git仓库的 `docs/review-1.0/`，或者让Codex按实际附件位置读取。不要替换源码，不要把本目录初始化成原仓库。若真实HEAD已更新，先映射差异。

阅读顺序：
1. `StreamLink-1.0-Final-Execution-Plan-3b285f2.md`：下一轮主执行规格。
2. `StreamLink-Source-Review-3b285f2.md`：源码定位、缺陷与证据边界。
3. `StreamLink-1.0-Codex-Tasks-3b285f2.json`：32个任务、依赖、验收与门槛。
4. `review-evidence/local-review-results.json`：本轮审阅环境实际执行结果；其余网络数据仍来自原交接包。

本包不含用户源代码全量副本、Windows运行包、私钥、Linux测试二进制或字体。CHECKSUMS仅用于包内完整性检查，不是发布者数字签名。

## 直接给Codex的任务

请读取本目录全部三份执行/审查/任务文件，结合仓库指令、真实当前HEAD和原M0—M9继续推进1.0.0-rc1，不重做已实现SO、来源学习、提名和UDP同socket架构。

先复现修复SEC-01原生解析返回码/长度问题，完成控制取消、旧Quality诊断预算与故障隔离、设置无损热更新；并行推进用户界面和安全权限分离。补齐交接明确的兼容业务pacing/过载反馈、完整出口见证/同步准备、私网UDP稳定证据provider。保持HTTP/SEQ、无业务重传、禁止业务中继和健康Active。

以真实源资源上的完整FakeTCP业务与算法off/on对照验证新增覆盖，按证据晋级默认自动能力，不把全部功能永久默认关闭，也不盲目全开。推进自主网卡provider与最小自研TUN驱动源码/API/测试；自研WFP捕获后端独立有限研究，生产驱动替换须安全、签名、硬件Gate通过，默认保留官方Wintun/WinDivert。

保留当前安装负载Fail与未完成反向结果，不降低门槛刷过。真实UI配对、最终完整包安装/回退、质量/恢复、多机和冷启动按文档验收。对外部设备/拓扑/签名不足明确Block，代码未完成记Partial，不以无限复跑或新增计划外功能拖延。最终交付固定RC、32任务状态、默认能力清单、新覆盖/退化表、修复证据、驱动研发产物和发布判断；Gate未过不宣布1.0正式发布。

## 审阅环境边界

本次没有Windows/.NET SDK/PowerShell，未执行Windows驱动、真实校园网或完整产品测试。630项现有C++模型在g++ + ASan/UBSan通过。TCP解析探针只复制精确源前缀和头结构、stub IP输入，返回99是测试哨兵；它证明长度/错误返回契约问题，不证明完整网络可利用性。详见审查F01。

探针无网络I/O，可在适当Linux工具链下检查：

```sh
g++ -std=c++17 -fsanitize=address,undefined -fno-omit-frame-pointer \
  review-evidence/tcp_parser_prefix_probe.cpp -o /tmp/sl-parser-prefix-probe
/tmp/sl-parser-prefix-probe
```

这不是修复验收脚本；Codex应把失败用例接入真正完整的生产解析器再验证修复。复制的源声明/前缀来自用户提交代码，集成时保留项目和上游许可证要求。

# CTL-02：旧测速许可、统一预算与隔离

原 Quality 身份/HMAC 防线保留并加强为 `manual-v2`：MAC 绑定 Version、Op、Count、时效、发起端 IP/端口和响应端。未许可的已认证成员也不能启动负载；配置 `AllowManualQualityRequests` 默认 false，UI 可明确允许，后台独立声明 ManualQualityVersion=2。旧消息不能被新接口当作有授权的启动请求。

与自动诊断使用同一 PathDiagnosticResources.Shared 会话互斥、90 秒会话和 256MiB 上限。自动 v1 窗口仍是 15 秒；明确手动 v2 只允许一个不超过20秒的窗口及90秒冷却，新请求 ID 不重置冷却。控制回复/重试/取消计入已有全机 TraversalResources.Shared 维护额度。手动数据为每包1536B的保守封装额度扣账，不冒充物理注入字节；实际注入 pacing/过载反馈继续在 QOS-01 补齐。普通独立双向手测必须遵守冷却，不用关闭预算刷过。

取消不仅停止 GUI 等待：发起端发送限定次数、限定期限的签名取消，对端终止当前匹配发起 IP/端口/ID 的实际发送。默认无许可有明确拒绝回复；端口故障仅禁用可选诊断，正式 MeshRunner 不重建网卡、不重启全部 peer。合法业务通过原 MeshLink，没有增加业务重传。

本轮真实回环 socket 验证许可/数据/取消；共享预算以可控时钟验证；正式 MeshRunner 在真实 UDP 端口占用后仍认证对端并交付完整内层 IP（使用 memory adapter/UDP forwarding夹具，不是真机 FakeTCP 或 WAN）。对应15＋4项专项检查、35项 Core、14项 Control 和100项 Windows UI/lifecycle通过。原 socket 质量门槛未下降；fixture明确模拟不同逻辑机器的独立诊断池，正式代码始终用 Shared。结果保留一秒收尾口径，不宣称期限内/单向送达。

证据见 `evidence/quality/`。真正两Windows的许可、Wintun数据与Native注入账本还需后续。当前 Akane `10.129.129.1` 的只读SSH探测超时；不把它写成算法不支持或关机已确认，也不无限重试。

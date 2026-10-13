# 控制操作及设置的第一批集成

修复前真实 ControlWorker 隔离夹具有 4/5 项失败：返回配置对象别名、状态排队、名称/日志保存停止 worker、未知字段丢失。当前 14 项隔离 Windows 检查与原 100 项 Windows 生命周期/界面检查通过，GUI 构建无警告/错误。此处不注册或替换当前生产服务、不加载驱动。

控制令牌贯穿排队与退出；操作有 ID/阶段/取消/重复请求幂等，同 ID 不接受不同内容。状态读取使用已生成快照，绕过管理锁；配置对象为深拷贝。后台管道最多八个并发实例，保持 SYSTEM/管理员 ACL、首实例保护及远程 SMB 拒绝。前台状态/取消同样不经长操作锁。没有把完整私密控制接口开放给普通用户。

网络/测速退出共同最多等待 15 秒；取消 UI 等待不解除仍使用中的运行资源，也不启动第二实例。调用 Dispose 仍有 work 时保留 runtime.lock 到 work 确认结束；StopLocal/Dispose 重复取消已释放令牌的实测失败单独保留，修复后通过。真实捕获挂起、精确 Job 强制退出及实际并发管道仍需后续 NET-01/集成证据，不以本夹具代替。

设置按差异分类：设备名、日志和未知未来字段可热保存；源端口、模式等网络参数仍走显式资源重建，保留身份修改拒绝与实际 LastStun/LastEntry，磁盘保存成功才提交新配置。正在运行的名称引用同步更新，不改变网卡/worker。本批尚未完成 UI 意图与暂不可用能力分离、逐参数影响提示，UI-02 状态继续 InProgress，不将其标全完成。

测试：`dotnet run --project tests/StreamLink.ControlTests -c Release`，`dotnet run --project tests/StreamLink.WindowsTests -c Release`。修复前后及中间失败证据在 `evidence/control/`。当前默认 HTTP/SEQ、外层无业务重传、禁止业务中继未改。

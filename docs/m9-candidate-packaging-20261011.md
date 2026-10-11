# M9：0.5.0 开发候选打包准备

本项推进可安装交付，不表示 M0—M9 已全部完成。0.5.0-preview 的发布等级固定为 `development-candidate`、`releaseGate=NotPassed`；真实公网、八 Windows、长时负载、协调中断和未登录启动另行验收。

## 打包约束

`scripts/Package.ps1` 要求干净且已提交的源码，默认执行原有打包回归、生产 native 构建及自包含 Windows x64 发布。记录源码 commit、.NET SDK、PowerShell、OS、CMake 配置/编译命令哈希和所有发布文件哈希。

生产 native 路径固定为 `out/native/udp2raw-native.exe`，额外核验 `--native-info` 的 WinDivert backend 和 HTTP profile。协议测试后端不能打包为生产后端。应用和服务程序集版本须与清单一致。`SkipBuild` 只能复用同 commit/版本、完整文件列表及哈希一致的构建收据，不能把旧发布目录当作当前源码。

保留官方 WinDivert 驱动签名、Wintun 固定哈希及运行时/组件许可证校验。默认不含 EasyTier，用户运行无需 WSL、Python 或开发工具链。源包从准确 commit 的 `git archive` 生成，排除未跟踪部署配置、缓存与实验私有文件。

每个候选包含开发验收状态、规格、版本说明及构建来源。完整发布目录写入 manifest 后，实际自包含 `StreamLink.exe --verify-bundle` 只读校验每个文件，不启动后台、不加载驱动、不改网络。只有通过才压缩发布目录。文件哈希证明完整性，不构成产品代码签名或可信发布渠道的替代。

## 安装前检查加固

在任何安装目录写入和 SCM 操作之前验证清单：数量/大小、相对规范路径、重复路径、Windows ADS/保留名称、实际长度与 SHA-256。拒绝绝对地址、`..`/`.`、空段、末尾点/空格以及经 reparse point 的路径；安装目标必须位于本次受管目录内。原代码只检查源路径前缀，对“绝对地址恰好位于源目录”的条目约束不足，此次已修复。

文件复制后再次核对哈希；保存的是本次已读取验证的 manifest 字节，避免第二次复制可变源清单。UTF-8 BOM 兼容保留。文件清单最多 4MiB/4096 项，读取前限制分配。

应用和服务版本为 0.5.0。服务仍安装到 Program Files 下按版本/manifest 哈希隔离的目录，保留旧目录；停止与升级仅针对 StreamLink。此次未在实际 SCM 执行安装、升级、卸载或重启。

## 隔离验证

`artifacts/m9-bundle-final-20261011.log`：51 项 Windows 生命周期、DPAPI、单后台、清单、安装副本和界面反馈检查通过。新增规范路径/绝对地址/ADS/别名/重复项、目标边界、只读预检与 BOM 检查。实际复制在临时目录，未访问线上 profile、SCM、驱动、路由或网卡。

打包脚本及本地验收脚本 PowerShell 语法检查通过。另修复本地验收脚本硬编码检查数量可能导致错误总状态的问题：以全部预定调用完成且无失败判断 Local，新增 pacing 正确性检查；性能和真实网络 Gate 仍独立，不能被 Local Pass 覆盖。

正式包构建结果、hash、体积与后续验证会另附产物记录。回退步骤见 `docs/releases/v0.5.0-preview.md`。尚未执行的真实安装、服务自动启动和回滚恢复不能根据临时目录测试标为通过。

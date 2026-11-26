# Projection 的上游组件与源码

Windows x64 的 Projection 使用以下上游发布资产。带内嵌播放的包使用同一 Moonlight 版本的源码重构建，并附带改动补丁。

| 组件 | 发布版本 | Windows 资产 | SHA-256 |
| --- | --- | --- | --- |
| Sunshine | v2026.914.233613 | Sunshine-Windows-AMD64-lite.zip | `233008e46f4c0e501a586cbfd6c4fd4a4c0d414a0b5fc7f13c070eb92ec3824b` |
| Moonlight Qt | v6.2.0 | MoonlightPortable-x64-6.2.0.zip | `6f91d268b41ed5ca8066d9d7578dc403b8db190991ff48f00b1700465f8f7ebf` |

Sunshine 使用 GPL-3.0。对应源码为提交 `63d35f702ee9e362e43263742981836ec0710384`，上游仓库包含构建说明及对应的子模块引用。[发布资产](https://github.com/SunshineStream/Sunshine/releases/tag/v2026.914.233613) · [源码及构建输入](https://github.com/SunshineStream/Sunshine/tree/v2026.914.233613)

Moonlight Qt 使用 GPL-3.0。对应源码为提交 `de2467e433821664cdd2224aad8c89a625be1ad9`，上游仓库包含 Windows 构建说明、依赖配置及对应的子模块引用。[发布资产](https://github.com/moonlight-stream/moonlight-qt/releases/tag/v6.2.0) · [源码及构建输入](https://github.com/moonlight-stream/moonlight-qt/tree/v6.2.0)

获取完整源码时使用 `git clone --recurse-submodules --branch <发布版本> <仓库地址>`。两款组件的许可证与 Sunshine 的上游声明随包置于 `licenses/`。

Windows 内嵌版还使用 SDL 3.4.18 的小幅焦点修订。ConWU 播放区获得键鼠焦点时，SDL 会跟踪实际收到输入的子窗口。[SDL 3.4.18 源码](https://github.com/libsdl-org/SDL/tree/release-3.4.18) · [焦点补丁](sdl3-conwu.patch)

## 内嵌播放的构建

在 Moonlight Qt v6.2.0 源码和子模块上应用补丁。Windows x64 构建使用上游的 v19 Windows x64 依赖、Qt 6.12.0 MSVC 2022 和 Visual Studio x64 工具链。使用下列命令前，将对应工具加入当前进程的环境。[Moonlight 补丁](moonlight-conwu.patch) · [Moonlight 依赖](https://github.com/moonlight-stream/moonlight-qt/tree/v6.2.0/libs) · [Qt 6.12 源码](https://download.qt.io/archive/qt/6.12/6.12.0/)

```powershell
git -C $moonlightSource apply "$repo/third-party/projection/moonlight-conwu.patch"
git -C $sdl3Source apply "$repo/third-party/projection/sdl3-conwu.patch"
cmake -S $sdl3Source -B $sdl3Build -G "Visual Studio 17 2022" -A x64 -DSDL_SHARED=ON -DSDL_STATIC=OFF -DSDL_TEST_LIBRARY=OFF -DSDL_TESTS=OFF -DSDL_EXAMPLES=OFF
cmake --build $sdl3Build --config Release --target SDL3-shared --parallel 1
Push-Location $moonlightBuild
qmake "$moonlightSource/moonlight-qt.pro"
jom -j 2 release
Pop-Location
& "$repo/rust/Stage-ProjectionMoonlight.ps1" -MoonlightSource $moonlightSource -MoonlightBuild $moonlightBuild -Sdl3Runtime "$sdl3Build/Release/SDL3.dll" -QtBin $qtBin -Output "$repo/out/projection-runtime"
```

将该运行目录交给 `package.py --projection-embedded-runtime`。Moonlight 和 SDL3 的对应补丁随包保存在 `source/`。

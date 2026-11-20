# ScyllaHide for IDA Pro 9.0 / 9.4

本项目基于开源用户态（Ring 3）反反调试框架 [x64dbg/ScyllaHide](https://github.com/x64dbg/ScyllaHide)，完成了对 **Hex-Rays IDA Pro 9.0 SDK** 与 **IDA Pro 9.4 SDK** 的完整适配与重构，支持 **Windows x64 / x86（WOW64）PE** 程序的自动反反调试隐藏。

> 如需内核态（Ring 0）反反调试，请参考 [TitanHide](https://github.com/mrexodia/titanhide)。

---

## 主要特性与适配亮点

- **原生支持 IDA 9.0 & IDA 9.4（x64）**：
  - 从原版 32 位 `.plw`（IDA 6.x API）全面迁移至 **64 位原生 `.dll` + `__EA64__`**。
  - 采用现代 IDA 9.x 插件模型：`PLUGIN_MULTI` + `plugmod_t` + `event_listener_t`（替代已移除的 `hook_to_notification_point`、`inf.filetype`、`ui_get_hwnd`、`askstr` 以及旧版 6 参数 `get_process_options`）。
  - 附带标准 **`ida-plugin.json`** 描述文件，支持以独立子文件夹 `plugins\ScyllaHide\` 形式安装与管理，不污染 IDA `plugins\` 根目录。
- **全自动覆盖 x64 / x86 目标**：
  - **本地 64 位 PE**：64 位 IDA 插件直接进程内无痕注入 `HookLibraryx64.dll`，无需额外 Server。
  - **本地 32 位 PE（WOW64）**：自动检测目标进程为 WOW64，自动拉起同目录 `ScyllaHideIDAServerx86.exe` 并通过 `127.0.0.1` 代理注入 `HookLibraryx86.dll`。
  - **远程 Windows 调试（x64 / x86）**：按目标架构自动匹配 `ScyllaHideIDAServerx64.exe` 或 `ScyllaHideIDAServerx86.exe`，支持按需自动启动与连接重试。
- **修复原版 `ScyllaHideIDAServer` 缺陷**：
  - 修复 `hookNtContinue` 错映射到 `EnableNtCloseHook`、`fixPebOsBuildNumber` 漏映射、注入前未初始化 `ReadNtApiInformation` 及架构不匹配时进程卡死的问题。
  - 资源文件 `.rc` 移除对 MFC `afxres.h` 的依赖（替换为 `winres.h`），标准 VS 2022 C++ 工具链即可直接编译。

---

## 支持矩阵

| 调试场景 | 目标架构 | 注入链路 | 是否自动生效 |
| :--- | :--- | :--- | :--- |
| **本地 Windows 调试** | x64（64 位 PE） | 插件进程内直接注入 `HookLibraryx64.dll` | 自动（F9 即生效） |
| **本地 Windows 调试** | x86（32 位 WOW64 PE） | 自动拉起 `ScyllaHideIDAServerx86.exe` 代理注入 `HookLibraryx86.dll` | 自动（F9 即生效） |
| **远程 Windows 调试** | x64 / x86 PE | TCP 连接目标机对应位数的 `ScyllaHideIDAServer*.exe` | 自动（目标机需运行对应 Server） |

> 限制说明：仅适用于 **Windows PE** 调试，不支持 Linux ELF / Android / macOS。

---

## 安装与使用

### 1. 安装插件

直接将对应版本打包好的整个 `ScyllaHide` 文件夹复制到 IDA 的 `plugins\` 目录即可：

- **IDA Pro 9.0**：复制 `Release\IDA9.0\ScyllaHide\` 到 `<IDA 9.0 安装目录>\plugins\ScyllaHide\`
- **IDA Pro 9.4**：复制 `Release\IDA9.4\ScyllaHide\` 到 `<IDA 9.4 安装目录>\plugins\ScyllaHide\`

插件文件夹包含以下文件（请保持在同一目录）：

```text
plugins/ScyllaHide/
├── ida-plugin.json               # IDA 9.x 子目录插件清单
├── ScyllaHideIDAProPlugin.dll    # IDA 9.0 或 9.4 对应版本的 x64 插件本体
├── HookLibraryx64.dll            # 64 位目标 Hook 库
├── HookLibraryx86.dll            # 32 位目标 Hook 库
├── ScyllaHideIDAServerx64.exe    # 64 位远程调试代理服务
├── ScyllaHideIDAServerx86.exe    # 32 位本地 WOW64 / 远程调试代理服务
└── scylla_hide.ini               # 配置文件（预设 Profile 与开关）
```

### 2. 使用方式

1. 打开任意 Windows PE 文件，IDA 会**自动初始化**插件并在 Output 窗口打印横幅：
   ```text
   ##################################################
   # ScyllaHide v1.4 (IDA SDK 900/940) ...          #
   ##################################################
   ```
2. **首次配置（只需一次）**：按 **`Alt-X`**（或菜单 `Edit -> Plugins -> ScyllaHide`）打开设置窗口，选择合适的 Profile（如 `Basic`、`VMProtect`、`Themida` 等）或自定义勾选项，点击 **Apply / OK** 保存至 `scylla_hide.ini`。
3. **日常调试全自动生效**：之后每次打开任意 PE 直接按 **F9** 启动调试即可，无需先下断点、也无需每次手动 Apply。
   - **64 位本地目标**：Output 窗口会打印 `[ScyllaHide] Hook injection successful, image base 0x...`。
   - **32 位本地目标**：会自动弹出 `ScyllaHideIDAServerx86.exe` 控制台窗口代理注入（调试期间请勿手动关闭）。
4. **附加调试（Attach）或热更新**：
   - 如使用 Attach 附加到已运行进程，或在调试中途修改了配置开关，按 `Alt-X` 打开设置框点击 **OK** 即可立即应用（无需重启目标）。

---

## 从源码编译

### 环境要求

- Windows 10 / 11（x64）
- Visual Studio 2022（MSVC `v143` C++ 桌面开发工具链，含 x64 与 x86 编译器）
- 官方 IDA SDK（已支持从 [HexRaysSA/ida-sdk](https://github.com/HexRaysSA/ida-sdk) 拉取）：
  ```bash
  git clone --depth 1 --branch v9.0.0-release https://github.com/HexRaysSA/ida-sdk.git 3rdparty/idasdk90
  git clone --depth 1 --branch v9.4.0-sdk.1   https://github.com/HexRaysSA/ida-sdk.git 3rdparty/idasdk94
  ```

### 一键编译并打包

直接运行根目录下的脚本：

```bat
build_ida9.bat
```

脚本会自动编译 x64 / Win32 版本的 `Scylla`、`HookLibrary`、`ScyllaHideIDAServer`，并分别链接 IDA 9.0 SDK 与 IDA 9.4 SDK 编译插件，最终产出到：

- `Release\IDA9.0\ScyllaHide\`
- `Release\IDA9.4\ScyllaHide\`

### 手动指定自定义 SDK 路径（可选）

如果本地已有其他路径的 IDA SDK，可通过 MSBuild 属性覆盖：

```bat
msbuild ScyllaHide.sln /t:ScyllaHideIDAProPlugin ^
  /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 ^
  /p:IdaSdkVersion=94 ^
  /p:IdaSdkIncludeDir="D:\path\to\idasdk\include" ^
  /p:IdaSdkLibDir="D:\path\to\idasdk\lib\x64_win_64"
```

---

## 工作原理简述

ScyllaHide 工作在用户态（Ring 3）运行期内存层，不修改磁盘文件：

1. **进程启动瞬间介入**：监听 IDA `HT_DBG` 的 `dbg_process_start` 事件，在目标进程刚创建、任何用户代码与 TLS 回调执行前挂起所有线程；后续在每次 `dbg_library_load` 时增量补齐 Hook。
2. **无痕手动映射（Manual Mapping）**：由 `DynamicMapping` 手动将 `HookLibrary` 映射进目标进程并完成重定位、导入表修复，同时擦除 PE 头且不写入 `PEB->Ldr` 模块链表。
3. **PEB 标志位修补**：直接修改目标进程 PEB（32 位目标同时修补 PEB32 与 PEB64），清除 `BeingDebugged`、`NtGlobalFlag`、堆标志、`StartupInfo` 等调试痕迹。
4. **远程 Inline Hook**：借助 `distorm` 反汇编引擎在目标进程内的 `ntdll.dll`、`kernel32.dll`、`user32.dll`/`win32u.dll` 关键反调试 API 入口安装 Trampoline 跳转，接管并过滤返回值。

---

## 相关文档与协议

- 原版 ScyllaHide 详细文档：[ScyllaHide.pdf](https://github.com/x64dbg/ScyllaHide/releases/download/docs-2019-05-17/ScyllaHide.pdf)
- 上游项目：[x64dbg/ScyllaHide](https://github.com/x64dbg/ScyllaHide)（Forked from NtQuery/ScyllaHide）
- 开源协议：[GNU General Public License v3 (GPL-3.0)](LICENSE)

### 致谢（上游项目）
- What — POISON Assembler source code
- waliedassar — Anti-debugging research & blog posts
- Peter Ferrie — *The "Ultimate" Anti-Debugging Reference*
- MaRKuS-DJM — Olly Advanced
- Lim Bio Liong — MS Spy++ style Window Finder

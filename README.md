# vis — WWFilter 全新透明加密客户端

全新实现的透明文件加密客户端（minifilter 驱动），不依赖任何旧
客户端的 DLL / 驱动。只按旧客户端现有的策略与加密逻辑重写：
S-box 流密码、512 字节文件头、.xcf 策略语义。

目标：Windows 全兼容、透明、兼容旧客户端加密格式、去掉许可证
与装机数量验证。

## 目录

- `wwflt/` — minifilter 驱动源码（WDK，C，x64）
  - `DESIGN.md` — 架构设计（必读：策略模型、I/O 规则、预留接口）
  - `wwflt.c` — 驱动主源码
  - `sbox.c` / `sbox.h` / `sbox_tables.h` — S-box 流密码
  - `wwflt.h` — 驱动与服务共用的 IOCTL / 策略 / 状态 / 事件定义
  - `wwflt.sln` / `wwflt.vcxproj` — Visual Studio 工程
  - `README-BUILD.md` — 本地编译说明（VS + WDK）
- `.github/workflows/build-driver.yml` — GitHub Actions 编译
  （windows-2022 runner，WDK 已预装；产物为 `wwflt.sys`）

## 编译（GitHub Actions）

推到 `main` 即自动编译。产物在 Actions 运行页下载：
`wwflt-Release-x64`（含 `wwflt.sys` 与 `wwflt.pdb`）。

## 测试

只在 PVE 虚拟机（Win10 专业版）上测，测前打快照，先用文件副本。
详见 `wwflt/DESIGN.md` §8 与 `wwflt/README-BUILD.md`。

## 状态

Phase 1：minifilter 核心（512 头 + S-box + 按现有 .xcf 策略判定）。
策略更新接口、管理 GUI、加解密日志、服务端为预留接口（见
`wwflt/DESIGN.md` §7），后续再做。

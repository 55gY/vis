# WWFilter 构建说明（Windows 上编译）

内核驱动在 Linux 下编不了。源码在 `wwflt/`，在 Windows 上用
WDK 编。目标：Win10 x64（测试机）；Win7 / Win11 以后再测。

## 1. 装工具（Windows 机器上，一次性）

- Visual Studio 2022（装 “C++ 桌面开发”；WDK 需要它）
- Windows Driver Kit (WDK) for Windows 10/11（与所装 VS 版本配套；
  从微软官网下 WDK + 对应的 Windows SDK）
- 装完确认 VS 里能新建 “Kernel Mode Driver” 工程（说明 WDK 已接好）

## 2. 编译

1. 把整个 `wwflt/` 文件夹拷到 Windows 机器上。
2. 双击 `wwflt.sln`（Visual Studio 打开）。
3. 选 **Release | x64**，Build → Build Solution。
4. 产物在 `x64\Release\wwflt.sys`（另有 `wwflt.inf` 需另写，见下）。

> 注意：`wwflt.vcxproj` 已配好 `fltMgr.lib` 与
> `_WIN32_WINNT=0x0A00`。若 VS 报错说缺 WDK 目标文件，
> 说明 WDK 版本与 VS 不配套，按微软的版本对照表重装匹配的 WDK。

## 3. 测试签名（开发期加载未签名驱动）

在**测试虚拟机**上（不要在主力机上做）：

```
bcdedit /set testsigning on
bcdedit /set nointegritychecks on
```

然后关安全启动（虚拟机设置里关 Secure Boot），重启。
桌面右下角出现 “测试模式” 水印即表示已生效。

给驱动做测试签名（用 WDK 自带的 signtool + 测试证书）：

```
makecert -r -pe -ss PrivateCertStore -n "CN=WWFilter Test" test.cer
signtool sign /s PrivateCertStore /n "WWFilter Test" /t http://timestamp.digicert.com x64\Release\wwflt.sys
```

或直接用 VS 工程的 “Driver Signing → Test Certificate” 自动签名。

## 4. 安装驱动（测试虚拟机上）

需要一份 `wwflt.inf`（安装信息文件，另写；或直接用 `sc` + 注册表）：

最简办法（先用 sc，不用 inf）：

```
sc create WWFilter type= kernel binPath= C:\path\to\wwflt.sys
sc start WWFilter
```

> minifilter 正常应走 `fltmc load wwflt`（需 inf 注册到
> `HKLM\SYSTEM\CurrentControlSet\Services\FltMgr`）。`sc` 方式
> 只能起服务，filter 不会自动 attach 到卷。Phase 1 先用
> `fltmc load` + 一份最小 inf；inf 文件待补。

**测前先打虚拟机快照。** 驱动 bug 会直接蓝屏，快照是唯一后悔药。

## 5. 服务对接（wwsvc）

服务（`wwsvc.exe`）负责：

1. 用 SCM 起 `WWFilter` 服务（或 `fltmc load wwflt`）。
2. 读本地 `wwkrn.xcf`，解析策略，拼成 `WWFLT_POLICY`，
   经 `IOCTL_WWFLT_SET_POLICY` 下发到驱动
   （设备 `\\.\WWFilter`）。
3. 定时经 `IOCTL_WWFLT_GET_EVENTS` 读事件环，写 `wwflt.log`。
4. 经 `IOCTL_WWFLT_GET_STATUS` 查状态。

这部分在 `wwsvc/` 里另做（见 `PLAN.md` / `DESIGN.md` §6-§7）。

## 6. 验收（Phase 1，干净虚拟机）

1. 驱动加载成功（`fltmc filters` 里能看到 WWFilter）。
2. 服务下发策略成功（`GET_STATUS` 里 policy_version > 0）。
3. 记事本新建 .txt、保存 → 磁盘文件有 512 字节头 + 密文，
   Python 解密脚本（`decrypt_waterwall.py`）能解回明文。
4. 重新打开该文件 → 记事本看到明文。
5. 压力：循环开/关 1 万个文件，驱动池用量回到基线（不漏内存）。
6. 正确性：写已知数据（多种大小、随机 seek 写、局部写），
   读回逐字节比对；多进程同时写不同文件。

**先用文件副本测，不碰真实文件。**

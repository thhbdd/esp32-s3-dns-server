# 固件下载、首次刷机、OTA 升级与恢复（v1.0.4）

> 本文档由 AI 整理生成。

本指南面向 **ESP32-S3 N16R8：16MB Flash + 8MB Octal PSRAM**。与 Arduino `.ino` 项目不同，本项目由 ESP-IDF 构建。**只安装固件的用户不需要安装 ESP-IDF**，使用发行版提供的 `.bin` 即可。

## 1. 从 Releases 下载哪一个？

前往 [**v1.0.4 Releases 页面**](https://github.com/thhbdd/esp32-s3-dns-server/releases/tag/v1.0.4) 下载：

| 文件 | 内容 | 用途 | 烧录地址 |
|---|---|---|---|
| `merged-binary.bin` | Bootloader + 分区表 + OTA 初始化 + 应用固件 | 首次烧录、恢复完整镜像 | **`0x0`** |
| `esp32s3_dns.bin` | 仅 ESP-IDF 应用镜像 | Web UI OTA、或在匹配分区的设备上单独写入应用区 | **OTA：不需要地址**；手动写初始 `ota_0` 才用 `0x20000` |
| `SHA256SUMS.txt` | 两份镜像的 SHA-256 | 检测下载损坏/误用 | 无 |

固件 SHA-256 校验值：

```text
1238cf51d1212021b4d39c0c5c2262cb3027ad855c8341dcd05f368ffe22c9bb  merged-binary.bin
3258f34aeedd060531af02462e295957d5a5b438a66a08fb698f3bf6ba9c0604  esp32s3_dns.bin
```

应用镜像读取到的 ESP-IDF 版本描述符为 **1.0.4**，体积 **1,223,872 字节**，小于当前项目 `0x180000`（1.5MiB）OTA 应用槽。完整镜像为 **1,354,944 字节**。镜像尺寸及版本号来自随仓库提供的固件文件。

Windows PowerShell 校验：

```powershell
Get-FileHash .\merged-binary.bin -Algorithm SHA256
Get-FileHash .\esp32s3_dns.bin -Algorithm SHA256
```

Linux：

```bash
sha256sum -c SHA256SUMS.txt
```

## 2. 首次烧录方法 A：Windows Flash Download Tool

1. 使用数据 USB 线连接 ESP32-S3；如果板卡需要手动进入下载模式，一般按住 `BOOT`、短按 `EN/RST`、松开 `BOOT`。不同开发板的 USB-UART 与 USB-JTAG/Serial 驱动略有差异。
2. 打开 Espressif Flash Download Tool，选择 **ESP32-S3** 芯片系列。
3. 添加 `merged-binary.bin`，在起始地址栏填写 **`0x0`**。**不要同时再添加一个单独应用 `esp32s3_dns.bin`**，以免覆盖。
4. 参考本构建的 Flash 参数选择 **16MB / 80MHz / DIO**。如果工具版本显示不同字段，请以镜像头中的配置与开发板硬件相符为准。
5. 选择正确的 `COM` 端口。传输速度可先用 `460800`，高速度不稳定就降到 `115200`。
6. 开始烧录，等待完成；结束后按 `EN/RST` 重启。检查串口日志是否出现 Wi-Fi 设置热点，并确认 Web 服务启动成功。

**擦除提示：** 从其他程序切换到本固件、且 Flash 分区布局不兼容时，建议先备份必要数据再擦除全片。**擦除会永久删除设备已有 Wi-Fi、规则、TLS 证书和 OTA 配置**。同项目正常升级不需要全片擦除。

## 3. 首次烧录方法 B：esptool 命令行

Windows（在含 Python/esptool 的终端中；端口换成实际 `COM`）：

```powershell
python -m esptool --chip esp32s3 -p COM3 -b 460800 write-flash 0x0 merged-binary.bin
```

Linux（串口可能是 `/dev/ttyACM0`、`/dev/ttyUSB0`）：

```bash
python -m esptool --chip esp32s3 -p /dev/ttyACM0 -b 460800 write-flash 0x0 merged-binary.bin
```

完整镜像包含了各自固定地址的分区与应用，**从偏移 `0x0` 写入**；不必再单独设置分区表、bootloader 和 app 的偏移。`merged-binary.bin` 包含空洞位置的填充，但并非整个 16MiB Flash 的转储；未被覆盖的其他区域是否保留旧配置取决于你是否执行全片擦除。

## 4. 首次联网和 DNS 验证

完成首次烧录后，设备会启动热点或连接已有的 STA 配置。连接 `ESP32-DNS-XXXX` 等设置热点，在浏览器打开 **`http://192.168.4.1/`**（此地址是设备处于热点模式时的默认地址，不是加入家中 Wi-Fi 后的固定地址）。

首次设置热点默认密码请核对当前固件及 [首次配置说明](FIRST_RUN.md)。在网页输入实际 Wi-Fi SSID/密码并保存。设备加入路由器后，在 DHCP 客户端列表查到局域网 IPv4 地址；后续浏览器访问 `http://设备LAN_IP/`。

```bash
# 在 Linux PC 上测试（把设备IP替换成你的地址）
nslookup www.baidu.com 192.168.31.7
# 如果安装 dig，可测试 UDP 与 TCP
 dig @192.168.31.7 www.baidu.com A +time=2 +tries=1
 dig @192.168.31.7 www.baidu.com AAAA +tcp +time=3 +tries=1
```

Web UI 能访问并不代表 DNS 已启动。建议同时检查串口是否存在 `cannot start threads`、Web Server 监听失败或订阅编译失败。

## 5. Web UI OTA（推荐后续升级方法）

**只有设备正在运行本项目的兼容分区布局并能正常进入 Web UI 时才推荐使用 OTA。**

1. 在 Web 管理后台备份配置。不要把包含 TLS 私钥、密码的备份上传到 GitHub。
2. 确保设备供电稳定、Wi-Fi 稳定且你可以在失败时通过 USB 串口救援；更新期间不要主动断电。
3. 从 Releases 下载 **`esp32s3_dns.bin`** 并核对 SHA-256；**不是** `merged-binary.bin`。
4. 打开 `http://设备LAN_IP/`，进入「**系统 → 固件升级 / OTA**」，选中 **`esp32s3_dns.bin`**，上传并等待应用校验与重启。
5. 重启后重新连接设备，确认版本变为 `1.0.4`，DNS UDP/TCP、订阅列表与主要配置仍在。必要时看 ESP-IDF 串口日志/OTA 引导分区。
6. 如失败，先确认 OTA 槽有足够空间、上传的文件确为 ESP32-S3 应用镜像、Web 连接没中断，并检查当前分区表与新版本一致。

**OTA 只写入未运行的应用分区**，不会升级 bootloader 或分区表。若今后版本确实调整分区布局，不能仅用普通 OTA 应用镜像替代完整刷机。

## 6. 从源码自行构建（开发人员）

安装 ESP-IDF v6.1 工具链（本次附带镜像由该环境编译；代码 CI 还声明了 v5.5 构建任务，但不能据此认定通过）。Windows 建议使用全英文路径，避免 Python/CMake/Kconfig 在含中文路径时发生乱码。

```powershell
cd D:\esp32-s3-dns-server
idf.py set-target esp32s3    # 首次构建执行一次
idf.py build
idf.py merge-bin
```

- `build/esp32s3_dns.bin`：可用于 OTA 的应用 BIN。
- `build/merged-binary.bin`：合并固件；仅在 `idf.py merge-bin` 成功后出现。
- `build/flash_args`：ESP-IDF 具体烧录偏移；修改了分区布局时按同次构建文件为准。
- 不要每次都运行 `set-target` / `fullclean`；日常改代码后可直接 `idf.py build`，保留 Ninja 增量缓存。
- `sdkconfig` 和 `managed_components` 是构建产物，不作为仓库源码跟踪；默认设置在 `sdkconfig.defaults`，cJSON 由 `main/idf_component.yml` 声明下载。

如果升级后的设备显示旧版本，需要同时检查 `CMakeLists.txt` 的 `PROJECT_VER`、构建配置中的 App version 和应用 BIN 的版本描述符，而不是单看 `.bin` 文件时间。保留原 Bootloader 的双 OTA 槽版本信息也需要对应验证。

## 7. 故障恢复

| 情况 | 首先检查 |
|---|---|
| 热点能 ping，但网页打不开 | 串口中 Web Server 是否真正启动；ESP32-S3 的片内 RAM 是否已被 Wi-Fi/线程栈耗尽 |
| 规则更新 `out of memory (arena / symbol table)` | 当前规则总量、编译工作区/PSRAM、当前固件是否是 v1.0.4；并确认是新错误还是旧错误残留 |
| 文件 OTA 拒绝 | 是否上传错了 `merged-binary.bin`；应用大小、分区布局、芯片目标是否相符 |
| 重启后进不了 Web | 先用串口监控 Bootloader 和应用日志；如需恢复再刷 `merged-binary.bin` 到 `0x0`，必要时先擦除并重新配置 |
| 证书配置失效 | 检查导入的 PEM、公私钥匹配、证书域名 SAN 与当前设备时间 |

其他详见 [排障手册](TROUBLESHOOTING.md)、[Flash/规则分区](RULES_AND_STORAGE.md) 和 [系统安全](TLS_AND_SECURITY.md)。

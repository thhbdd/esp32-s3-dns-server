# ESP-IDF v6.1 组件迁移与构建说明

> 本文档由 AI 整理生成。

## 为什么旧版直接编译失败

ESP-IDF 6.0 及之后的版本移除了内置 `json` 组件，而旧 `main/CMakeLists.txt` 仍写了 `REQUIRES ... json ...`，因而 CMake 在正式 C 编译之前停止。此问题不属于硬件或 Windows 配置错误。

当前源码使用 `main/idf_component.yml` 声明官方 `espressif/cjson: "^1.7.19"`，并从 CMake 的 `REQUIRES` 删除了 `json`。IDF 组件管理器会下载依赖到 `managed_components/`，无需手工复制 `cJSON.h`。**首次配置需要能访问 Espressif Component Registry 的网络。**

ESP-IDF v6.x 的 Mbed TLS 改为 v4.x；源码还按主版本号切换私钥解析/密钥配对函数参数，并使用 PSA SHA-256 计算认证摘要，保持已存密码摘要兼容。

## Windows PowerShell 构建（使用官方 ESP-IDF 终端）

```powershell
cd "D:\esp32-s3-dns-server"
# 新解压、且尚未生成 build 的项目，只需要首次选择芯片：
idf.py set-target esp32s3
idf.py build
# 以后修改源码：只运行 idf.py build；不要反复 set-target/fullclean
```

不希望 `set-target` 修改已有配置时，在备份配置后运行 `idf.py reconfigure`；若已经使用旧源码执行失败，推荐在保留 `sdkconfig.defaults` 的前提下重新配置。所有源代码应置于**修正版根目录**，确认存在 `main/idf_component.yml`。

如果组件管理器提示网络错误，先检查开发机是否能访问 `components.espressif.com`。不要仅删除 `json` 依赖而不添加 `espressif/cjson`，否则后续会出现 `cJSON.h` 找不到或链接失败。

## 如何识别第二类编译错误

Mbed TLS 4 取消了 `mbedtls_pk_parse_key` 与 `mbedtls_pk_check_pair` 的 RNG 回调参数，旧版会报 `too many arguments to function`；另一些旧 SHA-256 API 被移除。本版本在 `main/web.c` 与 `main/app_config.c` 添加了不同 Mbed TLS 主版本的调用路径。

**重要：** 本次沙盒没有安装 Xtensa/ESP-IDF 交叉编译器，无法保证其它 ESP-IDF v6.1 API、Kconfig 或 OTA 分区编译不会继续报错。请以在你本机执行 `idf.py build` 的实际输出为准。不要将主机测试通过等同于固件已能刷机。

## web.c 编译错误的已知修正（2026-10-16）

Windows / ESP-IDF v6.1 构建时曾报告：`DNS_MSG_MAX` 在 `web.c` 中未定义，以及 `HTTPD_DEF_CTRL_PORT` 名称错误。后者并不需要替换成另一宏：HTTPS 的 `HTTPD_SSL_CONFIG_DEFAULT()` 默认就使用与 HTTP 不同的内部控制端口，因此直接移除了覆盖语句。前者改为与 DNS 核心输入限制相同的局部常量 `DOH_MAX_WIRE_MSG`（4096 字节）。

这两处修复不增加运行时分配。已经完成 Linux 主机代码与文档检查，但没有 ESP-IDF Xtensa 编译环境，**不能将它写成固件交叉编译已经成功**。如果之后在链接或者设备运行阶段报错，请保留完整日志；此前 GCC 错误并非 Wi-Fi、Windows 防护或 USB 串口引起。

## Windows 构建缺少应用 BIN 的恢复方法

如果曾手动删除 `build/esp32s3_dns.bin`，但保留已链接的
`build/esp32s3_dns.elf`，一些增量构建状态可能只重新执行
`app_check_size`，并报告 `can't open .../esp32s3_dns.bin`。
这不表示旧的 BIN 会阻止生成新的 BIN；Ninja 正常行为是源代码未变化时沿用旧产物。

在项目根目录，先只删除应用 ELF 和缺失/残留的应用 BIN，强制重新链接：

```powershell
Remove-Item .\build\esp32s3_dns.elf -Force -ErrorAction SilentlyContinue
Remove-Item .\build\esp32s3_dns.bin -Force -ErrorAction SilentlyContinue
cmake --build build --parallel 8
Get-Item .\build\esp32s3_dns.bin | Select-Object Name,Length,LastWriteTime
```

以上不会删除已编译的 ESP-IDF 组件和 Bootloader。不要每次构建都执行
`idf.py set-target` 或 `fullclean`。若仍失败，以第一个 `FAILED:` 后面实际
C 编译/链接错误为准，而不是仅依据 `ninja: build stopped` 判断原因。

## 基准版本

ESP-IDF v5.5.5 是项目的初始目标版本。若暂时不准备迁移到 v6.1，仍可使用该版本编译；两个 SDK 版本切换时使用各自独立的 `build/`、`sdkconfig`，不要混用。

## 官方迁移资料

- [ESP-IDF 6.0 协议组件迁移：JSON / ESP-TLS](https://docs.espressif.com/projects/esp-idf/en/v6.0/esp32s3/migration-guides/release-6.x/6.0/protocols.html)
- [ESP-IDF 6.0 安全组件迁移：Mbed TLS 4 / PSA Crypto](https://docs.espressif.com/projects/esp-idf/en/v6.0/esp32/migration-guides/release-6.x/6.0/security.html)

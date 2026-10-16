# ESP32-S3 DNS Server

> 本文档由 AI 整理生成。

**在 ESP32-S3 N16R8 上运行的轻量 DNS 解析、过滤与缓存服务器。** 使用 ESP-IDF C 实现，提供 UDP/TCP DNS、AdGuard DNS 规则、Web 管理界面、本地 DNS 重写、上游 DoH/DoT，以及可选的 HTTPS DoH/DoT 服务端。

> **当前发布：v1.0.3 · 目标硬件 ESP32-S3（16MB Flash / 8MB Octal PSRAM）。** 适用于自建局域网 DNS 服务，管理端口不应直接暴露公网。

[**下载预编译固件 · GitHub Releases**](https://github.com/thhbdd/esp32-s3-dns-server/releases/tag/v1.0.3) · [**首次烧录 / OTA 教程**](docs/INSTALL.md) · [**首次配置**](docs/FIRST_RUN.md) · [**稳定性测试**](docs/STABILITY_TEST.md)

![管理页面概览](img/04.png)

## 1. 两种固件，不要混用

| Release 附件 | 用途 | 地址 / 操作 |
|---|---|---|
| `merged-binary.bin` | **首次完整刷机**；包含 Bootloader、分区表、OTA 初始化信息和应用 | Flash Download Tool / esptool 烧录偏移 **`0x0`** |
| `esp32s3_dns.bin` | **在已安装本项目且分区布局兼容的设备上 OTA 升级** | Web 页面「系统 → 固件升级」上传；不填写烧录地址 |
| `SHA256SUMS.txt` | 下载校验，避免损坏或混用版本 | `sha256sum -c SHA256SUMS.txt` 或 PowerShell `Get-FileHash` |

**切勿把 `merged-binary.bin` 当成 OTA 文件上传；也不要把 `esp32s3_dns.bin` 直接烧在 `0x0`。** 首次刷机和 OTA 的全部步骤、注意事项及风险见 [安装与升级指南](docs/INSTALL.md)。

## 2. 功能与适用边界

| 模块 | 说明 |
|---|---|
| 网络 | Wi-Fi STA、首次 SoftAP 配置门户；支持 IPv4/IPv6 网络相关能力（依赖局域网配置） |
| DNS | UDP/53、TCP/53、缓存与上游转发；常见 RR 类型及未知类型透明转发 |
| 上游 | UDP、TCP、DoT、DoH；历史低延迟优先、延迟加权负载均衡与并行竞速 |
| 规则过滤 | 兼容绝大部分 AdGuard DNS 过滤规则及常见 hosts 列表；支持黑白名单、例外、`$important` / `$dnstype` / `$dnsrewrite` 等 DNS 修饰符 |
| 规则更新 | 运行时编译为索引，成功切换后清理旧规则槽位和 staging；更新时暂时让出 DNS 缓存内存，结束后恢复 |
| 下游加密 DNS | HTTPS DoH `/dns-query` 与 DoT TCP/853，需要手动安装匹配的 PEM 证书/私钥，且未配置证书时不会启动对应服务 |
| 管理 | Web UI、查询日志、统计、本地记录、规则订阅、固件 OTA、配置备份 |

**过滤规则订阅：** 绝大部分 AdGuard DNS 过滤列表可以直接使用，无需转换格式。在 Web UI「过滤规则 → 订阅列表」添加规则 URL，保存并执行「检查更新」即可下载、编译、启用；后续可继续检查更新。少数非 DNS 规则或超出兼容范围的语法会被跳过并计数，具体见 [过滤规则兼容性](docs/FILTER_COMPAT.md)。

**安全提醒：** HTTP 管理端口不加密，Basic 身份验证不能替代 TLS；不要把管理端口直接暴露公网。服务端 TLS 私钥保存在配置 NVS，不要上传配置备份、私钥或带凭据截图到公开仓库。参见 [TLS 与安全边界](docs/TLS_AND_SECURITY.md)。

## 3. 五分钟快速上手

1. 到 [Releases v1.0.3](https://github.com/thhbdd/esp32-s3-dns-server/releases/tag/v1.0.3) 下载 `merged-binary.bin`，核对文件 SHA-256，并确保开发板确为 **ESP32-S3 N16R8**。
2. 在 Windows 的 Flash Download Tool 选择 **ESP32-S3 / 16MB / DIO / 80MHz**，添加完整镜像和偏移 **`0x0`**。或使用 `esptool` 命令：

   ```powershell
   python -m esptool --chip esp32s3 -p COM3 -b 460800 write-flash 0x0 merged-binary.bin
   ```

   把 `COM3` 换成真实端口；必要时先进入下载模式。**首次从其他项目迁移，分区不兼容时应备份后擦除 Flash；擦除会删掉所有旧配置。**
3. 重启开发板，连接首次配置热点（例如 `ESP32-DNS-XXXX`；默认密码 esp32dns；详细请参阅 [首次配置](docs/FIRST_RUN.md) 及当前 `main/net.c`），浏览器打开 `http://192.168.4.1/`，配置 Wi-Fi。
4. 接入局域网后从路由器 DHCP 客户端列表确认 ESP32 的新 IP，将需要测试的设备 DNS 指向该地址，使用 `nslookup example.com 设备IP` 验证。
5. Web UI 中设置上游 DNS、规则订阅、DNS 缓存和本地重写。订阅下载和编译需要时间；请等待实际更新成功，确认错误状态消失。

以后版本更新：**备份配置 → 从 Releases 下载 `esp32s3_dns.bin` → Web UI OTA → 自动重启 → 验证设备版本和 DNS 应答**。详细故障恢复流程见 [安装与升级](docs/INSTALL.md)。

## 4. 界面与测试截图

| Web 功能 | 截图 |
|---|---|
| 首页/状态 | ![状态概览](img/04.png) |
| 查询日志 | ![DNS 查询日志](img/05.png) |
| 过滤规则 | ![过滤器管理](img/06.png) |
| 自定义规则 | ![自定义规则](img/07.png) |
| DNS 配置 | ![DNS 设置](img/08.png) |
| TLS / 系统设置 | ![系统设置](img/09.png) |
| 管理 / OTA | ![管理设置](img/10.png) |

### dnsbench 吞吐量与延迟测试

![dnsbench 吞吐与延迟测试 01](img/01.png)

![dnsbench 吞吐与延迟测试 02](img/02.png)

### dnsbench 多阶段稳定性测试

![dnsbench 多阶段稳定性测试 03](img/03.png)

[完整截图](docs/SCREENSHOTS.md)

## 5. 实测摘要（不是理论最大值）

局域网 `192.168.31.7:53` 的 `bench_suite.sh` 10 秒测试结果：`cache_c16` 约 **1,390 QPS**、零丢失；`cache_rate500` **500 QPS**、零丢失；目标 `2,000 QPS` 压测时仅约 **1,432 QPS** 成功，且有大量超时。此结果混合包含缓存、本地过滤与网络效应，不等于公网上游解析性能。

独立的 10 分钟 `dns_stability_test.sh` 测试包含常态 5 QPS、繁忙 12 QPS、短时 25 QPS、低速新名称查询和 TCP 阶段，**3,680 / 3,680 应答，0 次超时，0 次 SERVFAIL**；其中一次恢复阶段的阶段 p99 达 **251.756ms**，不能只看平均值。参见 [可复现的稳定性测试](docs/STABILITY_TEST.md) 与 [详细基准](docs/BENCHMARK.md)。

## 6. 源码编译

```powershell
# 安装并激活 ESP-IDF v6.1 开发环境后；Windows 建议使用纯英文工程路径
cd D:\esp32-s3-dns-server
idf.py set-target esp32s3  # 首次执行即可；会清理旧 build
idf.py build
idf.py merge-bin
```

`build/esp32s3_dns.bin` 是 OTA 应用镜像，`build/merged-binary.bin` 是合并镜像（**`idf.py merge-bin` 生成，名称可能因 ESP-IDF 版本而异**）。重新修改少量代码后直接 `idf.py build`；切勿无故反复 `set-target` / `fullclean`，以免触发全量编译。项目依赖使用组件管理器下载 `espressif/cjson`。版本应在 `CMakeLists.txt` 的 `PROJECT_VER` 与构建出的应用描述符中一致。

## 7. 项目结构

```text
components/          DNS 协议、过滤引擎、基础兼容层
main/                Wi-Fi、规则更新、Web / DoT / DoH、应用入口
web/                 设备内置管理页面
img/                 实机界面与测试截图
tools/dnsbench/       标准吞吐测试及 5～10 分钟稳定性测试脚本
tools/flc/            规则编译工具
tools/                检查、主机仿真和兼容性测试
host/                 Linux 主机编译与测试
docs/                 完整用户/开发/性能/安全文档
.github/workflows/    CI（固件编译路径与主机测试）
partitions.csv        固件 A/B、配置、规则 A/B 与 staging 的固定分区布局
sdkconfig.defaults    ESP32-S3 默认配置
```

## 8. 完整文档

| 主题 | 文件 |
|---|---|
| 首次烧录、OTA、Flash 偏移、校验和错误恢复 | [安装与升级](docs/INSTALL.md) |
| 首次热点 / 路由器 Wi-Fi / IP | [首次使用](docs/FIRST_RUN.md) |
| UI 截图 | [截图说明](docs/SCREENSHOTS.md) |
| 长时间稳定性与突发测试 | [稳定性测试](docs/STABILITY_TEST.md) |
| 组件、线程、内存与更新原理 | [架构](docs/ARCHITECTURE.md) · [内存预算](docs/MEMORY_BUDGET.md) |
| Flash 规则分区、订阅、清理 | [规则与存储](docs/RULES_AND_STORAGE.md) · [内存回收和 OTA](docs/UPDATE_MEMORY_OTA.md) |
| 过滤语法兼容 | [规则兼容表](docs/FILTER_COMPAT.md) |
| 上游、服务端 TLS、证书与风险 | [TLS 与安全](docs/TLS_AND_SECURITY.md) |
| 本地记录 | [本地 DNS 重写](docs/LOCAL_RECORDS.md) |
| API / JSON / 备份 / OTA | [API](docs/API.md) |
| Windows/Linux 源码构建、6.1 兼容 | [开发说明](docs/DEVELOPMENT.md) · [ESP-IDF 6.x](docs/ESP_IDF_6.md) |
| 故障分析 / 测试计划 / 代码审查 | [排障](docs/TROUBLESHOOTING.md) · [测试计划](docs/TEST_PLAN.md) · [代码审计](docs/CODE_AUDIT.md) |
| 本次版本发布信息 | [v1.0.3 发布说明](docs/RELEASE_NOTES_v1.0.3.md) · [历史更新](CHANGELOG.md) |

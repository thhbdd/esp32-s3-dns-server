# 开发者指南：架构、构建、测试、优化与提交流程

> 本文档由 AI 整理生成。

## 1. 开发目标与边界

运行平台是 ESP32-S3 N16R8 + ESP-IDF v5.5（基准）；v6.1 源码适配待实机验收；可移植过滤与 DNS 核心在 Linux 上使用相同 C 源码。改动应优先减少热路径的拷贝、锁、临时分配，不能为了追求平均时延牺牲异常报文安全性、Flash 掉电安全或 DNS 标准兼容。

## 2. 核心目录图

| 代码 | 负责什么 | 风险重点 |
|---|---|---|
| `main/app_main.c` | 初始化 NVS、配置、DNS、规则、Wi-Fi、Web、OTA 标记等 | 启动顺序、栈、任务创建失败 |
| `main/app_config.c` | JSON 配置、NVS 持久化、密码哈希 | 认证、配置输入校验、Flash 写入 |
| `main/net.c` | STA/SoftAP、DHCP、IPv6、SNTP、Wi-Fi 重连 | captive portal、内存、网络连通 |
| `main/rules.c` | 订阅下载、staging 外排序、A/B 镜像、定时更新 | Flash 临界区、失败回滚、运行期切换 |
| `main/web.c` | HTTP/HTTPS Web、REST、TLS 证书、DoH、OTA | 不可信输入、认证、TLS 资源 |
| `main/dot_server.c` | 作为服务端的 DNS-over-TLS | TLS 握手、并发、超时 |
| `main/upstream_tls.c` | 作为客户端的 DoT/DoH 上游 | 引导解析、证书、重试、连接复用 |
| `components/fl_filter` | AdGuard 解析器、规则编译、镜像匹配 | 语义、越界、恶意正则、镜像校验 |
| `components/dns_core` | DNS 协议、缓存、上下游转发 | RFC 语义、并发数据一致性、TTL |
| `components/dc_base` | POSIX/ESP-IDF 平台抽象 | 任务栈、内存分配、时间与同步 |
| `tools/` | 命令行规则编译、网络压测、差分测试 | 主机工具参数校验 |
| `web/index.html` | 单文件管理 UI | 注入、错误状态展示、敏感数据 |

## 3. 构建方式

**ESP-IDF：**

```bash
. "$IDF_PATH/export.sh"
idf.py set-target esp32s3
idf.py build
```

**Linux 主机：**

```bash
cmake -S host -B build-host -DCMAKE_BUILD_TYPE=Release
cmake --build build-host -j
ctest --test-dir build-host --output-on-failure
```

**内存安全：**

```bash
cmake -S host -B build-asan -DSANITIZE=ON
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
./build-asan/fuzz all 20 123456
```

主机端测试不包含 `ESP_PLATFORM` 下的 Wi-Fi、NVS、ESP-TLS、HTTPD 等分支；对应代码仍需 ESP-IDF 构建、真机日志和网络测试。

## 4. 规则引擎开发原则

- 编译器读取原始语法并产生镜像，查询时不能再次扫描原始行文本。
- 任何去重/合并必须保留 `@@`、`$important`、`$badfilter`、`$dnsrewrite`、`$dnstype` 语义。
- 正则要有上限与执行保护；规则计入 unsupported 比触发退化/卡死好。
- 所有外部字节（列表、镜像、DNS 报文）必须先检查长度、偏移、整数溢出和索引范围，再访问内存。
- 变更镜像二进制格式需引入版本处理、检验加载旧格式的行为。

## 5. DNS 协议与缓存开发原则

DNS 大小写与名称压缩解析、EDNS OPT、DNSSEC DO/CD、UDP TC、TCP 两字节长度前缀、QTYPE/CLASS 都有各自边界。增加 RR 类型时，尽量不改变不需要本地重写的**透明上游转发**路径。

缓存键不能只按域名做：还必须考虑查询类型、CLASS、DO/CD 以及规则状态/版本影响；缓存 TTL 与负缓存需分别处理。不要将受到来源 ACL 或过滤配置影响的应答错误复用。

## 6. PSRAM / SRAM 调优规则

ESP32-S3 的 8MB PSRAM 不等于 8MB 全部可用堆。XIP、规则镜像、DNS L2、TLS、查询日志、编译暂存都需空间；片内 SRAM 则继续承担 Wi-Fi DMA、FreeRTOS 内部栈以及部分网络缓冲。PSRAM 不可简单替代所有片内 SRAM，Flash 写入/擦除期间的 cache suspend 需要格外警惕 PSRAM 任务栈。

调整任务栈前，先测量**任务高水位和最大连续片内可分配块**；但不要求这些日志常驻发布固件。测试版可临时启用诊断，完成测量后删除或编译期关闭。不要无根据把所有栈都增大到 16~32KB。

## 7. 安全检查清单

- 外部 HTTP 输入要限长度，认证检查不得被另一路 API 绕过。
- 私钥和完整备份文件绝不能打印在日志里。
- 订阅 URL、DNS 名称、TLS 主机名和 OTA 地址均视作不可信输入。
- DoH 端点只能在 HTTPS 注册，POST 必须检查 `application/dns-message`。
- 未配置证书时不能假装 DoH/DoT 服务已成功启动。
- 失败的规则更新不能覆盖旧规则；不应将异常 HTML 当作有效过滤列表。
- 变更 Flash 分区需考虑旧设备、OTA 和备份兼容性。

## 8. 变更后如何验收

1. 先编译无 sanitizer 的主机程序，`ctest` 全通过。
2. 开 ASan/UBSan 重新跑 `ctest` 和随机 fuzz；记录 seed。
3. 对用户真实 23 万条规则编译并查询，记录镜像大小和 staging 峰值。
4. 对影响解析的修改做 Go AdGuard 参照差分测试（如依赖可用）。
5. 修改 ESP-IDF 专用文件时，**必须交叉编译**；主机侧绿灯不能覆盖该步骤。
6. 上板依次测：首次配网、规则更新、断电保护、TLS、OTA、数小时负载、长期稳定性。
7. 更新 README / API / 兼容性 / 测试报告，不用“已实测”描述仅设计目标。

## 9. 性能测试不应自欺欺人

记录板子型号、固件 SHA256、ESP-IDF/编译优化、Wi-Fi RSSI、上游地址、客户端/服务端连接方式、QPS、p50/p95/p99/p99.9、错误率与片内堆低水位。对比算法时只改变一个变量，例如缓存大小或压缩块数量。主机 `flc bench` 用于算法比较，不可用于声称 ESP32 实机 p99。

## 10. 文档和提交约定

原则是“别人从零拿到仓库可以按步骤复现”。新增 API 要同步更新 [API](API.md)，修改规则语义更新 [FILTER_COMPAT](FILTER_COMPAT.md)，修改烧录地址或分区更新 [INSTALL](INSTALL.md) 和 [MEMORY_BUDGET](MEMORY_BUDGET.md)。建议把代码变更和文档变更放在同一个提交。

## 文件完整性与发布前检查

```bash
python3 tools/check_docs.py
python3 tools/audit_inventory.py
```

`audit_inventory.py` 只验证文件清单及 SHA-256 与当前源码是否相符，若更新代码后报告不一致，可运行 `python3 tools/audit_inventory.py --write` 重新生成。它不执行任何编译器检查，不能替代安全审计、覆盖率和硬件验收。逐文件清单是供 PR 审阅者确认影响范围的工具，而非“所有代码无 BUG”证明。

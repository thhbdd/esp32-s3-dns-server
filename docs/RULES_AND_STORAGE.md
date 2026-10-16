# 过滤列表、AdGuard 规则预编译与 Flash A/B 镜像

> 本文档由 AI 整理生成。

## 1. 为什么不在 DNS 查询时解析规则文本？

ESP32-S3 可用于系统任务的片内 SRAM 不大；把几十万行 AdGuard 规则拆成 `malloc` 独立对象，会带来大量指针、元数据与碎片。若每次查询从 Flash/SD 卡随机读取原始文本，时延可能受 I/O 主导。此项目将订阅格式视为**输入格式**，在下载/更新时完成语法校验、分类、统一归一化和紧凑索引构建；运行时只加载编译后的镜像，不需要保留订阅原文。

过滤器对普通域名、高级规则、白名单、重写执行不同的匹配操作，但最终统一返回判定结果（放行/拦截/重写等）。预编译只消除**解析语法**的开销，不会消除正则本身的匹配成本；对复杂正则仍需限制指令数量和候选规模。

## 2. 在 Web UI 增加订阅

兼容绝大部分 AdGuard DNS 过滤规则，以及常见 hosts 格式列表。可直接添加规则订阅 URL，无需转换格式。「过滤规则 → 订阅列表」每行有名称、URL、启用状态、白名单标识；支持添加多个列表，保存后点击「检查更新」或「强制重建」，后续可继续更新。常用输入示例：

```text
AdGuard DNS Filter: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
AdAway Hosts:        https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt
anti-AD EasyList:    https://anti-ad.net/easylist.txt
AdBlockDNS:          https://gcore.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockdns.txt
```

前三个地址只是列表来源示例，列表内容与可达性会变化。不同源可能相互重叠：编译器可以去重**语义完全等价**的规则，但不能简单把所有字符串丢进无差别黑名单。`@@`、`$important`、`$badfilter`、`$dnsrewrite` 与允许列表的优先级会改变最终结果。

## 3. 基本语法示例

```adblock
! 注释
||ads.example.com^                        
@@||safe.ads.example.com^
||tracker.example.com^$important
||ads.example.com^$dnstype=A|AAAA
||bad.example.com^$dnsrewrite=NOERROR;A;0.0.0.0
0.0.0.0 telemetry.example.com
127.0.0.1 beacon.example.com
/^(ads|track)\d+\.example\.net$/
```

单纯 `example.com`、hosts 精确匹配与 `||example.com^` 的子域名范围未必一致。**DNS 名称的标准语义以完整标签为界**：`example.com` 不应误命中 `notexample.com`。具体边界、已知差异和被跳过语法参见 [FILTER_COMPAT.md](FILTER_COMPAT.md)。

## 4. 整个更新事务

```text
用户点击更新 / 定时更新
    ↓
检测网络状态、条件请求 / 重试
    ↓
订阅响应校验（状态码、长度、类型、内容）
    ↓
确认需要完整重建后释放缓存 L1/L2 内存（DNS 仍继续工作）
    ↓
流式解析规则并分类；必要时外排序
    ↓
staging 分区写入临时 run
    ↓
合并/压缩 → 写入非活动 rules_a 或 rules_b
    ↓
镜像校验、加载/映射、切换指针
    ↓
提交元数据、剪除已删除/停用订阅的状态记录
    ↓
擦除整个废弃规则分区（4 MiB）以及 staging 临时分区（4.5 MiB）
    ↓
释放编译工作区，恢复最新 DNS 缓存预算（成功/失败均恢复）
```

设计目标是：**旧规则在新规则有效之前始终保持可用**，更新失败时保留旧规则，不用空镜像掩盖连接错误。注意中间阶段仍会消耗 Flash 擦写和 CPU；高并发时 p99 有可能受到影响。关闭设备电源或突然重启后的行为需要真实上板断电测试才能确认。

## 5. 为什么要 `staging`、`rules_a`、`rules_b`？

Flash 一共 16 MB，分区由 `partitions.csv` 固定：`rules_a` 与 `rules_b` 各 4 MiB、`staging` 为 4.5 MiB。分区空间不是 PSRAM 空间，镜像必须满足 Flash 槽长度约束；两份完整规则库**主要在 Flash 中**，不意味着运行时在 8MB PSRAM 里复制两份镜像。

只有当内容需要重新编译才应耗费擦写。HTTP `304 Not Modified` / ETag 等更新优化可减少无意义下载，但不能把服务器“始终可靠返回 304”当作假设。失败应记录错误与下一次重试时间；不应将暂时无法访问列表误判为空列表。

## 6. 真实规则编译测试

使用 `adblockdns.txt` 进行主机编译，原生 C 工具 `flc` 输出：

| 指标 | 本次主机测试结果 |
|---|---:|
| 规则总数 | 233,238 条有效 network rules |
| 去重键数 | 233,211 |
| 编译镜像大小 | 2,737,416 字节（2.611 MiB） |
| staging 峰值 | 2,740,224 字节 |
| 主机编译耗时 | 338 ms |

这不是 ESP32-S3 在 240MHz CPU 下的耗时；未计入设备 Wi-Fi 网络下载、TLS、Flash 写入/擦除与启动时映射。对于其它列表或复杂正则，镜像大小会变化，不能用一个固定“每条规则占 X 字节”来外推。实验命令：

```bash
./build-host/flc compile -o /tmp/adblock.img /path/to/adblockdns.txt
./build-host/flc info /tmp/adblock.img
./build-host/flc query /tmp/adblock.img ads.example.com A
```

## 7. 自定义规则与本地记录的区别

- **订阅规则**：随订阅更新重新编译为大镜像，适合大量广告列表。
- **自定义过滤规则**：用户输入少量黑/白名单和 `$dnsrewrite`，保存后生效；有限制的 NVS 容量。
- **本地解析记录**：直接为家庭服务创建具体 DNS 资源记录，配置入口为「本地解析」；优先于通常的订阅匹配。

它们不应随意混在一份“去重域名表”里：自定义本地记录具有不同优先级、RDATA 和 TTL。修改任何会影响应答的规则之后，建议清理 DNS 响应缓存并验证客户端实际结果。

## 8. 更新失败场景与排查

| 现象 | 应检查 | 正确处理 |
|---|---|---|
| 连接失败、timeout | Wi-Fi、DNS bootstrap、证书、目标域名是否可达 | 保留旧镜像，显示错误 |
| HTTP 403/404 | URL 是否有效、服务端是否有限制 | 不将错误页当作规则 |
| 下载到 HTML 页面 | 响应内容检查 | 拒绝该订阅 |
| 4 MB 镜像上限 | 列表规模与复杂度、重复规则 | 精简订阅，不盲目提高内存 |
| staging 空间耗尽 | 外排序临时块峰值 | 显示失败，不覆盖旧镜像 |
| 设备重启 | 任务栈位置、Flash/cache 禁用、安全供电 | 先查串口最早的断言/Cache error |
| 规则有但未生效 | 保护开关、白名单、本地解析、客户端缓存 | 使用 `flc query` / `dig @设备IP` 对比 |

## 9. 开发者注意点

可移植编译器位于 `components/fl_filter/`，硬件分区 I/O 与订阅下载位于 `main/rules.c`。不要在 `fl_compile` 代码里直接依赖 ESP-IDF，让同一实现继续可在 Linux + ASan/UBSan 下测试。修改内部镜像格式时需要更新头部版本/校验规则，并考虑旧镜像无效时自动安全重建。

## 10. 废弃规则 Flash 物理清理（v1.0.2）

**本项目没有一个订阅对应一个 Flash 文件的机制。** 启用的订阅依次流式解析后，合并为单个规则索引镜像；`staging` 仅存放临时 run。停用或删除 URL 不会立刻擦除某个“列表文件”，而是在**成功重新编译和激活**后，不再包含其规则。

- 对新规则镜像：只保留当前启用订阅的规则；成功切换后才更新有效槽位指针。
- 对 NVS：删除已删除/禁用订阅的旧状态、ETag、成功时间、错误信息等元数据。
- 对 Flash：新镜像有效并成功持久化后，按扇区擦除非活动规则槽位的完整 4 MiB 和 staging 分区的完整 4.5 MiB，确保旧数据的内容不再保留。当前生效的规则槽位不会擦除。
- 对空间：实际旧规则和 staging 物理存储扇区擦回 `0xFF`，便于下一次规则构建复用；由于 `rules_a/rules_b/staging` 是固定布局，不会因此变成 OTA 固件分区容量。
- 对可靠性：擦除整个旧槽意味着不再保留上一版规则作为第二份备用镜像；如果新镜像以后损坏，需联网重新下载或恢复规则。希望保留旧规则快照时应在设计上选择另一清理策略。

更新失败时不会把正在使用的旧槽当成淘汰文件来清理。无订阅时先提交空集合，再擦除两个规则槽和 staging；擦除中途断电，下次检查会重试。成功清理标记保存在 NVS，防止每次半小时检查都再次整片擦除。

# 更新日志

> 本文档由 AI 整理生成。

当前发布为 **v1.0.4**。下载、SHA-256、首次烧录及 OTA 见 [发布说明](docs/RELEASE_NOTES_v1.0.4.md) 和 [安装与升级](docs/INSTALL.md)。

## 1.0.4 — 过滤规则符号表编译降低内存峰值

- FSST 训练候选哈希表由 65,536 降至 8,192 项，三块主要临时工作区从约 1.51 MiB 降至约 202 KiB，避免因连续 PSRAM 大块分配失败而报 `out of memory (symbol table)`。
- 编译样本缓冲或 FSST 临时表分配不足时退化为**无符号后缀压缩**（直接保存原始后缀），继续生成完整规则镜像，不跳过规则、不误报订阅更新成功；若退化镜像超过 Flash 规则槽容量，仍按原有逻辑报容量错误。
- 不修改镜像格式、Flash 分区表、NVS 配置结构或 OTA 分区；以 ESP-IDF 的 PROJECT_VER 1.0.4 为固件应用版本。
- 补充主机压力及真实列表对比；设备端交叉编译和 OTA 实机验证仍应在 ESP-IDF v6.1 环境执行。

## 1.0.2 — 废弃规则 Flash 数据物理清除

- 新镜像完整激活、规则版本与订阅状态持久化成功后，擦除 **整个非活动 rules_a/rules_b（4 MiB）** 和 **整个 staging（4.5 MiB）**，替代 1.0.1 只清理旧镜像 4 KiB 头部的逻辑。
- 禁用全部订阅时，清空两个规则槽位和 staging；其他情况下永远不擦除当前活动槽。
- OTA 升级后即使订阅未变化，在首次成功更新检查时也清理 v1.0.1 遗留数据。
- 记录 `flash_gc_slot` / `flash_gc_gen` 防止无变化时反复擦除；清理出错会报告并允许下次重试。清理过程中逐块持锁并让出 CPU。
- 成功提交新镜像后立即恢复 DNS 缓存，不必等 8.5 MiB Flash 清理全部完成；规则更新本身内存优化保持不变。
- 不变更分区表、OTA 分区位置或规则镜像格式；固件版本升级到 1.0.2。
- **设备端需 ESP-IDF v6.1 交叉编译与实机验证**；Linux CTest 无法验证 ESP-IDF Flash 擦写时序。

## 1.0.1 — 规则更新内存回收与过期订阅清理

- 真正开始重建前临时释放 DNS 缓存 L1/L2 ring 与索引，重建结束（包括错误路径）自动恢复；更新期间的配置修改不会被旧缓存参数覆盖。
- 减小设备端过滤编译器块目标到 192KiB，缓和连续 PSRAM 内存压力；更频繁 Flash run 与镜像体积变化详见内存预算。
- 成功激活新镜像且持久化状态后删除不再启用的订阅状态，并使旧镜像槽头部无效，复用剩余固定分区。
- 检查订阅配置在漫长下载期间是否改变，避免激活已过时的订阅列表。
- 单元测试覆盖缓存实际释放、更新期间重配置、恢复到最新预算、两次进入/退出的幂等性。
- Flash 分区表、OTA 地址、NVS 配置结构保持不变。设备端固件还需 ESP-IDF v6.1 真正编译验证。

## Unreleased — ESP-IDF v6.1 source migration (not hardware-verified)

### 2026-10-16 — `web.c` ESP-IDF 6.1 compiler errors (reported by Windows GCC 15.2.0)

- Fix `DNS_MSG_MAX` undefined in the public Web component by using a local DoH wire-input bound of 4096 bytes (the matching DNS core limit).
- Remove incorrect `HTTPD_DEF_CTRL_PORT` override; `HTTPD_SSL_CONFIG_DEFAULT()` already reserves a separate HTTPS control port.
- No additional FreeRTOS task, buffer pool, or permanent memory diagnostic introduced.
- Re-ran portable host tests and Markdown validation; **full Xtensa/ESP-IDF firmware build has not been run in this environment**.


- Replace removed built-in `json` component with managed `espressif/cjson` via `main/idf_component.yml`.
- Adapt Mbed TLS 4.x certificate-key validation (`mbedtls_pk_parse_key` / `mbedtls_pk_check_pair`).
- Adapt authentication hash and password stretching to PSA SHA-256 with identical on-disk digest format for IDF 6.x; retain Mbed TLS 3.x path for 5.5.
- Add a CI firmware build matrix for IDF 5.5 and 6.1, plus a dedicated migration guide.
- Linux host tests do not compile IDF device-only sources: successful ESP-IDF 6.1 build and device tests are still required.

# 更新记录 / Changelog

## 2026-10-16 · 审查与文档完善版（源码交付）

### 文档和可维护性

- 重写 GitHub README，新增从安装到首次联网、规则管理、本地记录、TLS/DoH/DoT、问题排查的一整套操作教程。
- 扩充架构、内存预算、过滤器语法与已知差异、接口、性能测试、开发指南及安全边界说明。
- 修正不成立的“PSRAM 栈在 Flash 操作中完全安全”表述。
- 添加离线 Markdown 链接和代码围栏检查，并集成到主机 CI，不进入固件。
- 提供 `reports/` 中逐文件审查清单、覆盖率汇总和对抗测试摘要。

### 源码可靠性小修复

- DoH POST 要求正确的 `application/dns-message` Content-Type。
- Web 认证互斥锁创建失败时安全退出初始化。
- 配置修改前先确认可分配新的快照，避免写入状态不一致。
- 内存不足导致规则更新任务无法创建时报告错误，并支持后续主动重试。
- 从备份恢复 TLS 证书/私钥时检查 NVS 持久化错误并报告失败。
- 清理重复包含和误导性内存注释；没有增加常驻调试任务或缓冲。

### 真实测试结果与限制

- Linux 可移植代码 259 项主机断言组通过，ASan/UBSan 随机压力测试未报告错误。
- GCC gcov 可移植部分行覆盖率 89.54%，分支覆盖率 74.87%。
- 23.3 万条规则在 Linux 主机编译为 2,737,416 字节（2.611 MiB），耗时 338ms。
- 没有 ESP-IDF 交叉编译器或 ESP32-S3 硬件，**未生成或验证新版 `.bin` 固件**；TLS/Flash/Wi-Fi 上板验证仍待完成。

详见 [代码审计](docs/CODE_AUDIT.md)、[测试计划](docs/TEST_PLAN.md)及 [报告目录](reports/README.md)。

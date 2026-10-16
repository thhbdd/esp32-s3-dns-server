# 当前审查与测试报告（2026-10-16）

> 本文档由 AI 整理生成。

本目录为了 GitHub 新用户和维护人员提供**可复现的数据及被检查的文件范围**，不是固件的一部分。

## 1. 本次真正执行了什么

| 项目 | 结果 | 局限 |
|---|---|---|
| Linux Release 构建 + CTest | `test_filter` 117/117、`test_dns` 142/142，2/2 通过 | 不运行 ESP-IDF 专有代码 |
| GCC ASan + UBSan | 两组集成测试和随机输入测试，无报告错误 | 只覆盖本机可执行路径 |
| GCC gcov 行覆盖 | **6,882/7,686 = 89.54%** | 仅 dc_base/fl_filter/dns_core 的可移植目标 |
| GCC gcov 分支覆盖 | **5,136/6,860 = 74.87%** | 同上 |
| 真实规则编译 | 233,238 条有效网络规则 → **2,737,416 字节（2.611 MiB）** | 沙盒 CPU，不是设备编译时间 |
| Markdown 链接检查 | 自动验证文件内相对链接及代码围栏 | 不核查所有文字与实际 API 的语义 |
| Web JavaScript | `node --check` 语法通过 | 不等于浏览器端到端功能测试 |
| ESP32-S3 固件 | **未交叉编译 / 未上板** | 当前容器没有 ESP-IDF/Xtensa 编译器和硬件 |

**“100% 检查范围”** 指 `audit_inventory.csv` 列出了存档中的所有项目自有文件，并按类别纳入审查清单；并非 100% 代码覆盖率或零漏洞证明。

## 2. 两组随机输入的测试输入量

| 种子 | wire 报文 | parser 执行 | 正则输入 | 损坏镜像 | 缓存操作 | 服务端请求 |
|---|---:|---:|---:|---:|---:|---|
| `20261016`（ASan/UBSan） | 15,197,000 | 5,496,500 | 923,800 | 131,466 | 19,578,000 | 同步 1536、UDP 3060 |
| `20261017`（覆盖率构建） | 16,411,000 | 8,262,500 | 4,774,800 | 214,543 | 33,372,000 | 同步 1458、UDP 3032 |

测试程序会使用大量随机输入找崩溃和格式边界，不能据这些数字宣称“数千万个独立业务场景全部覆盖”。

## 3. 如何核对文件

- `audit_inventory.csv`：包内逐文件 SHA-256、文件类别和建议检查点（不含该清单文件自身，避免自指校验）。可通过 `python3 tools/audit_inventory.py` 校验清单，或加 `--write` 在修改仓库后重新生成。
- `coverage_portable.json`：gcov 按源码归类的覆盖统计。完整的 gcda/gcno 需要在构建环境重新生成。
- `rules_compilation.txt`：真实订阅编译器摘要，不含原始订阅文本。
- `host_sanitizer_summary.txt`：本次 ASan/UBSan + 压力输入记录。
- [测试和对抗测试计划](../docs/TEST_PLAN.md)；[局限和审查事项](../docs/CODE_AUDIT.md)。

```bash
cmake -S host -B build-test -DSANITIZE=ON
cmake --build build-test -j
ctest --test-dir build-test --output-on-failure
./build-test/fuzz all 25 20261016
python3 tools/check_docs.py
```

## 4. 需要在 ESP32-S3 实机补充的证据

首次配网与热点 HTTP 可用性、Wi-Fi 断连恢复、单/多客户端 DNS、规则下载/Flash A/B 更新和断电恢复、HTTPS DoH 与 DoT 的有效证书 TLS 握手、管理页认证、OTA 回滚、SRAM/PSRAM 最低余量、24 小时稳定性及实际 p95/p99 延迟。

Go 差分 oracle 本次也未复测：容器中的 Go 版本不满足该工具 `go.mod` 的最低要求。过去版本的差分成绩只作为背景参考。

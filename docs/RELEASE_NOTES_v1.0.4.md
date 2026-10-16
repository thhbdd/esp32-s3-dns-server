# ESP32-S3 DNS Server v1.0.4 · Release Notes

> 本文档由 AI 整理生成。

发布目标：**ESP32-S3 N16R8 / ESP-IDF v6.1**。固件应用镜像的版本字段为 `1.0.4`。

## 附件与下载

| 附件 | 用途 | 注意 |
|---|---|---|
| [`merged-binary.bin`](https://github.com/thhbdd/esp32-s3-dns-server/releases/download/v1.0.4/merged-binary.bin) | 首次完整刷机 | **ESP32-S3，偏移 `0x0`** |
| [`esp32s3_dns.bin`](https://github.com/thhbdd/esp32-s3-dns-server/releases/download/v1.0.4/esp32s3_dns.bin) | Web UI OTA | 仅含应用，**不能当完整镜像刷在 `0x0`** |
| [`SHA256SUMS.txt`](https://github.com/thhbdd/esp32-s3-dns-server/releases/download/v1.0.4/SHA256SUMS.txt) | 校验两份镜像 | 先检查再刷写 |

SHA-256：

```text
1238cf51d1212021b4d39c0c5c2262cb3027ad855c8341dcd05f368ffe22c9bb  merged-binary.bin
3258f34aeedd060531af02462e295957d5a5b438a66a08fb698f3bf6ba9c0604  esp32s3_dns.bin
```

**刷写和升级详见 [安装教程](INSTALL.md)**：首次从其他系统迁移建议备份并评估是否全擦，正常兼容升级在 Web UI 选择应用镜像即可。

## 本次版本变化

- **v1.0.4：** 过滤规则 FSST 符号表构建内存优化，降低候选哈希表临时开销；当符号表临时内存分配失败时可退化为未压缩后缀继续编译，但退化镜像可能更大，仍受 4MiB 规则槽位限制。
- **保留 v1.0.2：** 成功启用新规则后，擦除废弃的旧规则槽和 staging 数据；不改变固定分区布局。Flash 擦除有耗时和寿命成本。
- **保留 v1.0.1：** 规则编译期间临时释放 DNS 缓存的可回收内存，结束后按最新配置恢复；保持 DNS 解析继续运行。
- **服务能力：** UDP/TCP DNS、Web UI、规则过滤与 DNS 本地记录，DoH/DoT 上下游能力依赖相应配置和证书。
- **新增仓库文档：** 完整刷写与 OTA、截图导览、独立长稳测试与 CI 说明；包含 `dns_stability_test.sh`，并保留 `bench_suite.sh`。

## 已有实际测试数据（单次测量）

- 10 秒原版基准：16 并发缓存路径约 1,390 QPS、零丢失；固定 500 QPS 零丢失；目标 2,000 QPS 出现明显丢失。
- 10 分钟温和稳定性：3,680 次请求全部得到应答，无超时和 SERVFAIL；25 QPS 3 秒短突发重复 10 次，每轮全应答。少量查询有尾部延迟波动，个别恢复阶段 p99 为 251.756ms。
- 上述结果不是全部 DNS 查询在缓存命中、不是长期 24×7 运行报告，也不代表公网 DNS 上游的吞吐水平。

## 已知约束与安全提醒

- 硬件针对 N16R8，DNS 更新编译受可用 PSRAM 和规则槽容量约束；过滤规则数量极大时仍可能出现内存或 Flash 容量错误。
- HTTP 管理面板明文传输，不应暴露公网；DoH/DoT 服务端仅在有效 TLS PEM 证书和私钥已配置时启用。
- 私钥/配置备份可能包含机密信息，不要上传 GitHub。
- OTA 不修改引导程序、分区表；跨分区布局升级可能需要串口整片刷机。

更多内容见 [README](../README.md)、[稳定性测试](STABILITY_TEST.md)、[规则内存与 Flash](UPDATE_MEMORY_OTA.md) 和 [安全说明](TLS_AND_SECURITY.md)。

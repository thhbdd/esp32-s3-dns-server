# 参与贡献与问题反馈

> 本文档由 AI 整理生成。

请先阅读 [README](README.md)、[开发说明](docs/DEVELOPMENT.md)、[测试计划](docs/TEST_PLAN.md) 和 [安全边界](docs/TLS_AND_SECURITY.md)。

## 反馈模板建议

- 目标硬件与 Flash/PSRAM 容量（例如 ESP32-S3 N16R8）。
- ESP-IDF 版本、固件内部版本（例如 1.0.4）、是首次烧录还是 OTA 升级。
- 可复现步骤：发生前执行了什么、预期是什么、实际是什么。
- 串口异常全文或查询应答报文（打码敏感地址和域名）。
- 与相关模块有关的 SDK 配置、订阅规模、缓存预算、上游策略、Wi-Fi RSSI；无需上传密码和私钥。

## 代码贡献建议

- 先运行 `cmake -S host -B build-host && cmake --build build-host && ctest --test-dir build-host --output-on-failure`。
- 更改 ESP-IDF 相关代码时，在 ESP32-S3 工具链中运行 `idf.py build`，并尽可能进行实机验证。
- 不允许以 Linux 主机测试代替固件交叉编译结论；与具体设备有关的结果请附日志。
- 修改配置存储、分区布局、TLS/OTA/Flash GC 时增加回归测试、向后兼容说明及失败恢复路径。
- 源码使用依赖管理器管理的第三方组件，**不要提交构建产物 `build/`、私钥、设备配置备份或 `managed_components/`**。

本仓库当前没有明确的开放源代码许可证；贡献与再分发前请先确认授权安排。

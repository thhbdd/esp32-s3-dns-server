# HTTPS DoH、DoT、证书与安全边界

> 本文档由 AI 整理生成。

## 1. 三种服务不要混淆

- **普通 HTTP Web UI**：默认 `http://设备IP:80/`，用于管理页面与 API，HTTP Basic 管理口令本身**不提供传输加密**。
- **设备提供的 DoH**：`https://域名/dns-query`，底层是 HTTPS（RFC 8484），由 ESP-IDF `esp_https_server` 承载。当前 `/dns-query` 只注册在 HTTPS 服务上；`http://设备IP/dns-query` 不应当视作 DoH。
- **设备提供的 DoT**：默认 TCP/853（RFC 7858），客户端发送带两个字节长度前缀的 DNS 请求，使用 TLS 保护传输。

还有一组容易混淆的“**上游** DoH/DoT”：ESP32 自己作为客户端，连接公网 `tls://...` / `https://...` 解析器；这与设备自己作为 TLS 服务器的证书无关。

## 2. 如何准备证书

设备服务端需一份 PEM 格式证书链和**与之匹配的私钥**，建议通过正规 ACME/内部 CA 取得，并把匹配的 FQDN 用作客户端 DoH/DoT 配置的服务器名称。证书必须与客户端请求时使用的域名 SAN 相符；若你直接访问 IP 地址，需要证书里明确包含 IP SAN 且客户端信任颁发者。

Web UI 的「DNS 设置 → TLS 证书配置」支持上传或粘贴 PEM。源码在 `main/web.c` 校验 X.509 证书及公私钥匹配，保存到 `cfg` NVS 分区，保存后触发延迟重启以避免在 HTTP 回调中销毁正在使用的 TLS 服务器。

**重要安全事实：** 此项目的应用配置 NVS 分区未声明为加密 NVS。私钥持久保存不等于“硬件安全存储”；拿到 Flash 镜像的人可能恢复其中的密钥。仅用于可控设备和环境。私钥、完整备份文件不应公开上传 GitHub、Issue 或 CI Artifact。

## 3. 客户端如何验证

DoH：

```bash
# 需在 DNS 能解析出该域名且证书真实有效时运行
curl -v 'https://dns.example.net/dns-query'
# 仅连通测试可能返回 400（缺少 dns 参数），但 TLS 必须成功握手。
```

DoT TLS 握手：

```bash
openssl s_client -connect dns.example.net:853 -servername dns.example.net -brief
```

实际 DNS 请求可使用 `kdig +tls @dns.example.net example.com A`、支持 DoH 的 `curl` 或其他合规客户端。在排障时可以暂时查看自签证书，但不要以 `-k` 跳过证书验证来宣称安全 DoH 已上线。

**测试成功标准：** 正确域名的证书验证通过、能完成 TLS 握手、发 DNS 报文拿到合法 DNS 响应、重复连接和证书更新后可继续服务。测试 DoH GET/POST 与 DoT 的 A/AAAA/TXT、大响应和并发连接。

## 4. 资源与协议约束

设备使用 ESP32-S3 Wi-Fi 和有限 SRAM。HTTPS 服务器由独立任务提供，DoT 源码默认单连接顺序处理。TLS 握手比普通 UDP DNS 更慢，且连接状态、证书和缓冲占用额外堆内存。不是在 8MB PSRAM 下就可以无限并发。应优先复用 TLS 会话，控制最大并发。

- DoH POST 必须发送 `Content-Type: application/dns-message`，GET 使用 `?dns=` 携带 Base64URL 编码的 DNS 请求。
- DoT 需要处理 TCP 分段、2 字节长度、保持连接和读取超时；不能仅把 UDP 包复制到 TLS 流。
- 未上传有效证书时服务端 TLS 端点不应工作；管理 HTTP 可正常访问配置页。
- HTTPS URL 和 DoT 都需要明确的主机名与可信证书链。公网访问还依赖 NAT/防火墙端口映射，不由 ESP32 自动配置。

## 5. 外网访问的风险

**不推荐把 ESP32 直接作为公开递归 DNS 服务器。** 对外暴露之前至少需要：只允许可信客户端或可信 IP/网段访问、启用并测试速率限制、管理口完全禁止公网访问、证书正确、日志避免存储敏感查询过久、网络入口有额外防护。开启 DoH/DoT 并不会自动阻止陌生人发送大量 DNS 查询。

设备内的 `local_only=true` 是一道重要保护，但它是基于来源地址和网络配置判断，并不等于账号级鉴权。通过公网反向代理或 NAT 可能改变所见来源 IP，因此需要在外层网关单独限制访问。

## 6. 管理密码与备份

管理端采用 HTTP Basic 认证；**仅设置管理密码并不能保护 HTTP 明文传输**。优先从可信管理 VLAN/VPN 访问；具备可验证证书后可以通过 HTTPS 同一个管理服务访问 API。不要把后台管理端口和 DoH 对公网同时开放。

`GET /api/backup` 导出的 JSON 包含 Wi-Fi 密码、密码哈希及盐、TLS 证书与私钥。必须将其视作**高敏感备份**并加密保存。不要上传到不可信网盘、公开聊天或 Issues。丢失私钥时应撤销/轮换证书，而不是只修改管理密码。

## 7. 证书轮换与故障排查

上传新证书和匹配私钥后观察系统是否重启/重新监听，检查 `GET /api/tls` 中的 `configured`/`https_running`/`dot_running`。错误证书、过期证书、错误 SAN、设备时间未同步和私钥不匹配都可能造成 TLS 错误。优先查看第一条 TLS 错误日志，再核对客户端的证书验证结果。

对于证书被误传到公共地方的情况，必须从 CA 端撤销/替换证书，重新生成私钥，然后上传并重启设备。

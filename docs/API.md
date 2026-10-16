# REST API

> 本文档由 AI 整理生成。

除特别说明外，所有接口都返回 JSON。设置管理密码后需要 HTTP Basic 认证（用户名默认 `admin`）。
浏览器跨站发出的 POST/PUT（`Origin` 与 `Host` 不一致）返回 403；脚本和 curl 不带 `Origin`，不受影响。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 版本、运行时间、内存、网络（含 `configured`、`last_reason` 断线原因码、`ap_active`、`ap_closing`、`ap_ip`）、DNS 统计（同 `/api/stats`）、规则状态（同 `/api/filters`） |
| GET | `/api/stats` | 计数器、各路径延迟（count/mean/p50/p90/p99，微秒）、缓存、上游 |
| POST | `/api/stats` | 清零统计 |
| GET | `/api/history` | 最近 24 小时每分钟的查询数和拦截数：`{interval, queries[], blocked[]}` |
| GET | `/api/querylog?limit=200&q=关键字&result=N` | 查询日志，最新的在前。result：0 上游、1 缓存、2 拦截、3 重写、4 本地、5 放行、6 失败、7 拒绝、8 响应拦截 |
| GET | `/api/config` | 完整配置（不含密码），结构见下 |
| PUT/POST | `/api/config` | 部分更新，只需提交要改的字段；返回 `{ok, restart_required}` |
| POST | `/api/password` | `{username, password}`；password 为空表示取消密码 |
| GET / PUT | `/api/rules` | 自定义规则（text/plain），保存后立即生效，返回规则状态 |
| GET / PUT | `/api/local` | 本地解析记录（text/plain），每行 `域名 类型 值 [ttl=N]` |
| GET | `/api/filters` | 订阅更新状态、当前镜像统计、各列表状态（规则数、大小、ETag、错误） |
| POST | `/api/filters/update[?force=1]` | 检查更新；`force=1` 表示强制重建 |
| POST | `/api/cache/flush` | 清空 DNS 缓存 |
| GET | `/api/check?name=x&type=A` | 规则诊断（判定、命中的规则和来源）+ 实际解析结果 |
| GET | `/api/wifi/scan` | 扫描 Wi-Fi |
| GET | `/api/backup` | 下载备份（配置 + 自定义规则 + 本地解析） |
| POST | `/api/restore` | 上传备份 JSON，恢复后重启 |
| POST | `/api/ota` | 请求体为固件 .bin（application/octet-stream），写入后重启 |
| POST | `/api/ota/url` | `{url: "https://..."}`，后台下载升级 |
| POST | `/api/reboot` | 重启 |
| POST | `/api/factory-reset` | 恢复出厂设置并重启 |
| GET | `/metrics` | Prometheus 文本格式指标 |
| GET/POST | `/dns-query` | DNS-over-HTTPS（RFC 8484，仅 HTTPS）：GET `?dns=base64url`，或 POST `application/dns-message`；不需要认证，按 DNS 访问控制规则处理 |

## 配置结构（GET/PUT /api/config）

```json
{
  "network":   {"hostname":"esp32-dns","ssid":"","password":"********","static_ip":false,
                "ip":"","netmask":"","gateway":"","ipv6":true,
                "ntp":["ntp.aliyun.com","cn.pool.ntp.org"],"timezone":"CST-8"},
  "dns":       {"port":53,"ipv6":true,"tcp":true,"local_only":true,"allow":[],
                "ratelimit":0,"refuse_any":true,
                "upstreams":["223.5.5.5","119.29.29.29"],"bootstrap":["223.5.5.5","119.29.29.29"],
                "strategy":"fastest","upstream_timeout_ms":1500,"query_timeout_ms":4000,
                "cache_size_kb":2048,"cache_min_ttl":0,"cache_max_ttl":0,
                "optimistic":false,"optimistic_max_age":43200,"qlog_entries":1000},
  "filtering": {"enabled":true,"block_mode":"default","custom_ipv4":"","custom_ipv6":"",
                "blocked_ttl":10,"update_interval_hours":24,
                "subscriptions":[{"name":"AdGuard DNS filter",
                                  "url":"https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
                                  "enabled":true,"allowlist":false}]},
    "system":    {"web_port":80,"doh":true,"username":"admin","password_set":false}
}
```

- `strategy`：`fastest`、`load_balance` 或 `parallel`。
- `block_mode`：`default`、`null_ip`、`nxdomain`、`refused` 或 `custom_ip`。
- 修改 `dns.port`、`dns.ipv6`、`dns.tcp`、`dns.qlog_entries` 或 `system.web_port` 后需要重启，此时响应中 `restart_required` 为 `true`；其余设置立即生效。
- `network.password` 为 `"********"` 或省略时保持原值。

## 示例

```bash
curl -u admin:密码 http://192.168.1.53/api/stats
curl -u admin:密码 -X PUT -H 'Content-Type: application/json' \
     -d '{"dns":{"upstreams":["tls://dns.alidns.com","https://doh.pub/dns-query"]}}' \
     http://192.168.1.53/api/config
curl -u admin:密码 -X PUT --data-binary @my_rules.txt http://192.168.1.53/api/rules
curl -u admin:密码 -X POST --data-binary @build/esp32s3_dns.bin http://192.168.1.53/api/ota
```

## HTTPS、认证与 API 的正确理解

上表的 REST 管理 API 在明文 HTTP Web 服务和已启用的 HTTPS Web 服务上均可用；但 **DoH 的 `/dns-query` 只在 HTTPS 服务上注册**。如果没有配置 PEM 证书和私钥，HTTPS/DoT 服务不会自动以不安全的明文形式退化。HTTPS 管理路径不等于 DoH：只有 `application/dns-message` 格式的 `/dns-query` 才是 RFC 8484 的 DNS 查询。

`GET /api/config` 不返回明文 Wi-Fi 密码、管理密码哈希或 TLS 私钥；完整备份接口会包含敏感配置及私钥，必须妥善保管。配置密码的唯一常规管理入口是 `POST /api/password`；通用 `/api/config` 对 pass_hash、pass_salt 会忽略，不应依靠直接编辑密码哈希字段修改管理口令。

### 实用操作示例

```bash
BASE=http://192.168.31.53

# 无管理密码时可省略 -u；设置后需要 Basic Auth
curl -u 'admin:YOUR_PASSWORD' "$BASE/api/status"
curl -u 'admin:YOUR_PASSWORD' "$BASE/api/config"
curl -u 'admin:YOUR_PASSWORD' -X POST "$BASE/api/filters/update?force=1"
curl -u 'admin:YOUR_PASSWORD' -X POST "$BASE/api/cache/flush"

# 添加自定义规则，保留文件中的换行
curl -u 'admin:YOUR_PASSWORD' -X PUT \
  -H 'Content-Type: text/plain; charset=utf-8' \
  --data-binary @custom_rules.txt "$BASE/api/rules"

# 查看证书配置状态（返回状态，不返回私钥）
curl -u 'admin:YOUR_PASSWORD' "$BASE/api/tls"
```

### TLS 证书上传示例

```json
{"cert":"-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\\n",
 "key":"-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n"}
```

上传到 `PUT /api/tls` 或 `POST /api/tls`。JSON 字符串内的 PEM 换行用 `\n` 转义，证书和私钥应匹配。后台把证书保存在 NVS，**不要把真实私钥写进脚本、README 或 Git**。

### DoH 查询接口

- GET：`https://域名/dns-query?dns=Base64URL_DNS_MESSAGE`，不应附带 base64 常规 `+`、`/` 编码，且 URL 参数长度受服务器限制。
- POST：`https://域名/dns-query`，请求头 `Content-Type: application/dns-message`，请求体为 DNS 二进制报文；返回同类型报文。
- 若允许 CORS OPTIONS，仍不能视为管理 API 授权；DoH DNS 查询走自己的访问控制。
- 本项目无需为所有 QTYPE 定义 HTTP API：普通 DNS 报文包含 QTYPE、QCLASS、EDNS 等信息。

### 返回状态与错误排查

`200` 通常表示 API 调用成功（DNS 报文内部仍可能包含 NXDOMAIN/SERVFAIL）；`400` 输入格式错误；`401` 缺少/错误认证；`403` 访问控制或跨站策略阻止；`404` 路径未注册；`413` 请求过大；`415` DoH POST Content-Type 错误；`500` 内部资源/存储失败。错误详情优先看 JSON `error` 与同时刻串口日志。不要把任意非 200 HTTP 响应都解释成 DNS NXDOMAIN。

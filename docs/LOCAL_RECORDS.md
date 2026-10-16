# 本地解析（自定义 DNS 记录与重写）

> 本文档由 AI 整理生成。

## 1. 功能范围

「本地解析」不是 Hosts 文件的简单 A 记录映射。它为指定域名构造本地 DNS 资源记录，可用于 NAS、家庭服务、容器名称、SRV 服务发现等。配置与过滤订阅独立，便于不重新编译几十万条订阅就更新少量局域网记录。

语法是一行一条：

```text
域名 类型 值 [ttl=秒]
```

空行和 `#` 注释按解析器约定处理；建议只使用 ASCII 域名 / `xn--` Punycode（不在 Web 表单中自动把中文转换为 IDN）。普通解析名称应为 FQDN，家庭内部建议使用 `home.arpa` 而不是任意伪 TLD。

## 2. 常见示例

```text
nas.home.arpa A 192.168.31.88
nas.home.arpa AAAA 2001:db8::88
router.home.arpa A 192.168.41.1
files.home.arpa CNAME nas.home.arpa
_service._tcp.home.arpa SRV 0 5 8080 nas.home.arpa
# 将指定 AAAA 查询交给上游（按解析器支持的 - 规则）
nas.home.arpa AAAA -
```

这里只是**语法参考示例**，示例地址需替换为本地实际可路由地址；`2001:db8::/32` 仅用于文档。

过滤规则里 `$dnsrewrite` 与这里的**本地解析文本**是两套配置入口，二者优先级以及 CNAME 跟随逻辑要按照 [架构与兼容性](ARCHITECTURE.md) 理解。不要认为“已配置 CNAME”就必定自动发布其目标的所有 RR；目标如果不在本地，可能发生额外上游查询。

## 3. 类型与注意点

| RR | 用途 | 注意事项 |
|---|---|---|
| A、AAAA | IPv4/IPv6 地址 | 地址族必须对应；设备自身不能凭这条记录替网络添加路由 |
| CNAME | 域名别名 | 跟随解析链应限制深度和循环，不能把一个名字同时当作任意记录的别名和独立授权记录 |
| TXT | 任意文字 | 长文本与特殊字符需按解析器要求转义 |
| MX | 邮件服务器 | 需要优先级和主机名，主机名应可被解析 |
| SRV | 服务发现 | 包含 priority、weight、port、target |
| PTR | 反向 DNS | QNAME 必须是正确的 `in-addr.arpa` / `ip6.arpa` 名称 |
| HTTPS/SVCB | 服务绑定 | 语法和参数受二进制 RDATA 编码器支持范围约束 |
| 其他 | 取决于编译器 | 不能直接把“不知道的文字”假设为合法 RDATA |

## 4. 验证与排错

```bash
dig @192.168.31.53 nas.home.arpa A
dig @192.168.31.53 nas.home.arpa AAAA
dig @192.168.31.53 files.home.arpa CNAME
dig +tcp @192.168.31.53 _service._tcp.home.arpa SRV
```

- **DNS 返回正确，但访问失败**：这是 IP 路由、ACL、服务监听或防火墙问题，DNS 不能保证 IP 可达。
- **TTL 没变化**：确认没有中间路由器 DNS 缓存或客户端缓存。
- **A 能用、AAAA 不行**：分别检查本地 AAAA、IPv6 DNS 监听和网络 IPv6 路由。`AAAA` 并不要求必须通过 IPv6 传输 DNS。
- **CNAME 结果异常**：检查循环、目标记录是否存在、目标是否会被过滤规则拦截。
- **保存后仍是旧记录**：先用显式 `dig @设备IP` 测试，再清空设备 DNS 缓存与客户端 DNS 缓存。

## 5. 优先级与应用场景

根据此版本 DNS 引擎的设计，本地解析在过滤订阅之前检查。设计目标是内部域名重写不受公网拦截列表误伤；这也意味着设置了本地记录时，部分相同名称的订阅规则不会再被执行。配置时需确认是你想要的效果。

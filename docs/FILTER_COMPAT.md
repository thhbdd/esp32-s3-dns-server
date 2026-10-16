# 过滤规则兼容性

> 本文档由 AI 整理生成。

**兼容绝大部分 AdGuard DNS 过滤规则。** 可以将 AdGuard DNS 规则列表的 URL 直接添加到 Web UI「过滤规则 → 订阅列表」，保存并执行「检查更新」即可下载、编译、生效，后续可继续更新；常见 hosts 格式列表也能使用，无需手动转换。仅适用于 DNS 的规则参与 DNS 过滤，少数不适用的规则或超出资源限制的语法会跳过并计数。

参照对象是 AdGuard Home 使用的 **AdGuard urlfilter v0.23.4** DNS 引擎，以及 AdGuard Home 的结果处理逻辑（`internal/filtering`、`internal/dnsforward`）。

## 验证方法

`tools/compat-oracle` 是一个 Go 程序，直接调用 urlfilter 的 `DNSEngine` 加上 AdGuard Home 的判定逻辑，作为参照实现。`compare.py` 把同一批查询分别交给本项目的 `flc batch` 和参照实现，逐条比较规范化后的判定（NONE、ALLOW、ALLOWLIST、BLOCK、BLOCK_HOSTS+IP、REWRITE_*）。

- **真实列表**：AdGuard DNS filter、AdAway、AdGuard 广告过滤（EasyList 类）、adblockdns 合并列表。查询包括列表中出现的域名、它们的子域和父域、随机名称，以及不同的查询类型。**历史版本曾报告 30 万次查询一致；此次未重新构建 Go 对照工具，不能视作当前交付版新实测。**
- **随机规则组合（torture）**：随机生成相互作用的规则（例外、important、badfilter、dnstype、denyallow、dnsrewrite、正则）。除下面列出的 D2/D3/D4 外，全部一致。
- 差异不是按规则形状粗略归类的：D2 要求参照实现在「所有 `$badfilter` 都生效」的规则表（删去它们和被否定的规则）上重算后，得到与本项目相同的结果；D3 要求两边都是重写结果，且确有多条重写规则在争夺应答。

```bash
cd tools/compat-oracle && go build -o compat-oracle .
python3 compare.py --flc ../../build-host/flc --oracle ./compat-oracle --lists a.txt b.txt --seeds 20
```

## 支持的语法

| 类别 | 说明 |
|---|---|
| hosts 语法 | `0.0.0.0 a.com b.com`、`127.0.0.1 x`、IPv6 地址；行内 `#` 注释 |
| 纯域名行 | `example.com`，与 hosts 规则 `0.0.0.0 example.com` 等价：只拦截该名称本身，不含子域名（urlfilter 行为） |
| 基本规则 | `\|\|d^`、`\|d^`、`d^`、`.d^`、`*.d^`、`://d^`、`\|\|d^\|`，通配符 `*`，分隔符 `^`，锚点 `\|` |
| 正则 | `/.../`，RE2 语法子集（与 Go regexp 语义一致，DFA/Pike VM 执行） |
| 例外 | `@@` |
| 修饰符 | `$important` `$badfilter` `$dnstype` `$dnsrewrite` `$denyallow` |
| $dnsrewrite | `NOERROR;A;1.2.3.4` 简写、`REFUSED`、`NXDOMAIN`、CNAME 简写、A/AAAA/CNAME/PTR/MX/TXT/SRV/HTTPS/SVCB/NS 等，以及例外 `@@...$dnsrewrite` |
| 白名单列表 | 订阅标记为「白名单」时，其中所有规则都是放行（AdGuard Home allowlist） |
| 注释 | `!`、`#` 开头的行；`[Adblock Plus 2.0]` 等头部 |

不适用于 DNS 的规则会被统计并跳过，与 AdGuard 行为相同：元素隐藏（`##`、`#@#`、`#$#`）、`$third-party`、`$domain`、`$match-case`、`$script` 等请求类型修饰符、过宽的规则。统计结果显示在 Web 界面的「过滤规则」页。

## 已知差异

| 编号 | 场景 | 本项目 | urlfilter / AdGuard Home | 说明 |
|---|---|---|---|---|
| D1 | hosts 行内注释 | 在 `#` 处截断 | 截断到 `#` 前一个字符 | 只影响 `#` 前没有空格这类畸形行，真实列表中没有出现 |
| D2 | 同一请求命中**多条** `$badfilter` | 每条 badfilter 都禁用其对应规则 | 只有最后一条生效（urlfilter 实现缺陷），其余被否定的规则仍会命中 | 本项目按文档语义处理 |
| D3 | 多条相互冲突的 `$dnsrewrite`（例如 CNAME 和 RCODE 同时命中，或两条不同目标的 CNAME） | 按列表中的出现顺序 | 取决于内部索引顺序，不稳定 | 本项目的结果可预测 |
| D4 | 例外 `@@...$dnsrewrite=NOERROR;MX;...`（SRV、SVCB、HTTPS 同） | 值相同的重写被取消 | 永远不匹配（比较的是指针） | 本项目按文档语义处理 |
| D5 | 例外规则移除重写后的下一条重写 | 正常参与判定 | urlfilter 在遍历中删除元素，紧跟其后的一条会被跳过，被跳过的例外有时反而当作重写生效 | 只在多条重写和例外交错时出现 |
| D6 | 字母大小写：hosts 行中的大写域名、`$denyallow=Good.example.com`、`$dnsrewrite=X.org`（指向自身） | 不区分大小写 | 按原样比较（hosts 中的大写域名永远不匹配；指向自身的判断区分大小写） | DNS 名称本身不区分大小写 |
| D7 | 名称中含 `/`、`:`、`\@`、`\DDD` 等主机名以外的字符 | 域名规则按标签精确匹配 | `^`、`\|\|` 按字符匹配，结果可能不同 | 正常的 DNS 查询不会出现这类名称 |
| D8 | 文本形式超过 253 个字符的名称（二进制标签写成 `\DDD` 后变长） | 开启过滤时直接返回 REFUSED（无法检查就不解析） | 照常匹配 | 正常域名的文本形式不会超过 253 个字符 |
| D9 | 正则中极少见的写法：标志组后直接跟重复符（`a(?i)*`） | 视为语法错误，规则不匹配 | 按 `a*` 处理 | `\Q...\E` 后的重复符、空标志组 `(?)` 与 Go 一致 |

## 不支持或有限制的部分

| 项目 | 处理方式 |
|---|---|
| `$denyallow` 中使用通配 TLD（如 `example.*`） | 需要公共后缀列表，规则计入「不支持」 |
| `$respgeo` | 需要 GeoIP 数据，规则计入「不支持」 |
| IDN（中文域名） | 不做 punycode 转换；请使用 `xn--` 形式书写规则 |
| 例外 `$dnsrewrite` 的 MX/SRV/SVCB 值比较 | 按编码后的 RDATA 比较（等价写法视为相同） |
| 超过 255 字节的 TXT 值 | 自动拆分成多个字符串 |
| 单行超过 4096 字节 | 计入 `too_long` |
| 单个镜像上限 | 4 MB（Flash 槽位大小），约 30 万个不同域名；编译临时区 4.5 MB |
| 同一域名上超过 255 条带修饰符的规则 | 保留列表中最靠前的 255 条，其余计入「不支持」 |
| 同一 hosts 名称超过 16 个地址 | 只保留前 16 个 |
| 一次查询命中大量规则（超过 64 条） | 优先保留例外、important、重写和 badfilter，普通拦截规则让位，判定不受影响 |
| 没有可用字面量、每次查询都要运行的正则 | 先尝试编译成 DFA；仍是 NFA 的，总指令数上限 4096，超出的规则计入「不支持」（防止恶意列表拖慢每次查询） |
| 列表中途出现二进制数据 | 整次编译作废并报错（保留旧镜像）；开头就是 HTML 或二进制的列表被整体拒绝 |
| 规则行首尾的空白 | 与 Go `strings.TrimSpace` 相同，包括全角空格等 Unicode 空白 |

## AdGuard Home 结果处理

| 情况 | 应答 |
|---|---|
| 拦截，默认模式，hosts 规则 | 规则中对应地址族的 IP；没有对应地址族时返回 0.0.0.0 或 :: |
| 拦截，默认模式，普通规则 | A → 0.0.0.0，AAAA → :: |
| 拦截，非 A/AAAA 查询 | NODATA + SOA（`fake-for-negative-caching.adguard.com`）；null_ip 模式下为空 NOERROR |
| 拦截，nxdomain、refused 模式 | NXDOMAIN + SOA、REFUSED |
| 拦截，custom_ip 模式 | 自定义的 v4/v6 地址（未设置时返回空应答） |
| `$dnsrewrite=NXDOMAIN` 等 RCODE | 只有该 RCODE，没有 SOA |
| `$dnsrewrite` 记录 | 只返回与查询类型相同的记录，TTL 使用「拦截响应 TTL」 |
| `$dnsrewrite` CNAME | 转发目标名称，答案前补上 CNAME，不做响应过滤 |
| 响应过滤 | 依次检查 CNAME 目标、A/AAAA 地址、HTTPS 记录的地址提示；命中拦截规则时，按原查询生成拦截应答 |
| 过滤保护关闭 | 只有重写规则生效 |

兼容性参照工具和历史差分数字使用了当时的列表与编译版本。更新过滤引擎、调整规则索引或迁移新 ESP-IDF 后，应重新进行差分测试，不能把历史测试一致率理解为所有规则组合都完全兼容。

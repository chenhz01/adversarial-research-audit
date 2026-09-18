# PATCHES — adversarial review log（九步对攻产出，2026-09-12）

对攻方式：红队（黑客/统计怀疑者）→ 白队（事实核查）→ 蓝队（测试工程师/SRE）→ 黄队（合规）。

| ID | 优先级 | 身份 | 问题 | 根因 | 变更 | 验证 | 状态 |
|----|--------|------|------|------|------|------|------|
| PATCH-001 | P1 | 统计怀疑者 | 重复来源（同URL镜像）被算作多源，`verified` 虚高 | sources 只看数量不查唯一性 | `judge_claims` 按 url/name 去重 | tests/test_audit.py::TestSourceDedup ✅ | closed |
| PATCH-002 | P1 | 黑客 | MCP `raw` 无大小上限，超大 JSON 可打挂宿主进程 | 未设输入闸 | `MAX_RAW_CHARS=1_000_000` 超限返回 -32602 | 代码路径审查（未单测大payload） | closed |
| PATCH-003 | P2 | 事实核查 | README 未声明"不验证来源真实性"，易被误读为全功能事实核查 | 诚实边界只在协议 Non-goals 里 | README 顶部加 Honest boundary 声明 | 人工复核 ✅ | closed |
| PATCH-004 | P1 | 测试工程师 | 零测试，回归全靠手跑 | v1 快速发布 | tests/test_audit.py（7 用例）+ GitHub Actions CI | 本地 7/7 通过 ✅ | closed |
| PATCH-005 | P3 | 维护者 | 缺 SECURITY.md / CONTRIBUTING.md | v1 范围控制 | 未做——发布后首个社区 PR 前补齐 | — | open |

## 第二轮（加硬：真实性验证，2026-09-12 下午）

| ID | 优先级 | 身份 | 问题 | 根因 | 变更 | 验证 | 状态 |
|----|--------|------|------|------|------|------|------|
| PATCH-006 | P1 | 白队 | 五关只查算术自洽，不查来源是否真实存在——"技术含量"天花板低 | 设计缺陷 | 新增 `verify.py`（HTTP HEAD→GET→SHA-256，含缓存/大小上限） | tests/test_verify.py 8 用例 ✅ | closed |
| PATCH-007 | P0 | 事实核查 | **网络/代理失败被误判为"源已死"**（沙箱 HTTP_PROXY 劫持回环→502→dead），是诚实性硬伤 | 异常分支默认 ok=False | `PROXY_ERROR_CODES{407,502,503,504}`→ok=None+degraded；回环绕过代理；结果标 `via_proxy` | 本地 e2e：live=ALIVE / missing=DEAD（1 dead 正确）✅；单测覆盖 503 与回环旁路 ✅ | closed |
| PATCH-008 | P1 | 架构师 | 无法接入真实研究工具，"works with" 只是口号 | 缺适配层 | 新增 `adapters/llm_wiki.py`：按 nashsu/llm_wiki(18.9k★) 真实契约解析 wiki/ + frontmatter `sources[]` + `[[wikilink]]` | tests/test_adapter.py 5 用例 + `examples/llm-wiki-demo` 实跑 FAIL 5/6 ✅ | closed |
| PATCH-009 | P1 | 审计员 | 引用完整性无闸门：幽灵引用/悬空链接不影响判定 | 只有 5 关 | 新增 gate6（输入带 `integrity` 才启用，向后兼容 5 关制） | 干净项目 PASS 6/6；缺陷项目 FAIL 且 gate6 点名 ✅ | closed |
| PATCH-010 | P2 | 极简主义者 | adapter 首版把"未编译源"算进覆盖率导致 examined>total 自相矛盾 | 审计单元混淆（页 vs 源） | 覆盖率单元统一为 wiki 页；未编译源降级为 gate6 备注 | 21/21 测试 ✅ | closed |

## 第三轮（发布前检测流程，2026-09-12 下午）

| ID | 优先级 | 身份 | 问题 | 根因 | 变更 | 验证 | 状态 |
|----|--------|------|------|------|------|------|------|
| PATCH-011 | P1 | SRE | 文件以 **CRLF** 入库（编写机为 Windows），他人 clone 后会被整文件重写、产生全文件 diff，diff 历史失真 | 缺 `.gitattributes` | 新增 `.gitattributes`（`* text=auto eol=lf`）+ `git add --renormalize .` 重写 blob | 线上 blob 经 API 直读复核 **CR 行数 = 0** ✅ | closed |
| PATCH-012 | P1 | 测试工程师 | CI 只验退出码，不验 JSON 输出契约（verdict 合法值、gate 数量、5 关制向后兼容），契约回归无保护 | 断言过薄 | CI 增 JSON contract 步骤 | 本地 CI 全步骤复现通过 ✅ | closed |
| PATCH-013 | P2 | 商业 | 无求合作入口，与既有发布惯例不一致 → 流量来了没有转化出口 | 缺 | README 增 `Collaboration / 合作` 段（统一对外邮箱） | 人工复核 ✅ | closed |
| PATCH-014 | P3 | 维护者 | 缺 SECURITY.md / CONTRIBUTING.md（PATCH-005 遗留） | 范围控制 | 未做——发布后首个社区 PR 前补齐 | — | open |

## 第四轮（transport 安全：DNS-rebinding 修复，2026-09-18 · 外部审查驱动）

| ID | 优先级 | 身份 | 问题 | 根因 | 变更 | 验证 | 状态 |
|----|--------|------|------|------|------|------|------|
| PATCH-015 | P0 | 外部审查者(GodBlf)+独立AI | **DNS-rebinding**：取源时 DNS 解析与连接建立分离，且完全无 IP 校验——`evil.com` 解析到 127.0.0.1/内网 IP 照连，重定向跳同样裸奔（deer-flow#5472 合并阻塞） | 验证与连接是两步（TOCTOU） | `verify.py` 重构传输层：解析一次→逐 IP `is_global` 校验（解包 IPv4-mapped IPv6，显式拒组播/保留/未指定段——CPython 3.13 对部分组播段 `is_global=True` 不可依赖）→socket 只拨已验证地址（SNI/Host/证书校验保持原域名）→HEAD/GET/同主机跳共享 TTL 钉扎缓存封死翻转窗口→跨主机重定向每跳重新验证→默认受限策略 fail-closed（`allow_private_networks=False`，CLI `verify_sources` 同步收紧为显式开启）→policy-blocked=ok=False（确定性）、传输失败仍 ok=None（诚实语义） | `tests/test_verify.py` 新增 7 回归（loopback 默认拒/私网解析拒/rebinding 翻转不触内网/重定向跳重验/mapped-IPv6 拒/pin 缓存单次解析/GET 传输失败保持 ok=None），verify 线 16 用例 ✅；全量套件 36 用例（verify 16 + MCP server 8 + adapter 5 + audit 7）✅；独立 AI 对抗验证双轮 PASS（实测 flip 不改拨、混合记录只拨公网、组播/保留/CGNAT/链路本地全拒、代理路径跳过有文档） | open（待推送） |

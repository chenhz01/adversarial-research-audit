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
| PATCH-015 | P0 | 外部审查者(GodBlf)+独立AI | **DNS-rebinding**：取源时 DNS 解析与连接建立分离，且完全无 IP 校验——`evil.com` 解析到 127.0.0.1/内网 IP 照连，重定向跳同样裸奔（deer-flow#5472 合并阻塞） | 验证与连接是两步（TOCTOU） | `verify.py` 重构传输层：解析一次→逐 IP `is_global` 校验（解包 IPv4-mapped IPv6，显式拒组播/保留/未指定段——CPython 3.13 对部分组播段 `is_global=True` 不可依赖）→socket 只拨已验证地址（SNI/Host/证书校验保持原域名）→HEAD/GET/同主机跳共享 TTL 钉扎缓存封死翻转窗口→跨主机重定向每跳重新验证→默认受限策略 fail-closed（`allow_private_networks=False`，CLI `verify_sources` 同步收紧为显式开启）→policy-blocked=ok=False（确定性）、传输失败仍 ok=None（诚实语义） | `tests/test_verify.py` 新增 7 回归（loopback 默认拒/私网解析拒/rebinding 翻转不触内网/重定向跳重验/mapped-IPv6 拒/pin 缓存单次解析/GET 传输失败保持 ok=None），verify 线 16 用例 ✅；全量套件 36 用例（verify 16 + MCP server 8 + adapter 5 + audit 7）✅；独立 AI 对抗验证双轮 PASS（实测 flip 不改拨、混合记录只拨公网、组播/保留/CGNAT/链路本地全拒、代理路径跳过有文档） | pushed（e2771c7） |

## 第五轮（RFC 落地：CLI adapter，2026-09-18 · 外部审查驱动）

| ID | 优先级 | 身份 | 问题 | 根因 | 变更 | 验证 | 状态 |
|----|--------|------|------|------|------|------|------|
| PATCH-016 | P1 | 外部审查者(GodBlf RFC)+独立AI | audit pipeline 只有 MCP 入口（mcp_server.py）与旧式 audit.py CLI（文本输出+退出码只有 0/1/2），shell/CI 流水线无法以机器可读、语义诚实的方式接入；GodBlf RFC 三问（exit states/audit log/unknown candidate set）无落地 | 入口适配层缺位 | 新增 `cli_adapter.py`（与 mcp_server.py 平级，stdin/文件 → 不变 envelope）：①**边界1 exit states**——verdict 与 degraded 保持分离字段，退出码表文档化优先级（0=PASS/PASS-WITH-CAVEAT 无降级；1=FAIL 盖过 degraded；2=输入/用法错误无 envelope；3=执行错误（崩溃/日志 fail-closed），绝不重标 DEGRADED；4=PASS 但 degraded=true，verdict 不可靠（含 JSON 解析成功但非对象的无 verdict 降级 envelope，同归 4））；②**边界2 audit log**——append-only JSONL keyed by trace_id（audit_started/verification_opt_out/audit_finished/audit_execution_error），stdout 只走不变 envelope、诊断走 stderr，opt-out 记录失败 fail-closed（拒绝产出无法追溯的 envelope，待 GodBlf 裁决）；③**边界3 unknown candidate set**——adapter 零新语义：coverage/candidate_set 原样透传引擎，不用观测集合大小冒充未知总数，unknown total 的 coverage 表示留给 core-contract issue；取源策略显式收紧（与 mcp_server 同一 env var 显式开启机制）；**参数解析严格化**——未知选项/带值选项缺值一律 exit 2（`--cache --offline` 吞 flag 会致意外在线验证、`--audit-log` 缺值静默无日志会破坏审计链，均不许静默回退）；顺带修引擎既有缺陷：`judge_claims` 对非 list `claims` 抛 TypeError 违反 audit() never-raises 契约 → 防御性返回空 | `tests/test_cli_adapter.py` 20 用例（exit 0/1/2/3/4 全覆盖、crash≠DEGRADED、JSONL 追加+trace 贯穿、opt-out 事件有无两向、fail-closed mock 化、unknown total 透传不变、envelope 键集不变、私网 URL 默认拒、未知选项/缺值/吞 flag 三回归）+ `tests/test_audit.py` 2 用例（非 list claims 不崩、非 dict claim 项跳过）✅；全量 58/58（verify 16 + MCP 8 + adapter 5 + audit 9 + CLI adapter 20）；独立 AI 对抗验证双轮（AI#1 实测五档退出码+1MB 边界+内网 6 类全拒+envelope 逐字节等同原生，PASS 带 2 P1 → 全修复 → AI#2 复审：代码全部达标，指出 PR 草稿数字失实（已更正）与退出码表缺 degraded-无-verdict 子情形（已补注三处）） | open（待推送） |

## 第六轮（transport 收口：外部审查三 finding，2026-09-20 · GodBlf 复核驱动）

| ID | 优先级 | 身份 | 问题 | 根因 | 变更 | 验证 | 状态 |
|----|--------|------|------|------|------|------|------|
| PATCH-017 | P0 | 外部审查者(GodBlf, e2771c7 复核)+独立AI | GodBlf 在复核 `e2771c7` 时指出三处，均会破坏"受限模式"的承诺：①**代理配置绕过受限传输**——`_build_opener()` 在显式 proxy 或 `getproxies()` 非空时回退到普通（无钉扎）opener，静默跳过地址校验；②**GET 超时仍报成功**——HEAD 200 后 GET 抛 `TimeoutError` 落入通用 `except Exception`，只写 error 不清 `ok=True`，summary 报 `alive=1 / degraded=False`；③**policy-blocked 被计为 dead**——`_PolicyBlocked` 产出 `ok=False`，被 summary 计入 `dead`，把"策略决定不访问"说成"源已死" | `ok` 单一布尔被复用承担"是否可达/是否活着/是否被策略拦截"三种语义；代理路径与直连路径的传输保证不对等 | `verify.py`：①`_build_opener` 受限于 `allow_private_networks`——非回环/非 NO_PROXY 且存在代理时，受限模式抛 `_ProxyPolicyUnsupported`（fail-closed，绝不回退无钉扎 opener），显式 `allow_private_networks=True` 为文档化逃生口；②GET 通用异常分支改判 `outcome=unknown`（不再继承 HEAD 的 ok=True）；③引入四态 `outcome ∈ alive/dead/unknown/blocked`，`ok` 降为生命性投影（blocked→None），`summary` 增 `blocked` 独立计数且 `dead` 只计 `outcome=="dead"`，`fail_on_policy_block`（`--fail-on-policy-block`）为"策略拦截即判失败"的显式开关。`audit.py`：`verify_sources` 透传 blocked/policy_blocked_failed；`gate_integrity` 对 blocked 只出备注不判失败、仅 `policy_blocked_failed` 才判失败 | `tests/test_verify.py` 新增 10 用例（HEAD 成功→GET 成功共享单次解析｜HEAD 200→GET `TimeoutError` 判 unknown+`alive≠1`+`degraded=True`｜policy-blocked 不计 dead｜fail_on_policy_block 显式开关｜受限模式重定向到私网目标判 blocked｜显式代理拒｜环境代理拒｜代理不被静默放行｜NO_PROXY 命中仍走钉扎｜显式代理在 opt-in 下放行）+ `tests/test_audit.py` 新增 3 用例（blocked 不判失败只出备注｜dead 仍判失败｜policy_failed 仅显式配置时失败）；全量 **71/71** ✅；独立复现脚本逐条重放三 finding，**3/3 复现为已修复** | open（待推送） |


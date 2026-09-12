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

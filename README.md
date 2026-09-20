# Flow2API Token Updater v3.4

Flow2API Token Updater 是一个轻量级的多账号令牌刷新工具。
支持两种刷新模式：**协议刷新**（纯 HTTP，无需浏览器）和**浏览器刷新**（Playwright 持久化上下文）。
迁移到 `flow.google.com` 后默认使用浏览器刷新，取得完整 Google/Flow Cookie 与兼容 REST 的 Labs session。
旧的纯协议刷新仅在 `FLOW_PROTOCOL_REFRESH_ENABLED=true` 时启用，不代表已建立新站会话。

当前版本重点解决三件事：

- 多账号管理
- 单账号级别的 Flow2API 目标覆盖
- 协议刷新 + 浏览器自动登录
- 带图表和近期活动的实时仪表盘（Dashboard）

## 亮点

- **协议刷新**：无需浏览器，纯 HTTP 请求刷新 session token（由 [Hooper](https://github.com/Hooper27) 提供技术方案）
- 有界回退：协议授权失效时回退源浏览器；目标连接、代理、限流和独立登录保护错误不会触发重复登录或清空源 Cookie
- 浏览器自动登录：支持自动填写账号密码登录（多语言：中/英/日/韩/西/法/德/葡/俄）
- 运行时轻量：只有在需要登录时才会启动 VNC / Xvfb / noVNC
- Cookie 导入：支持导入 Google cookies 进行协议登录，或导入 labs.google cookies 恢复会话
- 完整会话：浏览器登录后提取带 domain/path/expiry 的 Google/Flow cookies，同步后由目标持久化浏览器继续轮换
- 智能同步：按最终生效的 Flow2API 地址和令牌分组
- 单账号覆盖：每个 Profile 都可以覆盖目标地址和连接令牌
- 代理支持：每个 Profile 都可以使用独立代理
- 实时仪表盘：优先使用 SSE，失败时自动回退到轮询
- 图表范围切换：6 小时 / 24 小时 / 72 小时 / 7 天
- 内置分析：同步活动、失败原因、目标实例分布

## 工作原理

### 刷新策略

1. 每个账号维护独立持久化 Profile 和结构化 Google cookies（`google_cookies` 字段）。
2. 默认在源 Profile 的代理下打开 Labs/Flow，校验 Labs `/auth/session` 的有效期、邮箱和 `/v1/credits` 实际鉴权，再等待 Flow 主域 Cookie。读到旧 ST、页面打开成功或 session HTTP 200 都不代表授权有效。
3. 刷新后重新读取最新 Cookie 快照，再同步到目标。目标服务必须确认 Cookie、代理、`oauth_verified=true` 和 `account_active=true`，否则不报告账号已恢复。
   - Profile 的 `proxy_url` 用于源浏览器；新增 `captcha_proxy_url` 是目标 Flow2API 可访问的同出口代理地址。
   - 首次同步或 ST 续期变化时必须填写 `captcha_proxy_url`。只有 ST 与目标保存值完全相同且已有代理绑定时，目标才可以沿用已有代理。不会自动复制源服务器的 `127.0.0.1` 地址。
   - 两台机器地址不同不代表出口不同；必须核对实际公网出口一致。
   - 协议模式也必须校验授权并发送完整 Cookie；纯文本旧 Cookie 会先进入浏览器补全，不能裸 ST 提交。
4. 同步结果分组逻辑：
   - 按”最终生效目标地址 + 最终生效令牌”分组
   - 先调用 Flow2API 的 `check-tokens` 接口，只刷新需要刷新的 Profile
   - 如果目标端检查失败，该分组记录失败并等待下次调度；不会因服务故障触发全部源账号重新登录
   - 目标 Flow2API 必须提供带连接 Token 鉴权的 `POST /api/plugin/check-tokens`。404/405 会显示具体接口及 HTTP 状态码；请先补齐/升级接收端，而不是反复重新登录。目标地址填写基础地址，不是完整的 `/api/plugin/update-token` 路径。
   - 状态响应中的 `sync_allowed=false` 表示目标不允许外部会话同步（如服务器独立登录），智能同步会优先跳过；人工强制同步仍受目标端的防覆盖校验保护。

### 登录方式

升级顺序：先升级 Flow2API 服务端（支持 `google_cookies`、`oauth_verified`、`account_active` 等确认字段），再升级同步器，
在每个源 Profile 完成 Labs 授权和 Flow 登录并手动同步。普通列表/API 不返回原始 Google Cookie；不要将 Cookie、页面 XSRF 或签名媒体链接写入日志。

接收确认只表示目标已保存配置，不保证跨机器登录可用。Google 可能存在设备/会话绑定；若目标 native Profile 查询返回 401 或跳转未登录页，需要在目标完成登录验收。不要反复重放 Cookie 或将其误判为流量 429。

| 方式 | 说明 | 自动提取 cookies |
|------|------|------------------|
| VNC 手动登录 | 通过 noVNC 完成 Google 登录 | 是 |
| 浏览器自动登录 | 配置账号密码后自动登录 | 是 |
| 协议 Cookie 导入 | 导入 Google cookies 直接协议登录 | 直接使用 |
| Labs Cookie 导入 | 导入 labs.google 域名 cookies 恢复会话 | 首次同步时提取 |

## 快速开始

### 1. 克隆并配置

```bash
git clone https://github.com/genz27/flow2api_tupdater.git
cd flow2api_tupdater
cp .env.example .env
```

至少需要在 `.env` 中设置以下变量：

- `ADMIN_PASSWORD`
- `FLOW2API_URL`
- `CONNECTION_TOKEN`

### 2. 启动服务

```bash
docker compose up -d --build
```

### 3. 访问应用

- 管理界面（Admin UI）：`http://localhost:8002`
- noVNC：`http://localhost:6080/vnc.html`

> 只有在启用并实际使用 VNC 登录时，端口 `6080` 才有意义。

## 常见使用流程

### 流程 A：通过 VNC 登录

1. 打开管理界面。
2. 配置全局默认的 Flow2API 地址和连接令牌。
3. 创建一个 Profile。
4. 点击 `Login` 启动浏览器。
5. 在 noVNC 中完成 Google 登录。
6. 点击 `Close Browser` 保存当前登录状态。
7. 手动执行一次同步，确认账号可用。
8. 后续刷新交给定时任务处理。

### 流程 B：协议 Cookie 导入（推荐）

1. 使用浏览器插件（如 Cookie Editor）导出以下域名的 cookies：
   - `.google.com` 域名下的所有 cookies
   - `accounts.google.com` 域名下的所有 cookies
   - `flow.google.com` 的 cookies（包括 OSID）
2. 创建一个 Profile。
3. 点击 `协议登录`，粘贴合并后的 cookies JSON。
4. 系统通过 OAuth 流程获取并校验 session token，然后在源浏览器补全和验证 Flow 登录。后续同步默认仍使用浏览器刷新。

> 提示：合并为一个 JSON 数组，保留 domain/path/expires，不能将不同域同名 Cookie 压平。Google 二次验证需人工完成。

### 多实例 Flow2API 配置

如果某个账号需要同步到另一套 Flow2API 实例：

1. 打开该 Profile 的编辑对话框。
2. 设置 `Flow2API URL override`。
3. 如果目标实例使用不同令牌，再设置 `Connection Token override`。
4. 保存后，这个 Profile 会优先使用覆盖值。

## 仪表盘

管理仪表盘包含以下内容：

- 概览指标
- 可切换时间范围的同步活动图表
- 状态分布和账号排行
- 失败原因聚合
- 目标实例分布
- 近期活动流
- 实时连接状态

前端默认优先使用 SSE 获取实时更新；
如果实时流不可用，会自动回退到轻量轮询。

## 持久化

默认的 `docker-compose.yml` 会挂载以下目录：

- `./data` -> `/app/data`
  - `profiles.db`：账号数据和同步历史
  - `config.json`：持久化的全局默认配置
- `./profiles` -> `/app/profiles`
  - Playwright 持久化浏览器 Profile 数据
- `./logs` -> `/app/logs`
  - 运行日志

## 环境变量

应用当前实际使用的环境变量如下：

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `ADMIN_PASSWORD` | 管理界面密码 | 空 |
| `API_KEY` | 对外 API 的访问密钥 | 空 |
| `FLOW2API_URL` | 全局默认 Flow2API 地址 | `http://host.docker.internal:8000` |
| `CONNECTION_TOKEN` | 全局默认 Flow2API 连接令牌 | 空 |
| `REFRESH_INTERVAL` | 定时刷新间隔，单位分钟 | `60` |
| `SESSION_TTL_MINUTES` | 管理端会话 TTL，`0` 表示永不过期 | `1440` |
| `CONFIG_FILE` | 持久化全局配置文件路径 | `/app/data/config.json` |
| `API_PORT` | HTTP 监听端口 | `8002` |
| `ENABLE_VNC` | 是否启用 VNC 登录入口，`1/0` | `1` |
| `VNC_PASSWORD` | noVNC / x11vnc 密码 | `flow2api` |

### 配置优先级

最终生效目标按以下顺序决定：

1. Profile 级别的 `flow2api_url`
2. 全局 `FLOW2API_URL`

连接令牌按以下顺序决定：

1. Profile 级别的 `connection_token_override`
2. 全局 `CONNECTION_TOKEN`

## API 参考

### 管理端 API

以下接口由 Web 仪表盘使用：

- `POST /api/login`
- `POST /api/logout`
- `GET /api/auth/check`
- `GET /api/status`
- `GET /api/dashboard?hours=6|24|72|168`
- `GET /api/dashboard/stream?session_token=...`
- `GET /api/config`
- `POST /api/config`
- `GET /api/profiles`
- `POST /api/profiles`
- `GET /api/profiles/{id}`
- `PUT /api/profiles/{id}`
- `DELETE /api/profiles/{id}`
- `POST /api/profiles/{id}/launch`
- `POST /api/profiles/{id}/close`
- `POST /api/profiles/{id}/check-login`
- `POST /api/profiles/{id}/import-cookies`
- `GET /api/profiles/{id}/export-cookies?kind=session|google`（默认导出 `google`）
- `POST /api/profiles/{id}/extract`
- `POST /api/profiles/{id}/sync`
- `POST /api/sync-all`

### 对外 API

以下接口需要在请求头中携带 `X-API-Key`：

- `GET /v1/profiles`
- `GET /v1/profiles/{id}/token`
- `POST /v1/profiles/{id}/sync`
- `GET /health`

## 升级说明

### 2026-09-09 会话同步修复

保持源浏览器与目标 Native Profile 分离。本次不迁移数据库、不重置账号、不覆盖服务器独立登录态。

1. 备份并保留 `data/` 和 `profiles/`，部署本次代码；默认保持 `FLOW_PROTOCOL_REFRESH_ENABLED=false`。
2. 为每个 Flow Profile 配置源 `proxy_url` 和目标可访问的 `captcha_proxy_url`，两端实际公网出口需相同。源代理已启用但地址缺失或无效时停止请求，不回退默认出口。
3. 先手动同步一个账号，确认响应 `success=true`、`oauth_verified=true`、`account_active=true`，再进行批量同步和目标生成验收。
4. 提示 Labs 过期时，同步器会在源 Profile 尝试一次正常 OAuth 续期；遇到二次验证或账号选择不一致，需要在源浏览器人工完成。仅重新登录 Flow 新站不会保证 Labs 授权续期。
5. `account_disabled` 表示会话已保存但账号仍禁用，应检查目标启用设置；`independent_login` 表示目标独立登录保护，需在目标处理，不要反复推送覆盖。

本次本地回归测试覆盖过期授权、撤销 AT、代理异常、Cookie 轮换及目标拒绝；不等同于部署后的真实生成验收。详细检查清单见 [会话修复说明](docs/session-sync-recovery-2026-09-09.md)。

### 升级到 v3.4

v3.4 新增了协议刷新能力：

- 协议登录（Cookie 导入 → OAuth 流程 → session token）
- 浏览器登录后自动提取 Google cookies，后续转协议刷新
- 协议刷新失败自动回退浏览器
- 浏览器自动登录多语言支持（日/韩/西/法/德/葡/俄）
- `login_method` 字段标识登录方式
- UI 全面重构

升级步骤：

1. 备份 `data/` 和 `profiles/`。
2. 拉取最新代码。
3. 重新构建并重启容器（`docker compose up -d --build`）。
4. 应用会自动创建新字段（`google_cookies`、`login_method`）。
5. 已登录的账号下次同步时会自动提取 Google cookies，无需重新登录。

### 升级到 v3.3

v3.3 新增了以下能力：

- Profile 级目标地址覆盖
- Profile 级连接令牌覆盖
- 同步历史存储
- 实时仪表盘和 SSE 流
- 失败原因聚合
- 目标实例分布
- 仪表盘时间范围筛选

建议按以下步骤升级：

1. 备份 `data/` 和 `profiles/`。
2. 拉取最新代码。
3. 重新构建并重启容器。
4. 应用会在需要时自动创建新字段和历史表。
5. 重新检查管理界面中的全局默认配置。
6. 如果你使用多套 Flow2API 目标，再检查一次各 Profile 的覆盖配置。

## 故障排查

### 同步提示：Flow2API URL 或令牌不完整

说明最终生效的目标配置不完整。请检查：

- 全局默认目标配置
- Profile 级地址覆盖
- Profile 级令牌覆盖

如果某个 Profile 指向另一套 Flow2API 实例，通常也需要为它配置匹配的令牌覆盖。

### 同步提示：提取令牌失败

说明当前保存的浏览器会话已经不可用。可以尝试：

- 通过 VNC 重新登录
- 导入新的 Cookie
- 在再次同步前先执行一次 `Check Login`

### noVNC 无法使用

请检查：

- `ENABLE_VNC=1`
- 端口 `6080` 已正确映射
- 你确实点击了对应 Profile 的 `Login` 按钮

### 修改了 `API_PORT` 但无法访问应用

如果你修改了应用监听端口，也要同时更新 `docker-compose.yml` 中的端口映射。

## 许可证

MIT

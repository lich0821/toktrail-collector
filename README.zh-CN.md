# TokTrail Collector

[English](README.md)

TokTrail Collector 是一个本地优先的 Go CLI，用于从受支持的本地开发工具中采集经过隐私过滤的 Token 使用元数据。

Collector 的设计目标是：即使没有账号，本地检查仍然可用。`scan`、`preview`、`export` 和诊断命令都可以离线运行；上传则需要显式设备绑定，并在每次上传前进行服务端 consent 预检。

## 采集什么

当前实现支持：

- Codex session JSONL（`codex-jsonl`）。
- Claude Code session JSONL（`claude-code-jsonl`）。
- 用于集成与兼容测试的合成/自由格式 `usage-json`。

Collector 上传 Token 使用计数和稳定的隐私安全记录标识。它不得上传 prompt、消息正文、原始 session ID、原始 message ID、本地绝对路径或私有模型路由名。

## 隐私与授权模型

TokTrail Collector 将三类权限分开：

1. **本地读取授权**：计划采集可以读取哪些本地路径。
2. **上传 consent**：绑定设备是否可以向 TokTrail 兼容服务上传使用记录。
3. **公开榜单 consent**：投影后的使用数据是否可以公开展示。

关键约束：

- `scan`、`preview`、`export` 不需要 TokTrail 账号。
- 计划采集只读取通过 `sources` 或 `service install --grant` 显式启用的路径。
- 没有任何 source grant 时，计划任务不扫描也不联网。
- `sync` 上传前会先调用 `GET /v1/devices/self`，并把当次快照中的 consent revision 随 ingest 请求提交。
- 未知 Token 计数保持未知，不会被静默转成 0。
- 私有模型路由名会折叠为 `unknown`，除非命中公开 allowlist。

## 仓库结构

```text
cmd/toktrail/            主 Collector CLI
cmd/toktrail-installer/  用户安装与验签入口
cmd/toktrail-release/    维护者 CLI 与旧命令兼容入口
scripts/release.sh      本地与 CI 共用的构建编排
.github/workflows/      测试与 tag 触发的草稿发布
tools/release/          归档组装、签名、bootstrap 模板和发行 E2E
internal/source/
  adapter/              共享记录契约、校验、Token 与隐私辅助逻辑
  jsonl/                共享 JSONL 文件发现、逐行读取和解码
  usagejson/            usage-json parser 与测试
  codexjsonl/            Codex parser、重放过滤与测试
  claudecodejsonl/       Claude Code parser、区间完整性与测试
  registry/             显式编译期 adapter 注册表
  pipeline/             扫描、预览、导出与批次拆分
internal/local/         本地状态、授权、outbox、commit、进度、锁与隔离区
internal/app/           应用工作流：采集、诊断与状态
internal/bind/          设备绑定
internal/connect/       一键连接编排流程
internal/syncclient/    服务端同步、ACK、重组与恢复
internal/distribution/  manifest、版本、签名、哈希与命名协议
internal/installer/     下载、验签、解包与安全替换二进制
internal/scheduler/     launchd、systemd user timer、Windows Task Scheduler 计划
docs/                   架构、发布与调度设计说明
```

依赖边界和新增数据源的方法见 [Architecture and adapter extension](docs/ARCHITECTURE.md)。

## 常用命令

- `toktrail version` 输出 Collector 版本。
- `toktrail help` 输出可用命令。
- `toktrail connect '<URL>'` 通过一键连接 URL/ticket 接入设备：获取服务端配置、绑定设备凭证、探测本地工具、配置授权、安装定时服务并执行首次采集。
- `toktrail scan` 离线汇总本地记录。
- `toktrail preview` 校验并预览本地记录。
- `toktrail export` 写出 server ingest batch，并登记到本地 outbox。
- `toktrail bind` 生成或复用本地 device secret，并用服务端一次性 ticket 绑定设备。
- `toktrail status` 检查当前绑定设备状态。
- `toktrail sync` 上传指定 batch 或最旧的 pending outbox batch。
- `toktrail sources` 管理计划采集的显式本地读取授权。
- `toktrail periodic` 从已启用 grants 采集，并有限度 drain pending batches。
- `toktrail service` 安装或卸载用户级计划任务。
- `toktrail privacy` 与 `toktrail doctor` 提供本地诊断。

## 本地开发快速开始

构建并查看 CLI：

```sh
go run ./cmd/toktrail version
go run ./cmd/toktrail help
```

扫描并导出 Codex 使用数据：

```sh
go run ./cmd/toktrail scan --source codex-jsonl --input ~/.codex/sessions
go run ./cmd/toktrail export --source codex-jsonl --input ~/.codex/sessions --out ./codex-batch.json --batch codex-demo-1
```

扫描并导出 Claude Code 使用数据：

```sh
go run ./cmd/toktrail scan --source claude-code-jsonl --input ~/.claude/projects
go run ./cmd/toktrail export --source claude-code-jsonl --input ~/.claude/projects --out ./claude-batch.json --batch claude-demo-1
```

绑定并同步到本地开发服务：

```sh
TOKTRAIL_BIND_TICKET=dev-ticket go run ./cmd/toktrail bind \
  --server http://127.0.0.1:3211 \
  --application leaderboard-local \
  --subject demo-user \
  --device-name my-mac

TOKTRAIL_BIND_TICKET=dev-ticket go run ./cmd/toktrail status \
  --server http://127.0.0.1:3211

go run ./cmd/toktrail sync --server http://127.0.0.1:3211
```

`TOKTRAIL_BIND_TICKET=dev-ticket` 只是本地占位符。生产部署应通过自己的账号和接入流程发放一次性 bind ticket。

## 计划采集

计划采集需要显式开启。本地启用 source grants 后再安装用户级任务：

```sh
go run ./cmd/toktrail service install \
  --grant codex-jsonl=$HOME/.codex/sessions \
  --grant claude-code-jsonl=$HOME/.claude/projects \
  --interval 30m
```

安装后的任务只运行：

```text
<toktrail binary> periodic --state-dir <absolute state dir>
```

调度器命令行上不会出现 server URL 或 secret。完整模型与平台说明见 [Scheduled collection](docs/SCHEDULING.md)。

## 签名发布与安装

GitHub Actions 和 `scripts/release.sh` 编排六平台构建；维护者工具负责归档与签名；独立安装器负责验签、SHA-256 校验和安全替换。Tag workflow 生成 GitHub Release 草稿供审阅。详见 [Release and installation](docs/RELEASE.md)。

生产运营方需要自行提供发布签名密钥、可信公钥分发渠道、下载托管，以及所需的平台公证或代码签名。

## 开发检查

提交前运行：

```sh
gofmt -l cmd internal tools
GOCACHE="$PWD/.gocache" GOPROXY=off go test ./...
GOCACHE="$PWD/.gocache" GOPROXY=off go vet ./...
```

较慢的 release E2E 测试需要显式开启：

```sh
GOCACHE="$PWD/.gocache" GOPROXY=off TOKTRAIL_RELEASE_E2E=1 go test ./tools/release/ -run '^TestEndToEndRelease$' -count=1 -v
```

## 贡献与安全

- 开发规范和 PR 检查见 [CONTRIBUTING.md](CONTRIBUTING.md)。
- 报告漏洞或隐私问题前请先阅读 [SECURITY.md](SECURITY.md)。

## 许可证

MIT。见 [LICENSE](LICENSE)。

# CPA 网络检测插件

CPA 网络检测插件是一个独立的 CLIProxyAPI / CPA 动态库插件，用来查看 CPA 服务端进程所在环境的网络状态，包括本机 IP、公共出口 IP、DNS 解析、OpenAI 连通性、IP 画像和出站路径对比。

页面检测执行位置是 CPA 服务端进程，不是浏览器所在电脑。无论 CPA 运行在主机、Docker 还是云容器中，页面显示的都是 CPA 实际运行环境看到的网络结果。

## 功能

- 显示 CPA 进程所在机器/容器的本机网卡 IP。
- 显示访问公网时使用的本地源地址。
- 通过多个公网接口检测出口 IP。
- 对比 `direct`（插件直连）与 `host`（CPA 宿主 HTTP 回调）两条出站路径。
- 检测 `chatgpt.com`、`api.openai.com`、`auth.openai.com`、`cdn.openai.com` 的 DNS 和 HTTP 连通性。
- 展示出口路径、DNS、OpenAI 连通性、IP 画像等事实检测结果，不做综合评分。
- 提供浏览器资源页和 JSON Management API。

## 插件商店安装

推荐通过 CPA 第三方插件商店安装。添加插件源：

```text
https://raw.githubusercontent.com/yuankc/cpa-network-diagnostics-plugin/main/registry.json
```

也可以直接写入 CPA `config.yaml`：

```yaml
plugins:
  enabled: true
  store-sources:
    - "https://raw.githubusercontent.com/yuankc/cpa-network-diagnostics-plugin/main/registry.json"
```

必须使用 `raw.githubusercontent.com` 地址，不能使用 GitHub 页面里的 `blob` 地址。`blob` 地址返回的是 HTML 页面，不是插件商店需要读取的 JSON。

添加插件源后，在插件商店中找到 `Network Diagnostics` 并安装。通过插件商店安装时，插件 ID 是：

```text
cpa-network-diagnostics-plugin
```

资源页路径：

```text
http://<服务器IP>:8317/v0/resource/plugins/cpa-network-diagnostics-plugin/dashboard
```

插件商店安装会写入动态库并启用 `plugins.configs.cpa-network-diagnostics-plugin.enabled`，但不会强行打开全局 `plugins.enabled`。如果插件列表里显示未生效，请先确认全局插件开关已经开启。

如果刚从手动安装的 `diagnostics` 版本切换到商店安装版本，建议重启 CPA 服务一次，让插件目录扫描、配置和资源路由重新加载干净。

## 使用说明

页面右上角可以切换检测网络：

- `本机网络`：插件进程直接访问外部网络，反映 CPA 运行环境的裸网络。
- `CPA 代理`：通过 CPA 宿主 HTTP 回调访问外部网络，会应用 CPA 全局 `proxy-url` 等宿主出站策略。

默认检测模式是 `本机网络`。如果要验证 CPA 配置的 socks5/http 代理是否生效，请切换到 `CPA 代理`。

商店安装后的 JSON 资源接口：

```bash
curl "http://<服务器IP>:8317/v0/resource/plugins/cpa-network-diagnostics-plugin/status?network=host"
```

资源接口用于页面渐进加载，返回公开脱敏视图：会隐藏 hostname、PID、本机网卡 IP、出站本地源地址、代理变量值、Cloudflare 返回的出口 IP 和 compliance 原始响应体。需要完整诊断明细时使用兼容保留的 Management API：

```bash
curl -H "Authorization: Bearer <management-key>" \
  "http://<服务器IP>:8317/v0/management/diagnostics/status?network=host"
```

## 本地手动安装

如果不使用插件商店，也可以手动构建并把动态库放入 CPA 插件目录。手动安装时动态库文件名是 `diagnostics`，因此插件 ID 是 `diagnostics`。

Windows 本地示例：

```powershell
.\scripts\build.ps1

# 将 dist\windows\amd64\diagnostics.dll 复制到 CPA 的 plugins\windows\amd64 目录
```

CPA `config.yaml`：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    diagnostics:
      enabled: true
      priority: 10
```

手动安装后的资源页路径：

```text
http://127.0.0.1:8317/v0/resource/plugins/diagnostics/dashboard
```

手动安装后的 JSON API：

```bash
curl -H "Authorization: Bearer <management-key>" \
  http://127.0.0.1:8317/v0/management/diagnostics/status
```

## Docker 手动测试

Docker 容器里通常是 Linux，所以要放 Linux `.so`，不能把 Windows `.dll` 塞进去。

目录示例：

```text
./plugins/linux/amd64/diagnostics.so
```

`docker-compose.yml` 示例：

```yaml
services:
  cpa:
    image: eceasy/cli-proxy-api:latest
    volumes:
      - ./config.yaml:/app/config.yaml
      - ./plugins:/app/plugins
    ports:
      - "8317:8317"
```

容器内配置：

```yaml
plugins:
  enabled: true
  dir: "/app/plugins"
  configs:
    diagnostics:
      enabled: true
      priority: 10
```

重启容器后访问：

```text
http://<服务器IP>:8317/v0/resource/plugins/diagnostics/dashboard
```

## 构建要求

必须安装：

- Go，版本遵循 `go.mod`
- CGO 可用的 C 编译器
- 打包时需要 `zip`

Windows 本地如果看到：

```text
cgo: C compiler "gcc" not found
```

说明还没装 MinGW / MSYS2，或者 `gcc.exe` 没进 `PATH`。这是 Go `-buildmode=c-shared` 动态库插件的硬要求，不是插件代码问题。

## 本地构建

Windows PowerShell：

```powershell
.\scripts\build.ps1
```

Linux / macOS：

```bash
bash scripts/build.sh
```

也可以用 Makefile：

```bash
make fmt
make vet
make test
make build
make package
make checksums
```

构建产物：

```text
dist/<goos>/<goarch>/diagnostics.dll
dist/<goos>/<goarch>/diagnostics.so
dist/<goos>/<goarch>/diagnostics.dylib
```

## 发布打包

Windows：

```powershell
.\scripts\package.ps1
```

Linux / macOS：

```bash
bash scripts/package.sh
```

输出示例：

```text
release/cpa-network-diagnostics-plugin_0.1.13_windows_amd64.zip
release/cpa-network-diagnostics-plugin_0.1.13_linux_amd64.zip
```

本插件的商店发布格式遵循 CPA 官方插件商店规范：

- `registry.json` 使用 `schema_version: 1`。
- `id`、`name`、`description`、`author`、`repository` 为必填字段。
- `repository` 必须是 `https://github.com/{owner}/{repo}`。
- `version` 只是展示兜底值，真实安装版本来自 GitHub latest release tag。
- release 需要提供当前平台对应的 zip 资产和 `checksums.txt`。

release 资产命名格式：

```text
cpa-network-diagnostics-plugin_<version>_<goos>_<goarch>.zip
checksums.txt
```

zip 根目录直接包含目标平台动态库，例如：

```text
cpa-network-diagnostics-plugin.so
cpa-network-diagnostics-plugin.dll
cpa-network-diagnostics-plugin.dylib
```

仓库已包含 GitHub Actions release workflow。推送 tag 后会构建多平台 zip、`.sha256` 和 `checksums.txt`：

```bash
git tag v0.1.13
git push origin v0.1.13
```

## 插件规范

本插件是 CPA 原生动态库插件：

- 导出 `cliproxy_plugin_init`、`cliproxyPluginCall`、`cliproxyPluginFree`、`cliproxyPluginShutdown`。
- 使用 `github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi` 的 ABI 版本、RPC 方法名和 envelope。
- 使用 `github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi` 的 metadata、config field、Management API route/resource/response 类型。
- 只声明 `management_api` 能力，不接管模型执行、调度、认证或请求转换。
- HTTP 类检测支持两种模式：`direct` 使用插件自身直连 HTTP；`host` 通过宿主 `host.http.do` 回调执行。

## 本地 CPA SDK 联调

`go.mod` 默认依赖 CPA 正式 module 版本，适合 GitHub Actions 和发布。如果你要临时对着旁边的 CPA 源码联调，可以执行：

```powershell
go mod edit -replace github.com/router-for-me/CLIProxyAPI/v7=../CLIProxyAPI
go mod tidy
```

发布前撤销本地 replace：

```powershell
go mod edit -dropreplace github.com/router-for-me/CLIProxyAPI/v7
go mod tidy
```

## 注意

- 这个插件读取的是 CPA 进程环境，不是你浏览器所在电脑的网络环境。
- 页面中的 `direct` 表示插件进程直连网络；`host` 表示通过 CPA 宿主 HTTP 回调发起请求，会应用 CPA 全局 `proxy-url` 等宿主出站策略。
- “代理环境”面板只展示进程环境变量（如 `HTTP_PROXY`、`ALL_PROXY`），不等同于 CPA `config.yaml` 中的 `proxy-url`；是否使用 CPA 代理请看“出站路径对比”面板。
- 公共 IP、DNS、OpenAI 连通性都依赖外部网络，网络被墙、代理异常或第三方 IP 查询接口限流时，检测会显示失败。
- 页面不做综合评分；IP 画像仅展示第三方接口返回的代理、VPN、机房、ASN、组织等字段。

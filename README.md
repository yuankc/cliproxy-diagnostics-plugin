# CPA 网络检测插件

CPA 网络检测插件是一个独立的 CLIProxyAPI / CPA 网络检测动态库插件。它不修改 CPA 主仓库代码，通过 CPA 原生插件机制注册浏览器资源页，用来查看 CPA 进程所在环境的本机 IP、公共出口 IP、DNS 解析、OpenAI 相关连通性和 IP 画像字段。

页面风格参考 `https://ip.net.coffee/gpt/` 的检测面板思路，但检测执行位置是 CPA 服务端进程。无论主机直装、Docker 还是云容器部署，页面显示的都是 CPA 实际运行环境看到的网络状态。

## 功能

- 显示 CPA 进程所在机器/容器的本机网卡 IP。
- 显示访问公网时使用的本地源地址。
- 通过多个公网接口检测出口 IP，并对比 `direct`（插件直连）与 `host`（CPA 宿主 HTTP 回调）两条出站路径。
- 页面默认使用 `direct` 本机/容器裸网络检测；如果 CPA 配置了代理，可以切换到 `host` / CPA 代理网络检测，使结果反映 CPA `proxy-url` 等宿主出站策略。
- 检测 `chatgpt.com`、`api.openai.com`、`auth.openai.com`、`cdn.openai.com` 的 DNS 和 HTTP 连通性。
- 展示出口路径、DNS、OpenAI 连通性、IP 画像等事实检测结果，不做综合评分。
- 提供浏览器资源页和 JSON Management API。

## 插件规范

本插件是 CPA 原生动态库插件：

- 导出 `cliproxy_plugin_init`、`cliproxyPluginCall`、`cliproxyPluginFree`、`cliproxyPluginShutdown`。
- 使用 `github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi` 的 ABI 版本、RPC 方法名和 envelope。
- 使用 `github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi` 的 metadata、config field、Management API route/resource/response 类型。
- 只声明 `management_api` 能力，不接管模型执行、调度、认证或请求转换。
- HTTP 类检测支持两种模式：`direct` 使用插件自身直连 HTTP；`host` 通过宿主 `host.http.do` 回调执行。

资源页：

```text
/v0/resource/plugins/diagnostics/dashboard
```

Management JSON API：

```text
/v0/management/diagnostics/status
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

动态库文件名必须保持 `diagnostics`，这样 CPA 识别到的插件 ID 就是 `diagnostics`，配置里也使用这个 ID。

## 安装到 CPA 本地测试

Windows 本地示例：

```powershell
cd cpa-network-diagnostics-plugin
.\scripts\build.ps1

# 将diagnostics.dll拷贝至\CLIProxyAPI\plugins\windows\amd64
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

启动 CPA：

```powershell
cd CLIProxyAPI
go run ./cmd/server --config config.yaml
```

打开检测页面：

```text
http://127.0.0.1:8317/v0/resource/plugins/diagnostics/dashboard
```

验证 JSON API：

```bash
curl -H "Authorization: Bearer <management-key>" \
  http://127.0.0.1:8317/v0/management/diagnostics/status
```

## Docker 测试

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
release/diagnostics_0.1.0_windows_amd64.zip
release/diagnostics_0.1.0_linux_amd64.zip
```

zip 根目录中只包含一个平台对应的动态库，例如 `diagnostics.so` 或 `diagnostics.dll`。

仓库已包含 GitHub Actions release workflow。推送 tag 后会构建多平台 zip、`.sha256` 和 `checksums.txt`：

```bash
git tag v0.1.0
git push origin v0.1.0
```

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
- 默认检测模式是 `direct`。要验证 CPA 配置的 socks5/http 代理是否生效，请在页面右上角切换到“CPA 代理”，或调用 JSON API 时添加 `?network=host`。
- “代理环境”面板只展示进程环境变量（如 `HTTP_PROXY`、`ALL_PROXY`），不等同于 CPA `config.yaml` 中的 `proxy-url`；是否使用 CPA 代理请看“出站路径对比”面板。
- 公共 IP、DNS、OpenAI 连通性都依赖外部网络，网络被墙、代理异常或第三方 IP 查询接口限流时，检测会显示失败。
- 页面不做综合评分；IP 画像仅展示第三方接口返回的代理、VPN、机房、ASN、组织等字段。后续可以扩展接入自定义画像 API、延迟目标、自定义检测域名等配置。

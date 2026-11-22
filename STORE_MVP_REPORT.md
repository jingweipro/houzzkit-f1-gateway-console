# F1 独立显式代理候选

本次交付为可运行的本地管理服务、容器构建定义和 HOS 安装候选目录。当前没有完成 ARM64 构建、原生 HDP 导入或 F1 实机验收。普通用户从商店安装的发布条件仍未满足。

## 用户路径与边界

1. 候选安装流程准备独占的 /var/data/f1-standalone-mvp 目录，权限 0700，UID/GID 10001，再启动 Bridge 容器。HOS 管理员需要能从可信的本机管理入口读取 pairing.txt。用 HTTPS 打开设备的 17680 端口，在输入随机管理密码前核对证书 SHA256。配对入口的普通用户可达性、HOS 启动按钮是否正确打开 HTTPS 有待实测。
2. 登录后提交个人 HTTPS 订阅。下载器仅允许合法域名的 443 端口，检查一次解析的所有地址，直连选定公网地址并按原域名验证 TLS，拒绝重定向，限制响应大小和读取时间。仅保存节点快照，更新时重新提交地址。页面和访问日志不输出 URL 或节点参数。
3. 本版本仅支持一个待启用快照、一个运行快照。只接受使用公网 IP 的 HTTP/SOCKS5 上游节点及界面说明的基本配置。域名节点、其他协议和扩展字段会使整次保存失败。用户提供的规则、监听器和控制器不进入核心配置。验证包括结构检查和本地 mihomo -t，未探测上游可用性。
4. 点击启用后，私有核心使用固定 MATCH 规则选用首个节点。客户端在可信局域网手动配置 F1 地址、17890、client 及页面中的独立随机代理密码。HTTP 和 SOCKS5 客户端认证均需可信链路。管理页面用会话 Cookie 与 CSRF，凭据和节点快照保存在私有卷内明文文件中。状态来自已提交快照、子进程状态及本地 SOCKS5 认证握手，链路出口可用性仍需客户端实测。
5. 替换运行快照需中断连接，启动或提交失败会尝试重启旧配置。重新启动旧核心也可能失败，此时页面会显示端口未就绪。可停用并撤销客户端手动代理设置。停用保留快照。此版未提供历史版本选择、自动刷新、节点切换、全屋 UDP 或 DHCP 管理。
6. 卸载清理脚本为空，升级、卸载均设计为保留 bind mount。重新安装应复用相同私有目录及身份；HOS 是否另行清理目录待验。容器内管理服务直接拥有单个子进程，不依赖原 Python host agent、系统 Docker API、主机网络、TUN 或额外 capability。

## 构建与复验

在仓库根目录、具备 Docker Buildx 的开发机执行下面的本地构建。Dockerfile 专用 ignore 文件只放入所需代码。第一阶段从 MetaCubeX 的版本镜像取 /mihomo，第二阶段使用 Python Alpine、CA 证书、OpenSSL 与 PyYAML。标签尚未经过供应链审查或解析固化。localhost 名称只供本地预载。

```sh
docker buildx build --platform linux/arm64 --load -f standalone/Dockerfile -t localhost/f1-standalone:arm64-dev .
docker run --rm --platform linux/arm64 --network none --cap-drop ALL \
  -v "$PWD/standalone/tests:/opt/qa/tests:ro" localhost/f1-standalone:arm64-dev \
  python -B -m unittest discover -s /opt/qa/tests -p test_core.py -v
```

第二条命令预期使用实际核心，通过两个客户端协议访问容器内模拟上游。必须看到测试实际执行。核心镜像来源及文件路径可对照 [Mihomo 上游 Dockerfile](https://github.com/MetaCubeX/mihomo/blob/v1.19.12/Dockerfile)。

Mac 上可用安装了 PyYAML 的 Python 3.13，仅在新建私有目录中运行管理页：

```sh
export F1_STANDALONE_DATA="$(mktemp -d)"
F1_STANDALONE_BIND=127.0.0.1 PYTHONPATH=app python3 standalone/ui.py
```

打开 https://127.0.0.1:17680 。保存和启用要求 PATH 中有 mihomo。

## 本地实测

|检查|结果|
|---|---|
|python tools/check_release.py|原 62 个测试通过，含订阅 DNS/TLS、拒绝重定向与错误脱敏|
|python -m unittest discover -s standalone/tests -v|5 项通过，1 项因没有 Mihomo 跳过|
|会话与配置集成|socketpair 上测试真实 HTTP 编解码、独立 TLS 配对登录、CSRF 拒绝、保存与显式启停、退出、重读数据、失败恢复。下载与核心切换使用替身|
|配置边界|拒绝私网节点和额外拨号字段，检查认证及固定规则|
|YAML 与资源|解析 manifest/flow，断言 Bridge、卷、端口、权限、脚本资源引用与图标存在；人工对照官方 Portainer 和 Node-RED 的目录、端口字段及 flow 步骤（本地上游 8525cd9）。尚无 HOS 导入器验证|
|静态检查|两个前端脚本 node --check 和两个 shell 脚本 bash -n 通过|

当前沙箱拒绝本地 TCP bind，TLS 登录实测使用私有套接字对。当前 Mac 环境缺少 Docker CLI 与 Mihomo，未生成镜像、digest 或签名，未实测客户端转发。工作区位于 feature/hos-selfcontained-mvp；创建 .git/index.lock 时系统拒绝写入，无法完成本地提交。

## 发布阻断项

- 在隔离 ARM64 构建机核实多阶段输入、许可证与依赖，固定经核验的输入 digest，生成 SBOM、扫描并记录最终 OCI manifest digest。完成真实核心离线双协议、未认证访问拒绝、停用断连和实际服务重启测试后再评估签名与分发。
- 在干净 HOS 测试机验证预载镜像发现、初始化顺序、卷权限、证书核验和配对入口、端口冲突、断电恢复、升级保留数据及卸载重装。验证真实 HDP 导出及另一台干净设备导入的资源完整性。
- 准备可维护的证书续期、凭据轮换与普通用户配对说明，评估受限节点格式是否覆盖目标订阅。经历候选验收后再进入商店审查。此轮仅修改本地工程。

## 商店宿主端口冲突修复（发布复核）

HOS 开发候选改为 host 17681 → container 17680（HTTPS 管理）及 host 17891 → container 17890（HTTP/SOCKS5 显式代理），以避免覆盖当前用户已运行的原型端口 17680/17890。此端口约定不保证在其他 F1 设备上空闲，正式安装仍需 HOS 端口占用检测和用户可配置宿主端口。仅更改候选 manifest、说明与离线断言；当前家庭 F1 未安装此版本。

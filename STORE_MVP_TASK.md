# HOUZZkit HOS 商店发布冲刺：独立可安装 MVP

用户明确要求尽快把 F1 Gateway Console 放到 HOUZZkit OS 应用商店，并在 GitHub 公开协作。代码已在 https://github.com/jingweipro/houzzkit-f1-gateway-console 公开，HOS 上游集成提案 https://github.com/yinbaiyuan/houzzkit-application-store/issues/6 已提交。

**重要边界：当前发布的是源码预览，不是真正可安装的 HOS 应用。你的任务是在当前独立 Mac 工程目录设计、实现和测试一套可真实安装的、安全、自包含的第一阶段 HOS 应用候选，但绝不能假称已经通过实机验收。**

## 交付目标
首先尝试提供一个完整的、非 privileged、Bridge 网络、没有 Docker socket、无需读取用户 F1 宿主配置的 ARM64 容器，它包括：
- 自己管理的 Mihomo 代理核心，支持显式 HTTP/SOCKS5 代理，**不默认接管家庭网络流量或修改 DHCP**。
- 中文管理页面，独立随机首次密码和会话/CSRF、实际代理/订阅服务状态。
- 可新增、验证、保存、启用、停用用户个人订阅，明确风险和回滚。新增只有显式操作才进入独立容器里的代理配置。节点参数仍不可泄露。
- 按照 HOS 官方目录模式配置独立 app manifest、初始化 flow_config.yml、resource/、图标、持久化卷。镜像先做开发候选配置，未验证镜像/签名不得写成可上架。
- 升级/卸载默认保留容器数据；在 HOS 数据卷上自持配置，不接触原有系统 docker/mihomo。
- 可用脱敏离线集成测试验证 UI 与内部代理配置的可靠性和功能路径。

## 重点
1. 先读 README.md、INSTALL-AND-RELEASE.md、hos-appstore/ 下模板，以及已有代码和测试，再选择最小风险架构。应优先新增 standalone/ 目录，不要破坏原来公开源码和 62 项回归。
2. 这是**独立应用**，不能继续把现有 Python host root agent 当成 Docker 容器里已经可用的功能。UI 与 agent 可以在同一受限容器，通过同 UID 私有 Unix socket 通信。不要使用 host Docker socket、privileged、host-network、TUN、CAP_NET_ADMIN 等越权能力。
3. 用 docker/OCI 多阶段构建针对 linux/arm64 的镜像，来源清晰，镜像固定 digest 的验证应在实际构建后进行。不得编造未构建镜像的 digest 或发布仓库。可以编写 GitHub Actions 发布候选工作流，但默认不要使其真的推送未经验收的镜像。
4. 订阅下载要有固定域名 DNS、TLS 校验及 SSRF 防御；不能在日志/状态里暴露 URL token。使用有针对性的离线测试。
5. 如某项功能无法安全完成，请界面明确标记「未开放」而不是假成功。必须区分可用的显式 HTTP/SOCKS5 代理和未实现的全屋 UDP 透明代理。
6. HOS 官方项目结构示例在公开上游仓库 yinbaiyuan/houzzkit-application-store 的 Portainer、Node-RED 等目录。必要资源必须在源码中实际存在，不能依赖 HOS 导出时临时路径。
7. 不查询或复制家庭 F1 密码、订阅、真实 IP、生产数据库；不运行 ssh/远程控制，不发布 GitHub，不向上游创建 PR，不部署任何 F1 服务。只在当前 Mac 工程本地文件中编码测试。

## 验收输出
- 保留原 62 项测试全部通过，增加独立自包含组件的离线测试。
- node --check 前端脚本，bash -n shell 脚本，检查 YAML schema 与 HOS manifest 是否和官方项目示例结构相近。
- 写一份 STORE_MVP_REPORT.md，包括已实现功能、真实测试、哪些只是模板、实际 ARM64 构建/上架还缺哪些环节。
- 在本地 feature/hos-selfcontained-mvp 分支提交代码，不要推送。
- 如实现不完，先给出架构与可运行最小版本，明确阻断项，严禁伪造任何成功。

优先级最高的是让 **普通 F1 用户真正能从 HOS 安装后，用 Web 页面管理自己容器内的显式代理订阅**；同家庭现有透明网关的可选集成必须后置，并单独授权验收。
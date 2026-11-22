# 公共发布隐私检查门禁

本项目在公开源码、发布容器镜像及提交 HOS 应用商店前，都应先完成隐私核验。

## 已接入的检查

- GitHub Actions **Public release privacy gate**：在 push、Pull Request、release 事件和手动运行时检查源码与可达 Git 历史；阻止高置信度密钥、令牌、私钥、敏感文件、个人本地路径。日志只输出文件位置和检测规则，不打印秘密。
- **Offline source tests**：敏感信息检查在常规测试前执行；失败会使工作流整体失败。
- **ARM64 standalone HOS candidate smoke**：构建前检查源码及 HOS 资源目录，构建后检查 Docker 镜像层和嵌入配置。
- **Publish ARM64 preview image**：在登录 GHCR 和推送镜像之前执行源码、历史、HOS 资源及镜像层扫描；任一检查失败都会停止后续推送。
- 自动测试构造模拟 GitHub Token、历史中曾提交后删除的密钥、带私有元数据的 PNG，以及带测试密钥的 OCI 镜像层，确保能拦截并避免把匹配值输出到 CI。

### 本地运行

在仓库根目录执行：

    python3 tools/publication_guard.py --history --extra-dir hos-appstore

有独立商店候选时额外执行：

    python3 tools/publication_guard.py --extra-dir standalone/store

已有测试 Docker 镜像时先在隔离测试机执行 docker save，再扫描：

    python3 tools/publication_guard.py --image-tar /path/to/test-image.tar

如要向上游提交 HDP 或 ZIP 包：

    python3 tools/publication_guard.py --package-zip /path/to/proposed-package.hdp

**不要将原厂签发的含 Token HDP、个人订阅或真实凭据放入公开仓库或聊天。** 对源代码仓库之外的上游 PR，发布者还必须在提交前独立检查待提交的 HOS 应用目录。

## 边界和故障处置

自动规则检测不保证找出所有私密信息：低熵密码、某些自定义协议、未识别的二进制和此前公开的 Git 历史仍需额外检查。公开 release 事件发生在 GitHub 已发布之后；它属于事后报警，**不能代替前置验收**。手动使用 GitHub API 或直接推送未经过以上工作流的镜像也可能绕过这些限制。因此发布镜像只应经受检发布工作流；正式发布前还应在 GitHub 的仓库规则里启用必需检查。

上游应用商店仓库不由本仓库管理，必须在提交 PR 前单独审查并等待维护者审批。自动检查也不会消除旧 Git 提交中的信息。如果发现实际泄露，首先吊销、轮换凭据，再根据情况处理提交历史、镜像层和使用者通知。

通过这些隐私门禁仅表示未检测出规则覆盖的敏感信息，**不意味着 ARM64/HDP/商店安装已经验收通过**。

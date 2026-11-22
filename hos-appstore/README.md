# HOS Application Store source candidate — DO NOT INSTALL YET

这是原生 HOUZZkit 应用商店源文件的候选模板，不是原厂签发的 HDP 安装包。
现有商店 v0.1.6 项目已验证本机 HOS GUI 的安装/卸载/重装、但 HDP 导出丢失 resource 资源文件，不具备跨设备原生分发验收。
新 UI v0.2.0 已通过用户 F1 systemd 常驻上线，商店模板仍缺发布并审计的 arm64 镜像、安全本地 agent 的用户安装向导、HOS 完整资源导出/导入，以及另一台空白 F1 实机验证。

不要把源码ZIP改名.hdp、不要仿造原厂token、不要打包私人订阅或设备登录信息。
参考 https://yinbaiyuan.github.io/developers/houzzkit_docker_package_make.html

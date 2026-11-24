# 宝塔面板 - SSH 登录日志与安全审计插件 (`ssh_log`)

一款专为宝塔 Linux 面板（aaPanel / BT-Panel）打造的轻量级 **SSH 安全审计与登录日志查看插件**。

支持登录成功/失败状态实时监控、爆破攻击统计、一键联动系统防火墙黑名单拦截、在线终端会话管理及 CSV 审计日志导出。

---

## 核心特性

- **实时数据看板**：统计今日成功登录次数、今日拦截/爆破次数、攻击源 IP 数量以及当前在线会话数。
- **登录日志明细**：
  - 完整记录登录时间、状态（成功/失败/非法用户探测）、用户名、认证方式（公钥/密码）、来源 IP、运营商归属地及端口。
  - 支持多状态筛选（全部 / 成功 / 密码错误 / 非法用户 / 全部失败）与日期过滤（全部 / 今天 / 昨天）。
  - 支持按 IP 或 用户名实时关键字检索。
  - 支持 10s / 30s / 60s 自动轮询刷新及导出标准 CSV 表格文件。
- **爆破拦截 TOP 榜**：
  - 自动分析海量历史认证日志，统计并排序尝试攻击次数最多的 TOP 20 恶意 IP。
  - 展示高频探测账号、最近攻击时间及防火墙拦截状态。
  - 支持「批量封锁高危 IP (>=10次)」一键加入防火墙黑名单。
- **在线会话监控与踢出**：
  - 实时监控当前连接到本机的终端会话（TTY、来源 IP、归属地、登录时间、空闲时长、当前进程）。
  - 支持管理员一键强制断开/踢出指定终端连接。
- **安全配置与基线检查**：
  - 动态检测 SSH 运行状态、监听端口、是否允许 Root 登录及密码认证（自动兼容 `/etc/ssh/sshd_config.d/*.conf` 动态子配置）。
  - 智能防护管理员自身访问 IP 与内网专用网段，杜绝误封锁风险。
- **自适应 16:9 界面**：
  - 弹窗自适应 16:9 宽屏黄金比例，表格布局舒展，全无多余 Emoji 杂乱干扰，风格干净商务。

---

## 插件目录结构

```
ssh_log/
├── info.json           # 插件元信息（名称、版本、作者等）
├── ssh_log_main.py     # 后端核心业务逻辑（日志解析、IP 定位、防火墙对接）
├── index.html          # 前端交互界面（自适应宽屏纯净 UI）
├── install.sh          # 插件安装与卸载脚本
├── icon.png            # 插件图标
├── .gitignore          # Git 忽略文件（忽略运行时缓存与字节码）
└── README.md           # 项目说明文档
```

---

## 安装与部署

### 方式一：Git 一键安装（推荐）

通过 SSH 终端进入服务器，执行以下命令：

```bash
# 1. 克隆代码到宝塔插件目录
git clone https://github.com/Jayin/btpanel-ssh_log.git /www/server/panel/plugin/ssh_log

# 2. 执行安装初始化脚本
bash /www/server/panel/plugin/ssh_log/install.sh install
```

执行完成后，在宝塔面板的「软件商店」或快捷软件列表中即可直接看到并打开使用。

---

### 方式二：手动离线部署

1. 下载本仓库源码压缩包。
2. 将解压后的文件夹重命名为 `ssh_log`。
3. 上传到服务器的 `/www/server/panel/plugin/ssh_log` 目录。
4. 执行 `bash /www/server/panel/plugin/ssh_log/install.sh install`。

---

## 卸载插件

```bash
bash /www/server/panel/plugin/ssh_log/install.sh uninstall
```

---

## 系统兼容性

- **支持面板**：宝塔 Linux 面板 7.x / 8.x / 9.x，aaPanel 6.x / 7.x
- **支持操作系统**：
  - Ubuntu 18.04 / 20.04 / 22.04 / 24.04
  - Debian 10 / 11 / 12
  - CentOS 7 / 8 / Stream
  - AlmaLinux / RockyLinux 8 / 9
  - TencentOS / Alibaba Cloud Linux / OpenEuler

---

## 开源协议

本项目基于 [MIT License](LICENSE) 开源协议发布。

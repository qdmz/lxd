# LXD Web Manager

LXD Web Manager 是一个基于 Web 的管理工具，专为简化 LXD（Linux 容器）的管理和操作而设计。它提供了一个直观的用户界面，让用户能够轻松地管理容器、镜像、网络和存储等资源。

## 功能特性

- 容器管理：创建、启动、停止和删除容器。
- 镜像管理：管理本地和远程镜像。
- 网络管理：配置和管理容器网络。
- 存储管理：管理存储卷和快照。
- 用户权限：支持多用户权限管理。

## 安装指南

1. 克隆仓库：
   ```bash
   git clone https://gitee.com/qdmz/lxd_webmanager.git
   ```
2. 安装依赖：
   ```bash
   cd lxd_webmanager
   pip install -r requirements.txt
   ```
3. 配置数据库和 LXD 连接信息：
   - 修改 `config.py` 文件中的数据库和 LXD 配置。

4. 初始化数据库：
   ```bash
   python manage.py db init
   python manage.py db migrate
   python manage.py db upgrade
   ```

5. 启动应用：
   ```bash
   python app.py
   ```

## 使用说明

- 访问 `http://localhost:5000` 进入 Web 管理界面。
- 默认管理员账户和密码可在 `config.py` 中找到或进行修改。

## 贡献指南

欢迎贡献代码！请遵循以下步骤：

1. Fork 仓库。
2. 创建新分支。
3. 提交您的更改。
4. 创建 Pull Request。

## 许可证

本项目采用 MIT 许可证。详细信息请参阅 [LICENSE](LICENSE) 文件。
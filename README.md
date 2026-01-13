# Pear 自动登录服务

每4小时自动登录刷新 Cookie 和 `__pk`，提供 HTTP API 访问，并同步到 GitHub。

## 功能

- 自动登录 Pear 账号 (SRP-6a 协议)
- 每4小时自动刷新 Cookie
- Web 控制面板
- 自动同步到 GitHub 仓库
- Cookie 有效性测试

## 快速部署

```bash
# 1. 安装依赖
npm install

# 2. 配置账号
cp config.json.example config.json
# 编辑 config.json 填入账号信息

# 3. 启动服务 (默认端口 3000)
npm start

# 自定义端口
PORT=8080 npm start
```

## 配置说明

`config.json`:
```json
{
  "username": "手机号",
  "password": "密码",
  "githubToken": "GitHub Personal Access Token",
  "githubRepo": "用户名/仓库名",
  "githubFile": "文件路径"
}
```

GitHub Token 需要 `repo` 权限，在 https://github.com/settings/tokens 创建。

## HTTP API

| 接口 | 说明 |
|------|------|
| `GET /` | Web 控制面板 |
| `GET /api` | 获取完整数据 (JSON) |
| `GET /cookie` | 只获取 cookie |
| `GET /pk` | 只获取 pk (loginenc) |
| `GET /test` | 测试 Cookie 有效性 |
| `GET /refresh` | 手动触发刷新 |
| `GET /health` | 健康检查 |

## 使用 PM2 守护进程

```bash
npm install -g pm2
pm2 start server.js --name pear-login
pm2 startup
pm2 save
```

## Cloudflare Worker

`worker.js` 是配套的 Cloudflare Worker 脚本，从 GitHub 获取 Cookie 数据进行视频解析。

部署到 Cloudflare Workers 后，调用方式：
```
GET /?id=movieId&sign=xxx&t=timestamp
```

## 环境要求

- Node.js >= 18.0.0

## 注意

`worker.js` 为 Cloudflare Worker 脚本，出于安全考虑，未包含在仓库中。

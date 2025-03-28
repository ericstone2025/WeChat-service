# 微信智能客服系统

这是一个基于 Flask 的微信智能客服系统，集成了 Dify API 和企业微信 API，可以自动回复用户消息。

## 功能特点

- 接收微信用户消息
- 调用 Dify API 获取智能回复
- 通过企业微信 API 发送回复

## 安装步骤

1. 克隆项目到本地
2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
3. 配置环境变量：
   - 复制 `.env.example` 文件为 `.env`
   - 填写以下配置信息：
     - WECHAT_CORP_ID：企业微信的企业ID
     - WECHAT_AGENT_ID：企业微信的应用ID
     - WECHAT_SECRET：企业微信的应用密钥
     - DIFY_API_KEY：Dify API 的访问密钥
     - DIFY_API_URL：Dify API 的接口地址

## 运行项目

```bash
python app.py
```

服务将在 http://localhost:5000 启动，webhook 地址为 http://localhost:5000/webhook

## 配置说明

1. 企业微信配置：
   - 登录企业微信管理后台
   - 创建应用并获取相关配置信息
   - 配置接收消息的服务器地址

2. Dify API 配置：
   - 登录 Dify 平台
   - 创建应用并获取 API 密钥
   - 配置 API 接口地址

## 注意事项

- 请确保服务器能够被企业微信服务器访问
- 建议在生产环境中使用 HTTPS
- 请妥善保管 API 密钥等敏感信息 
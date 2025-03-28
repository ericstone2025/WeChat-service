import os
import json
import requests
from flask import Flask, request, abort
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import base64
import hashlib
import hmac
import time

# 加载环境变量
load_dotenv()

app = Flask(__name__)

# 配置信息
WECHAT_CORP_ID = os.getenv('WECHAT_CORP_ID')
WECHAT_AGENT_ID = os.getenv('WECHAT_AGENT_ID')
WECHAT_SECRET = os.getenv('WECHAT_SECRET')
DIFY_API_KEY = os.getenv('DIFY_API_KEY')
DIFY_API_URL = os.getenv('DIFY_API_URL')

def get_access_token():
    """获取企业微信访问令牌"""
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={WECHAT_CORP_ID}&corpsecret={WECHAT_SECRET}"
    response = requests.get(url)
    return response.json().get('access_token')

def send_message(access_token, user_id, content):
    """发送消息到企业微信"""
    url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={access_token}"
    data = {
        "touser": user_id,
        "msgtype": "text",
        "agentid": WECHAT_AGENT_ID,
        "text": {
            "content": content
        }
    }
    response = requests.post(url, json=data)
    return response.json()

def get_dify_response(user_id, content):
    """调用 Dify API 获取回复"""
    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "user": user_id,
        "query": content
    }
    response = requests.post(DIFY_API_URL, headers=headers, json=data)
    return response.json().get('answer', '抱歉，我现在无法回答。')

@app.route('/webhook', methods=['POST'])
def webhook():
    """处理微信消息的webhook"""
    # 获取请求数据
    data = request.get_json()
    
    # 验证消息来源（这里需要根据实际情况实现）
    
    # 提取消息内容
    try:
        user_id = data.get('FromUserName')
        content = data.get('Content')
        
        if not user_id or not content:
            return 'Invalid message format', 400
            
        # 获取 Dify 回复
        dify_response = get_dify_response(user_id, content)
        
        # 获取访问令牌
        access_token = get_access_token()
        
        # 发送回复
        send_message(access_token, user_id, dify_response)
        
        return 'Success', 200
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return 'Internal Server Error', 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True) 
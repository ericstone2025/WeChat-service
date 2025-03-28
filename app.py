import os
import json
import requests
import xmltodict
import hashlib
from flask import Flask, request, abort, make_response
from dotenv import load_dotenv

# 加载 .env 环境变量
load_dotenv()

app = Flask(__name__)

# 企业微信配置
WECHAT_TOKEN = os.getenv("WECHAT_TOKEN")  # 微信后台配置的 token
WECHAT_CORP_ID = os.getenv("WECHAT_CORP_ID")
WECHAT_AGENT_ID = os.getenv("WECHAT_AGENT_ID")
WECHAT_SECRET = os.getenv("WECHAT_SECRET")

# Dify 配置
DIFY_API_KEY = os.getenv("DIFY_API_KEY")
DIFY_API_URL = os.getenv("DIFY_API_URL")  # 示例: https://api.dify.ai/v1/chat-messages

# 生成签名用于校验消息来源
def check_signature(signature, timestamp, nonce):
    tmp_list = sorted([WECHAT_TOKEN, timestamp, nonce])
    tmp_str = ''.join(tmp_list)
    hashcode = hashlib.sha1(tmp_str.encode('utf-8')).hexdigest()
    return hashcode == signature

# 获取 access_token
def get_access_token():
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={WECHAT_CORP_ID}&corpsecret={WECHAT_SECRET}"
    response = requests.get(url)
    return response.json().get('access_token')

# 向用户发送消息
def send_message(access_token, user_id, content):
    url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={access_token}"
    data = {
        "touser": user_id,
        "msgtype": "text",
        "agentid": WECHAT_AGENT_ID,
        "text": {
            "content": content
        },
        "safe": 0
    }
    response = requests.post(url, json=data)
    return response.json()

# 调用 Dify API 获取回答
def get_dify_response(user_id, content):
    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "inputs": {"question": content},
        "response_mode": "blocking",
        "user": user_id
    }
    response = requests.post(DIFY_API_URL, headers=headers, json=payload)
    print("Dify返回：", response.text)
    return response.json().get('answer', '抱歉，我现在无法回答。')

# 接收微信消息
@app.route('/webhook', methods=['GET', 'POST'])
def wechat():
    # 校验 GET 请求签名（用于微信验证接口时）
    if request.method == 'GET':
        signature = request.args.get('signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')
        echostr = request.args.get('echostr')
        if check_signature(signature, timestamp, nonce):
            return echostr
        else:
            return 'Invalid signature', 403

    # 处理 POST 请求（消息事件）
    try:
        xml_data = request.data
        msg = xmltodict.parse(xml_data)['xml']
        msg_type = msg.get('MsgType')
        user_id = msg.get('FromUserName')

        if msg_type == 'text':
            content = msg.get('Content')
            print(f"[用户] {user_id}：{content}")

            # 调用 Dify
            dify_reply = get_dify_response(user_id, content)

            # 发送回微信
            token = get_access_token()
            send_message(token, user_id, dify_reply)

        else:
            print(f"[非文本消息类型] {msg_type}，未处理。")

        return make_response('success')
    except Exception as e:
        print(f"异常：{e}")
        return make_response('error', 500)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
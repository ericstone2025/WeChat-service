import os
import json
import requests
import xmltodict
import hashlib
import base64
import random
import string
import time
import struct
from flask import Flask, request, abort, make_response
from dotenv import load_dotenv
from Crypto.Cipher import AES

# 加载 .env 环境变量
load_dotenv()

app = Flask(__name__)

# 企业微信配置
WECHAT_TOKEN = os.getenv("WECHAT_TOKEN")  # 微信后台配置的 token
WECHAT_CORP_ID = os.getenv("WECHAT_CORP_ID")
WECHAT_AGENT_ID = os.getenv("WECHAT_AGENT_ID")
WECHAT_SECRET = os.getenv("WECHAT_SECRET")
WECHAT_ENCODING_AES_KEY = os.getenv("WECHAT_ENCODING_AES_KEY")  # 企业微信后台配置的 EncodingAESKey

# Dify 配置
DIFY_API_KEY = os.getenv("DIFY_API_KEY")
DIFY_API_URL = os.getenv("DIFY_API_URL")  # 示例: https://api.dify.ai/v1/chat-messages

# 消息加解密相关函数
class PKCS7Encoder():
    block_size = 32

    def encode(self, text):
        length = len(text)
        amount_to_pad = self.block_size - (length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def decode(self, decrypted):
        pad = ord(decrypted[-1])
        if pad < 1 or pad > self.block_size:
            pad = 0
        return decrypted[:-pad]

def generate_random_str(length=16):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def calculate_signature(token, timestamp, nonce, encrypt=None):
    params = [token, timestamp, nonce]
    if encrypt:
        params.append(encrypt)
    params.sort()
    signature = hashlib.sha1(''.join(params).encode()).hexdigest()
    return signature

def decrypt_message(encrypt_text):
    aes_key = base64.b64decode(WECHAT_ENCODING_AES_KEY + "=")
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_key[:16])
    decrypted_text = cipher.decrypt(base64.b64decode(encrypt_text))
    
    try:
        pad = decrypted_text[-1]
        content = decrypted_text[20:-pad]
        xml_len = struct.unpack('!I', content[:4])[0]
        xml_content = content[4:xml_len+4].decode('utf-8')
        corp_id = content[xml_len+4:].decode('utf-8')
        
        return xml_content
    except Exception as e:
        print(f"解密失败: {e}")
        return None

def encrypt_message(reply_msg, nonce, timestamp):
    pad_msg = PKCS7Encoder().encode(reply_msg)
    random_str = generate_random_str().encode('utf-8')
    msg_len = struct.pack('!I', len(reply_msg.encode('utf-8')))
    corp_id = WECHAT_CORP_ID.encode('utf-8')
    
    content = random_str + msg_len + reply_msg.encode('utf-8') + corp_id
    
    # 使用AES-CBC加密
    aes_key = base64.b64decode(WECHAT_ENCODING_AES_KEY + "=")
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_key[:16])
    encrypt_text = base64.b64encode(cipher.encrypt(PKCS7Encoder().encode(content.decode('utf-8')).encode('utf-8')))
    
    signature = calculate_signature(WECHAT_TOKEN, timestamp, nonce, encrypt_text)
    
    result = {
        'Encrypt': encrypt_text,
        'MsgSignature': signature,
        'TimeStamp': timestamp,
        'Nonce': nonce
    }
    return result

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
    # 处理 GET 请求（用于企业微信验证接口）
    if request.method == 'GET':
        # 获取参数
        msg_signature = request.args.get('msg_signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')
        echostr = request.args.get('echostr')
        
        print(f"收到验证请求: msg_signature={msg_signature}, timestamp={timestamp}, nonce={nonce}, echostr={echostr}")
        
        # 验证签名
        temp_sign = calculate_signature(WECHAT_TOKEN, timestamp, nonce, echostr)
        if temp_sign != msg_signature:
            print("签名验证失败")
            return 'Invalid signature', 403
        
        # 解密 echostr
        decrypted_echostr = decrypt_message(echostr)
        if not decrypted_echostr:
            print("解密 echostr 失败")
            return 'Decrypt failed', 403
        
        print(f"验证成功，返回: {decrypted_echostr}")
        return decrypted_echostr

    # 处理 POST 请求（消息事件）
    try:
        # 获取参数
        msg_signature = request.args.get('msg_signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')
        
        # 获取加密的 XML 数据
        xml_data = request.data
        xml_dict = xmltodict.parse(xml_data)
        encrypt = xml_dict['xml']['Encrypt']
        
        # 验证签名
        temp_sign = calculate_signature(WECHAT_TOKEN, timestamp, nonce, encrypt)
        if temp_sign != msg_signature:
            print("签名验证失败")
            return 'Invalid signature', 403
        
        # 解密消息
        decrypted_xml = decrypt_message(encrypt)
        if not decrypted_xml:
            print("解密消息失败")
            return 'Decrypt failed', 403
        
        # 解析解密后的 XML
        msg = xmltodict.parse(decrypted_xml)['xml']
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
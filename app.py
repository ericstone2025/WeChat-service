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
import logging
from flask import Flask, request, abort, make_response
from dotenv import load_dotenv
from Crypto.Cipher import AES
from functools import wraps
from datetime import datetime, timedelta

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('wechat-service')

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

# 缓存 access_token
access_token_cache = {
    'token': None,
    'expires_at': None
}

# 消息加解密相关函数
class PKCS7Encoder():
    """用于 PKCS7 填充的工具类"""
    block_size = 32

    def encode(self, text):
        """对文本进行 PKCS7 填充"""
        length = len(text)
        amount_to_pad = self.block_size - (length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def decode(self, decrypted):
        """对解密后的文本进行 PKCS7 去填充"""
        pad = ord(decrypted[-1])
        if pad < 1 or pad > self.block_size:
            pad = 0
        return decrypted[:-pad]

def generate_random_str(length=16):
    """生成指定长度的随机字符串"""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def calculate_signature(token, timestamp, nonce, encrypt=None):
    """计算签名"""
    params = [token, timestamp, nonce]
    if encrypt:
        params.append(encrypt)
    params.sort()
    signature = hashlib.sha1(''.join(params).encode()).hexdigest()
    return signature

def decrypt_message(encrypt_text):
    """解密企业微信消息"""
    try:
        aes_key = base64.b64decode(WECHAT_ENCODING_AES_KEY + "=")
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_key[:16])
        decrypted_text = cipher.decrypt(base64.b64decode(encrypt_text))
        
        pad = decrypted_text[-1]
        content = decrypted_text[20:-pad]
        xml_len = struct.unpack('!I', content[:4])[0]
        xml_content = content[4:xml_len+4].decode('utf-8')
        corp_id = content[xml_len+4:].decode('utf-8')
        
        # 验证 corp_id
        if corp_id != WECHAT_CORP_ID:
            logger.warning(f"解密后的 corp_id 不匹配: {corp_id}")
            return None
            
        return xml_content
    except Exception as e:
        logger.error(f"消息解密失败: {str(e)}")
        return None

def encrypt_message(reply_msg, nonce, timestamp):
    """加密回复消息"""
    try:
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
    except Exception as e:
        logger.error(f"消息加密失败: {str(e)}")
        return None

def api_request_with_retry(func):
    """API 请求重试装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                return func(*args, **kwargs)
            except requests.RequestException as e:
                retry_count += 1
                if retry_count >= max_retries:
                    logger.error(f"API 请求失败，已达到最大重试次数: {str(e)}")
                    raise
                logger.warning(f"API 请求失败，正在第 {retry_count} 次重试: {str(e)}")
                time.sleep(1)
    
    return wrapper

# 获取 access_token，带缓存机制
def get_access_token():
    """获取企业微信 access_token，带缓存机制"""
    global access_token_cache
    
    # 检查缓存是否有效
    now = datetime.now()
    if (access_token_cache['token'] and access_token_cache['expires_at'] 
            and now < access_token_cache['expires_at']):
        logger.debug("使用缓存的 access_token")
        return access_token_cache['token']
        
    # 缓存无效，重新获取
    logger.info("重新获取 access_token")
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={WECHAT_CORP_ID}&corpsecret={WECHAT_SECRET}"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # 如果请求不成功则抛出异常
        
        result = response.json()
        if result.get('errcode') == 0:
            token = result.get('access_token')
            expires_in = result.get('expires_in', 7200)
            
            # 更新缓存，提前5分钟过期
            access_token_cache['token'] = token
            access_token_cache['expires_at'] = now + timedelta(seconds=expires_in - 300)
            
            return token
        else:
            logger.error(f"获取 access_token 失败: {result}")
            return None
    except Exception as e:
        logger.error(f"获取 access_token 异常: {str(e)}")
        return None

@api_request_with_retry
def send_message(access_token, user_id, content):
    """向用户发送消息，带重试机制"""
    if not access_token:
        logger.error("发送消息失败: access_token 为空")
        return {'errcode': -1, 'errmsg': 'access_token is empty'}
        
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
    
    response = requests.post(url, json=data, timeout=10)
    result = response.json()
    
    if result.get('errcode') != 0:
        logger.warning(f"发送消息可能失败: {result}")
    else:
        logger.info(f"消息发送成功: {result.get('msgid')}")
        
    return result

@api_request_with_retry
def get_dify_response(user_id, content):
    """调用 Dify API 获取回答，带重试机制"""
    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "inputs": {"question": content},
        "response_mode": "blocking",
        "user": user_id
    }
    
    try:
        response = requests.post(DIFY_API_URL, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        logger.info(f"Dify 返回结果: {result}")
        
        # 返回回答，如果没有则返回默认消息
        return result.get('answer', '抱歉，我现在无法回答您的问题。')
    except Exception as e:
        logger.error(f"调用 Dify API 失败: {str(e)}")
        return "抱歉，服务暂时不可用，请稍后再试。"

def verify_signature_middleware():
    """验证消息签名的中间件函数"""
    msg_signature = request.args.get('msg_signature')
    timestamp = request.args.get('timestamp')
    nonce = request.args.get('nonce')
    
    if not all([msg_signature, timestamp, nonce]):
        logger.warning("签名参数不完整")
        return False, 'Incomplete signature parameters', 400
    
    return True, None, 200

# 接收微信消息
@app.route('/webhook', methods=['GET', 'POST'])
def wechat():
    """处理企业微信消息的主入口"""
    # 验证基本参数
    success, error_msg, status_code = verify_signature_middleware()
    if not success:
        return error_msg, status_code
        
    # 处理 GET 请求（用于企业微信验证接口）
    if request.method == 'GET':
        # 获取参数
        msg_signature = request.args.get('msg_signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')
        echostr = request.args.get('echostr')
        
        logger.info(f"收到验证请求: msg_signature={msg_signature}, timestamp={timestamp}, nonce={nonce}")
        
        # 验证签名
        temp_sign = calculate_signature(WECHAT_TOKEN, timestamp, nonce, echostr)
        if temp_sign != msg_signature:
            logger.warning(f"签名验证失败: {temp_sign} != {msg_signature}")
            return 'Invalid signature', 403
        
        # 解密 echostr
        decrypted_echostr = decrypt_message(echostr)
        if not decrypted_echostr:
            logger.error("解密 echostr 失败")
            return 'Decrypt failed', 403
        
        logger.info(f"验证成功，返回解密后的 echostr")
        return decrypted_echostr

    # 处理 POST 请求（消息事件）
    try:
        # 获取参数
        msg_signature = request.args.get('msg_signature')
        timestamp = request.args.get('timestamp')
        nonce = request.args.get('nonce')
        
        # 获取加密的 XML 数据
        xml_data = request.data
        if not xml_data:
            logger.warning("请求体为空")
            return 'Empty request body', 400
            
        # 解析 XML
        try:
            xml_dict = xmltodict.parse(xml_data)
            encrypt = xml_dict['xml']['Encrypt']
        except (KeyError, ValueError) as e:
            logger.error(f"解析 XML 失败: {str(e)}")
            return 'Invalid XML format', 400
        
        # 验证签名
        temp_sign = calculate_signature(WECHAT_TOKEN, timestamp, nonce, encrypt)
        if temp_sign != msg_signature:
            logger.warning(f"签名验证失败: {temp_sign} != {msg_signature}")
            return 'Invalid signature', 403
        
        # 解密消息
        decrypted_xml = decrypt_message(encrypt)
        if not decrypted_xml:
            logger.error("解密消息失败")
            return 'Decrypt failed', 403
        
        # 解析解密后的 XML
        try:
            msg = xmltodict.parse(decrypted_xml)['xml']
            msg_type = msg.get('MsgType')
            user_id = msg.get('FromUserName')
        except (KeyError, ValueError) as e:
            logger.error(f"解析解密后的 XML 失败: {str(e)}")
            return 'Invalid decrypted XML', 400
        
        # 处理文本消息
        if msg_type == 'text':
            content = msg.get('Content')
            logger.info(f"收到用户 {user_id} 的文本消息: {content}")
            
            # 调用 Dify
            dify_reply = get_dify_response(user_id, content)
            
            # 发送回微信
            token = get_access_token()
            if not token:
                logger.error("获取 access_token 失败，无法发送回复")
                return make_response('Failed to get access_token', 500)
                
            send_result = send_message(token, user_id, dify_reply)
            if send_result.get('errcode') != 0:
                logger.warning(f"发送消息失败: {send_result}")
        
        # 处理其他类型消息
        else:
            logger.info(f"收到非文本消息类型 {msg_type}，来自用户 {user_id}，暂不处理")
        
        # 返回成功
        return make_response('success')
    except Exception as e:
        logger.exception(f"处理消息时发生异常: {str(e)}")
        return make_response('error', 500)

# 健康检查接口
@app.route('/health', methods=['GET'])
def health_check():
    """健康检查接口，用于监控系统状态"""
    return {
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'service': 'wechat-customer-service'
    }

if __name__ == '__main__':
    # 检查环境变量
    required_vars = ['WECHAT_TOKEN', 'WECHAT_CORP_ID', 'WECHAT_AGENT_ID', 
                     'WECHAT_SECRET', 'WECHAT_ENCODING_AES_KEY', 
                     'DIFY_API_KEY', 'DIFY_API_URL']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"缺少必要的环境变量: {', '.join(missing_vars)}")
        logger.error("请检查 .env 文件配置")
        exit(1)
        
    logger.info("微信智能客服系统启动中...")
    app.run(host='0.0.0.0', port=5002, debug=True)
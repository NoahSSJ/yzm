from pathlib import Path
import re
from curl_cffi import requests
from pprint import pprint
import json
import os
import base64
import random
import math
import time
import numpy as np
import cv2
import ddddocr
import logging
import uuid
import execjs
import string
from urllib.parse import quote
import sys
pkg_dir = Path(__file__).parent / "reverse"
sys.path.append(pkg_dir)
from reverse.utils import encrypt

def jsonp_callback():
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=7))
    return f'__JSONP_{suffix}_0'

def xor_encode(token, data, _A="i/x1XgU0z7k8N+lCpOnPrv6\\qu2Gj9HRcwTYZ4bfSJBhaWstAeoMIEQ5mDdVFLKy", _P="3"):
    def s2b(s):
        enc, out, i = quote(s, safe="!*'()"), [], 0
        while i < len(enc):
            if enc[i] == '%':
                out.append(int(enc[i+1:i+3], 16)); i += 3
            else:
                out.append(ord(enc[i]) & 0xFF); i += 1
        return out

    d, k = s2b(data), s2b(token)
    kl = len(k)
    x = [(d[i] ^ k[i % kl]) & 0xFF for i in range(len(d))]  # 8位异或，有/无符号等价

    o, n, i = [], len(x), 0
    while i < n:
        m = min(3, n - i)
        b0 = x[i]
        b1 = x[i+1] if m > 1 else 0
        b2 = x[i+2] if m > 2 else 0
        o.append(_A[(b0 >> 2) & 0x3F])
        o.append(_A[((b0 << 4) & 0x30) | ((b1 >> 4) & 0x0F)])
        o.append(_A[((b1 << 2) & 0x3C) | ((b2 >> 6) & 0x03)] if m > 1 else _P)
        o.append(_A[b2 & 0x3F] if m > 2 else _P)
        i += 3
    return "".join(o)

# ============================================================
# 行为特征提取：19 个四元组 → 47 个统计特征
# ============================================================
def _mean(a): return sum(a) / len(a)
def _std(a):
    m = _mean(a); return math.sqrt(sum((v - m) ** 2 for v in a) / len(a))
def _r4(x): return float(f"{x:.4f}")  # parseFloat(x.toFixed(4))
def _quant(arr, p):
    s = sorted(arr)
    if p <= 0: return s[0]
    if p >= 100: return s[-1]
    idx = (len(s) - 1) * (p / 100); lo = math.floor(idx)
    return s[lo] + (s[lo + 1] - s[lo]) * (idx - lo)
def _diffq(t, a):  # (a[i+1]-a[i])/(t[i+1]-t[i])
    return [(a[i + 1] - a[i]) / (t[i + 1] - t[i]) for i in range(len(a) - 1)]
def _stats7(seq):  # [min, max, mean, std, unique(round后), q25, q75]
    return [_r4(min(seq)), _r4(max(seq)), _r4(_mean(seq)), _r4(_std(seq)),
            len(set(_r4(v) for v in seq)), _r4(_quant(seq, 25)), _r4(_quant(seq, 75))]


def feature_extract(data):
    """data: [[x,y,t,type], ...]，返回 47 个特征。"""
    if not isinstance(data, list) or len(data) <= 2:
        return []
    X = [d[0] for d in data]; Y = [d[1] for d in data]; T = [d[2] for d in data]
    vx = _diffq(T, X); vy = _diffq(T, Y)
    vmag = [math.sqrt(X[i] ** 2 + Y[i] ** 2) for i in range(len(X))]
    vm = _diffq(T, vmag)
    T2 = T[:-1]
    ax = _diffq(T2, vx); ay = _diffq(T2, vy); am = _diffq(T2, vm)
    out = [len(set(X)), len(set(Y)), _r4(_mean(Y)), _r4(_std(Y)), len(X)]
    out += _stats7(vx) + _stats7(vy) + _stats7(vm)
    out += _stats7(ax) + _stats7(ay) + _stats7(am)
    return out

def replace_special(s: str) -> str:
    if not isinstance(s, str):
        return ""
    return s.replace('\\', '-').replace('/', '_').replace('+', '*')

def generate_slide_trace(target_x: int, duration_ms: int = 1200) -> list:
    """生成滑动轨迹，返回 [[x,y,t,type], ...]"""
    trace = []
    begin_time = 0
    current_x = 0
    current_y = random.randint(5, 15)   # 初始Y位置轻微随机
    t = begin_time
    
    steps = random.randint(18, 28)      # 轨迹点数量 18~28 比较自然
    
    for i in range(steps):
        # X 逐渐接近目标，带一点加速度 + 抖动
        progress = i / (steps - 1)
        ease = progress * progress * (3 - 2 * progress)   # 缓动函数
        
        x = int(current_x + (target_x - current_x) * ease)
        x += random.randint(-2, 2)         # 小抖动
        
        # Y 轻微波动（人类手抖）
        y = current_y + int(math.sin(progress * math.pi * 3) * random.uniform(1.5, 3.5))
        
        # 时间间隔逐渐先快后慢
        dt = random.randint(12, 45) if i < steps * 0.6 else random.randint(25, 55)
        t += dt
        
        # type: 一般都是1（按下/移动）
        trace.append([max(0, x), y, t, 1])
        
        current_x = x
        current_y = y
    
    # 最后强制对齐目标位置（很重要）
    trace[-1][0] = target_x
    trace[-1][1] = current_y + random.randint(-1, 1)
    
    return trace

def encrypt_trace_arr(token: str, trace_arr: list) -> list:
    """把轨迹列表转成加密后的字符串列表"""
    encrypted = []
    for point in trace_arr:
        point_str = ','.join(map(str, point))      # "179,-462,350400,1"
        enc = xor_encode(token, point_str)
        encrypted.append(enc)
    return encrypted


def url_safe(s):
    return re.sub(r'[\\/+]', lambda m: {'\\':'-', '/':'_', '+':'*'}[m.group()], s)

def _0xab267f(short_validate: str, fingerprint: str, prefix: str = "NANP") -> str:
    """
    对应网易易盾 _0xab267f 函数
    short_validate: 来自 /api/v3/check 返回的短 validate
    fingerprint: 设备指纹（含时间戳）
    prefix: 一般为 "NANP"
    """
    # 1. 拼接
    raw = short_validate + '::' + fingerprint
    
    # 2. 执行 _0xb77ce（encrypt） + _0x127d20（replace_special）
    temp = encrypt(raw)                    # 这里调用你已有的 encrypt / b77ce 函数
    
    # 3. 字符替换
    hash_val = url_safe(temp)
    
    # 4. 拼接最终结果
    if prefix:
        result = prefix + '_' + hash_val
    else:
        result = hash_val
    
    result += "_v_i_1"    # 注意是 77_v_i_1
    
    return result


class AMS():
    session = requests.Session()
    session.headers = {
        'Accept': '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Connection': 'keep-alive',
        'Origin': 'https://user.zhihuishu.com',
        'Referer': 'https://user.zhihuishu.com/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0',
        'content-type': 'text/plain',
        'sec-ch-ua': '"Microsoft Edge";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }
    # session.proxy = {
    #     "http":"127.0.0.1:7890",
    #     "https":"127.0.0.1:7890"
    # }
    
    def __init__(self, p: str, save_name: str):
        self.p = p
        self.save_dir = Path(__file__).parent / save_name
        os.makedirs(self.save_dir, exist_ok=True)

    def get_captcha(self):
        js_path = Path(__file__).parent / 'reverse' / 'a.js'
        with open(js_path, mode='r', encoding="utf-8") as f:
            js_code = f.read()
        ctx = execjs.compile(js_code)
        n = ctx.call('G')
        d = ctx.call('v')
        data_dict = {
            "p": "YD00192283058223",
            "v": "2.0.13_yanzhengma",
            "vk": "d44593ca",
            "n": n,
            "d": d,
        }
        data = json.dumps(data_dict)
        # print(data)
        response = AMS.session.post('https://ir-sdk.dun.163.com/v4/j/up', data=data)
        # pprint(response.json())
        es = response.json()['data']['es']
        td = response.json()['data']['td']
        ts = response.json()['data']['ts']
        token = response.json()['data']['tk']
        js_path = Path(__file__).parent / 'reverse' / 'cb.js'
        with open(js_path, mode='r', encoding="utf-8") as f:
            js_code = f.read()
        ctx = execjs.compile(js_code)
        cb = ctx.call('makeCbToken')
        callback = jsonp_callback()
        params = {
            'referer': 'https://user.zhihuishu.com/zhsuser/register',
            'zoneId': 'CN31',
            'dt': 'EnaMU4j53VFAAlBQEUKGuafrlvB1fpHK',
            'irToken': token,
            'id': '75f9f716460a422f89a628f50fd8cc2b',
            'fp': 'D5+PmnBaavA44JxypQEHnYEI1b7RCX3UnJtzjB2WdHkSHrpP8SjX5w9umbxBE3TPkMJT9ozievwvwh8f7lwrC+nQMULmT6QYClYAzfR8mMsiHLTEErRrBj3nGbZTefQu/SQNkBuGX5f99hJEkd6izQQoG/S4/jNwYIxKeL+Ev5mkgwf7:1781874635295',
            'https': 'true',
            'type': '',
            'version': '2.28.5',
            'dpr': '1.25',
            'dev': '1',
            'cb': cb,
            'ipv6': 'false',
            'runEnv': '10',
            'group': '',
            'scene': '',
            'lang': 'zh-CN',
            'sdkVersion': '',
            'loadVersion': '2.5.4',
            'iv': '4',
            'user': '',
            'width': '320',
            'audio': 'false',
            'sizeType': '10',
            'smsVersion': 'v3',
            'token': '',
            'callback': callback,
        }
        response = AMS.session.get('https://c.dun.163.com/api/v3/get', params=params)
        # print(response.text)
        # pprint(response.json())
        if match := re.search(fr'{callback}\((.*?)\)', response.text, re.S):
            json_str = match.group(1)
            json_dict = json.loads(json_str)
            # pprint(json_dict)
            bg_url = json_dict['data']['bg'][0]
            slide_url = json_dict['data']['front'][0]
            token = json_dict['data']['token']
            zone_id = json_dict['data']['zoneId']
            bg_img = AMS.session.get(bg_url)
            slide_img = AMS.session.get(slide_url)
            bg_path = os.path.join(self.save_dir, 'bg.png')
            slide_path = os.path.join(self.save_dir, 'slide.png')
            with open(bg_path, mode='wb') as f:
                f.write(bg_img.content)
            with open(slide_path, mode='wb') as f:
                f.write(slide_img.content)
            return token, bg_path, slide_img
        else:
            print("获取captcha失败")

    def verify_captcha(self, token, bg_path=None, slide_path=None):
        js_path = Path(__file__).parent / 'reverse' / 'cb.js'
        with open(js_path, mode='r', encoding="utf-8") as f:
            js_code = f.read()
        ctx = execjs.compile(js_code)
        cb = ctx.call('makeCbToken')
        callback = jsonp_callback()

        x = AMS.get_slide_x(bg_path, slide_path)
        trace_arr = generate_slide_trace(x)
        encrypted_trace_arr = encrypt_trace_arr(token, trace_arr)
        encrypted_trace = ':'.join(encrypted_trace_arr)
        
        distance = f"{x}px"
        _0x15278a = encrypt(xor_encode(token, (lambda v: str(int(v)) if v==int(v) else repr(v))(int(float(distance[:-2]))/320*100)))
        
        _0x4d98f2 = feature_extract(trace_arr)
        # print(_0x4d98f2)
        # print('.'.join(map(str, _0x4d98f2)))
        data_dict = {
            'd': encrypt(encrypted_trace),
            'm': '',
            'p': _0x15278a,
            'f': encrypt(xor_encode(token, '.'.join(map(str, _0x4d98f2)))),
            'ext': encrypt(xor_encode(token, '1' + ',' + str(len(trace_arr)))), 
        }
        data = json.dumps(data_dict, separators=(',', ':'))
        print('1' + ',' + str(len(trace_arr)))
        print(len(trace_arr))
        print(len(encrypted_trace_arr))
        params = {
            'referer': 'https://user.zhihuishu.com/zhsuser/register',
            'zoneId': 'CN31',
            'dt': 'EnaMU4j53VFAAlBQEUKGuafrlvB1fpHK',
            'id': '75f9f716460a422f89a628f50fd8cc2b',
            'token': token,
            'data': data,
            'width': '320',
            'type': '2',
            'version': '2.28.5',
            'cb': cb,
            'user': '',
            'extraData': '',
            'bf': '0',
            'runEnv': '10',
            'sdkVersion': '',
            'loadVersion': '2.5.4',
            'iv': '4',
            'callback': callback,
        }
        # pprint(params)

        response = AMS.session.get('https://c.dun.163.com/api/v3/check', params=params)
        # print(response.status_code)
        # print(response.text)
        if match := re.search(fr'{callback}\((.*?)\)', response.text, re.S):
            json_str = match.group(1)
            json_dict = json.loads(json_str)
            pprint(json_dict)
            token = json_dict['data']['token']
            validate = json_dict['data']['validate']
            zone_id = json_dict['data']['zoneId']
            if json_dict['data']['result'] == True:
                return token, validate, zone_id
            else:
                exit()
        
    def send_sms(self, validate, zone_id):
        short_validate = validate
        # fingerprint = rf"Cv/eunqBTDEzhN0tijp4ai+dRwqcj8LKilkHKjG3ewS+YBlS90HCZ8RT5tWJRaSapGx5ctTdZ1xn5c82dt6/LcIAwUBkJLXE3QyI\4G3iTi3uKOXMg3MAyih1A8CkTDXD4KtDhLCByZvdOinr6Wr4JI\DUNHCj2IKKJMcT2gObR8/aYu:{int(time.time() * 1000)}"
        fingerprint = r"Cv/eunqBTDEzhN0tijp4ai+dRwqcj8LKilkHKjG3ewS+YBlS90HCZ8RT5tWJRaSapGx5ctTdZ1xn5c82dt6/LcIAwUBkJLXE3QyI\4G3iTi3uKOXMg3MAyih1A8CkTDXD4KtDhLCByZvdOinr6Wr4JI\DUNHCj2IKKJMcT2gObR8/aYu:1782243703788"
        final_validate = _0xab267f(short_validate, fingerprint, zone_id)
        data = f'validate={final_validate}&mobile={self.p}'
        print(data)
        # data= '1'
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://user.zhihuishu.com',
            'Referer': 'https://user.zhihuishu.com/zhsuser/register?v=20230919',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36 Edg/149.0.0.0',
            'X-Requested-With': 'XMLHttpRequest',
            'sec-ch-ua': '"Microsoft Edge";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Cookie': '__snaker__id=0qioEIcYaOe2k78Z; JSESSIONID=0DAEDD587A4C4521BB01AB4F2566CED7; INGRESSCOOKIE=1782242804.84.38363.819507|865937502aa59599d89fff2e6ce3d29b; gdxidpyhxdE=imYGkIlzimZnLDAKkDEdh%5C1eE5r0QO4x52B8jZvJj0tHKwG%2BBUqmzk6Lg%2BsG0%2FH%5CtGAc%2FfjEg%5CQBAZ0HVDNKQXk%2B2H9fqgVabncTYz6nnTxVl3n%2FdI4%2BmPhQq%5CrdM%5C%5C0RL%5CHkdyJBC87oXNsRpt7vi%5COJPQ3JlsPz9H7jryrLkjTXxCs%3A1782248574679; acw_tc=76b20f8617822476761064710e08ee360e6a6cd2adc21ad40be0c28187aa07; SERVERID=fe82cac8f8e600c79e0f3988dddd82bc|1782248482|1782242803',
        }
        response = AMS.session.post('https://user.zhihuishu.com/zhsuser/register/code2.do',headers=headers, data=data)
        # print(response.text)
        pprint(response.json())

    @staticmethod
    def get_slide_x(bg_path: Path, slide_path: Path):
        bg = cv2.imread(bg_path)
        slide = cv2.imread(slide_path)
        bg_edge = cv2.Canny(bg, 100, 200)
        slide_edge = cv2.Canny(slide, 100, 200)
        result = cv2.matchTemplate(bg_edge, slide_edge, cv2.TM_CCOEFF_NORMED)
        _, max_val, _, max_loc = cv2.minMaxLoc(result)
        x = max_loc[0]    
        print(x)      # 缺口左上角的 x 坐标
        # print(round(max_val, 3))
        return x



    @classmethod
    def run(cls, p, save_name):
        obj = AMS(p, save_name)
        token, bg_path, slide_path = obj.get_captcha()
        token, validate, zone_id = obj.verify_captcha(token, r'local\bg.png', r'local\slide.png')
        obj.send_sms(validate, zone_id)

if __name__ == "__main__":
    AMS.run('13987509723', 'local')

    
         






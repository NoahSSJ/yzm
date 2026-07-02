
"""
网易易盾滑块验证码 提交数据(data)的完整离线复现。

两层加密 + 行为特征提取，全部用真实抓包数据验证通过：
  内层 xor_encode : 单帧轨迹编码（自定义表 i/x1XgU0... / pad '3'）
  外层 encrypt    : 分组密码（默认表 MB.CfHU... / pad '7'，nonce+CRC32+SBOX+CBC）
  feature_extract : 19→47 个行为统计特征

提交结构：
  data = {
    "d":   encrypt( sample(traceData).join(':') ),   # 逐帧轨迹密文，':' 拼接
    "m":   "",
    "p":   encrypt( xor_encode(token, str(left/320*100)) ),  # 拼图最终位置百分比
    "f":   encrypt( xor_encode(token, ','.join(47特征)) ),    # 行为特征
    "ext": encrypt( xor_encode(token, "按下次数,轨迹长度") ), # 统计量
  }
"""
import json
import math
import random
import re
from urllib.parse import quote

# ============================================================
# 公共原语
# ============================================================
def i8(x):
    """折叠到有符号 int8 [-128,127]，对应 _0x3ab4e1。"""
    x &= 0xFF
    return x - 256 if x > 127 else x


def u8(x):
    return x & 0xFF


def str_bytes(s):
    """encodeURIComponent 版字符串转有符号字节，对应 _0x312bea。"""
    enc = quote(str(s), safe="!*'()")
    out, i = [], 0
    while i < len(enc):
        if enc[i] == '%':
            out.append(i8(int(enc[i + 1:i + 3], 16))); i += 3
        else:
            out.append(i8(ord(enc[i]))); i += 1
    return out


def bytes_to_string(d):
    return bytes(u8(b) for b in d).decode("utf-8", errors="replace")


def xor_byte(a, b):
    return i8(i8(a) ^ i8(b))


def add_byte(a, b):
    return i8(a + b)


# ============================================================
# 内层：xor_encode / xor_decode
#   自定义字母表 i/x1XgU0... , pad '3'
# ============================================================
XOR_ALPHA = "i/x1XgU0z7k8N+lCpOnPrv6\\qu2Gj9HRcwTYZ4bfSJBhaWstAeoMIEQ5mDdVFLKy"
XOR_PAD = "3"
_XOR_IDX = {c: i for i, c in enumerate(XOR_ALPHA)}


def _b64_encode(data, alpha, pad):
    arr = [u8(b) for b in data]
    o = []
    for i in range(0, len(arr), 3):
        n = min(3, len(arr) - i)
        b0 = arr[i]
        b1 = arr[i + 1] if n > 1 else 0
        b2 = arr[i + 2] if n > 2 else 0
        o.append(alpha[(b0 >> 2) & 0x3F])
        o.append(alpha[((b0 << 4) & 0x30) | ((b1 >> 4) & 0x0F)])
        o.append(alpha[((b1 << 2) & 0x3C) | ((b2 >> 6) & 0x03)] if n > 1 else pad)
        o.append(alpha[b2 & 0x3F] if n > 2 else pad)
    return "".join(o)


def _b64_decode(s, alpha, pad):
    idx = {c: i for i, c in enumerate(alpha)}
    out = []
    for i in range(0, len(s), 4):
        g = s[i:i + 4]
        e = [idx.get(c, 0) for c in g] + [0, 0, 0, 0]
        npad = g.count(pad)
        out.append(((e[0] << 2) | ((e[1] >> 4) & 3)) & 0xFF)
        if npad < 2:
            out.append(((e[1] << 4) | ((e[2] >> 2) & 15)) & 0xFF)
        if npad < 1:
            out.append(((e[2] << 6) | e[3]) & 0xFF)
    return out


def xor_encode(token, data):
    d = str_bytes(data)
    k = str_bytes(token)
    kl = len(k)
    return _b64_encode([xor_byte(d[i], k[i % kl]) for i in range(len(d))], XOR_ALPHA, XOR_PAD)


def xor_decode(token, enc):
    k = str_bytes(token)
    kl = len(k)
    x = _b64_decode(enc, XOR_ALPHA, XOR_PAD)
    return bytes_to_string([u8(xor_byte(x[i], k[i % kl])) for i in range(len(x))])


# ============================================================
# 外层：encrypt / decrypt
#   默认字母表 MB.CfHU... , pad '7'
# ============================================================
ENC_ALPHA = "MB.CfHUzEeJpsuGkgNwhqiSaI4Fd9L6jYKZAxn1/Vml0c5rbXRP+8tD3QTO2vWyo"
ENC_PAD = "7"
SEED_KEY = "fd6a43ae25f74398b61c03c83be37449"
ROUND_KEY = "037606da0296055c"
SBOX_HEX = (
    "a7be3f3933fa8c5fcf86c4b6908b569ba1e26c1a6d7cfbf60ae4b00e074a194d"
    "ac4b73e7f898541159a39d08183b76eedee3ed341e6685d2357440158394b1ff"
    "03a9004cbbb5ca7dcb7f41489a16e03dcc9c71eb3c9796685b1d01b4d56193a6"
    "e1f1a2470445c191ae49c5d82765dc82c350f263387a24a502fcbf442e2dddaa"
    "d0e936d9ea22b89275307b42518fbc3a626ba806d4ecd6d725f50cc8c72fefa4"
    "551ccd6fc9b2b7ab954f815c7264c6e51f4eaf99885a79892b1b60a0b3526e57"
    "ba5d178d370958847eb9fd28f9ce0bc023f4148a2adfe632126769057043d3bd"
    "8eda0df7872629f3809ef05310e83113216afe202c460fc23e789f77d1addb5e"
)
SBOX = [i8(int(SBOX_HEX[i:i + 2], 16)) for i in range(0, len(SBOX_HEX), 2)]
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[u8(_v)] = _i


def _xors(d, k):
    kl = len(k); return [xor_byte(d[i], k[i % kl]) for i in range(len(d))]
def _shifts(d, k):
    kl = len(k); return [add_byte(d[i], k[i % kl]) for i in range(len(d))]
def _unshifts(d, k):
    kl = len(k); return [i8(d[i] - k[i % kl]) for i in range(len(d))]
def _sub_bytes(d): return [SBOX[u8(b)] for b in d]
def _inv_sub_bytes(d): return [i8(INV_SBOX[u8(b)]) for b in d]


def _make_crc_table():
    t = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        t.append(c & 0xFFFFFFFF)
    return t
_CRC_TABLE = _make_crc_table()


def crc32(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC_TABLE[0xFF & (crc ^ b)]
    return "%08x" % ((0xFFFFFFFF ^ crc) & 0xFFFFFFFF)


def _int4(x):
    x &= 0xFFFFFFFF
    return [i8((x >> 24) & 0xFF), i8((x >> 16) & 0xFF), i8((x >> 8) & 0xFF), i8(x & 0xFF)]
def _bytes4_to_int(b):
    return ((u8(b[0]) << 24) | (u8(b[1]) << 16) | (u8(b[2]) << 8) | u8(b[3])) & 0xFFFFFFFF


def _prep(data):
    L = len(data)
    pad = 64 - (L % 64) - 4 if (L % 64) <= 60 else 128 - (L % 64) - 4
    return data + [0] * pad + _int4(L)
def _chunk64(d):
    return [d[i:i + 64] for i in range(0, len(d), 64)]


def _dec_byte(two):
    return i8((int(two[0], 16) << 4) + int(two[1], 16))
def _round_steps():
    return [(_dec_byte(ROUND_KEY[i:i + 2]), _dec_byte(ROUND_KEY[i + 2:i + 4]))
            for i in range(0, len(ROUND_KEY), 4)]


def _op(idx, b, k):
    k = i8(k)
    if idx == 0: return list(b)
    if idx == 1: return [xor_byte(x, k) for x in b]
    if idx == 2: return [add_byte(x, k) for x in b]
    if idx == 3: return [xor_byte(x, i8(k + j)) for j, x in enumerate(b)]
    if idx == 4: return [add_byte(x, i8(k + j)) for j, x in enumerate(b)]
    if idx == 5: return [xor_byte(x, i8(k - j)) for j, x in enumerate(b)]
    if idx == 6: return [add_byte(x, i8(k - j)) for j, x in enumerate(b)]
    raise ValueError(idx)
def _inv_op(idx, b, k):
    k = i8(k)
    if idx == 0: return list(b)
    if idx == 1: return [xor_byte(x, k) for x in b]
    if idx == 2: return [i8(x - k) for x in b]
    if idx == 3: return [xor_byte(x, i8(k + j)) for j, x in enumerate(b)]
    if idx == 4: return [i8(x - i8(k + j)) for j, x in enumerate(b)]
    if idx == 5: return [xor_byte(x, i8(k - j)) for j, x in enumerate(b)]
    if idx == 6: return [i8(x - i8(k - j)) for j, x in enumerate(b)]
    raise ValueError(idx)
def _to_block(b):
    for op, arg in _round_steps(): b = _op(op, b, arg)
    return b
def _inv_to_block(b):
    for op, arg in reversed(_round_steps()): b = _inv_op(op, b, arg)
    return b


def _fit64(a):
    if not a: return [0] * 64
    if len(a) >= 64: return a[:64]
    return [a[i % len(a)] for i in range(64)]
def _derive_key(nonce):
    return _fit64(_xors(_fit64(str_bytes(SEED_KEY)), _fit64(nonce)))
def _gen_nonce():
    return [i8(random.randint(0, 255)) for _ in range(4)]


def encrypt(text, nonce=None):
    if nonce is None:
        nonce = _gen_nonce()
    data = str_bytes(text)
    session_key = _derive_key(nonce)
    crc = str_bytes(crc32([u8(b) for b in data]))
    blocks = _chunk64(_prep(data + crc))
    out = list(nonce)
    chain = session_key
    for blk in blocks:
        b = _to_block(blk)
        x = _xors(b, session_key)
        s = _shifts(x, chain)
        x = _xors(s, chain)
        chain = _sub_bytes(_sub_bytes(x))
        out += chain
    return _b64_encode(out, ENC_ALPHA, ENC_PAD)


def decrypt(token, verify_crc=False):
    raw = _b64_decode(token, ENC_ALPHA, ENC_PAD)
    nonce = [i8(v) for v in raw[:4]]
    body = raw[4:]
    session_key = _derive_key(nonce)
    plain, chain, i = [], session_key, 0
    while i + 64 <= len(body):
        cb = [i8(v) for v in body[i:i + 64]]
        x = _inv_sub_bytes(_inv_sub_bytes(cb))
        s = _xors(x, chain)
        xx = _unshifts(s, chain)
        b = _xors(xx, session_key)
        plain += _inv_to_block(b)
        chain = cb
        i += 64
    L = _bytes4_to_int(plain[-4:])
    combined = plain[:L]
    data = combined[:-8]
    crc_bytes = combined[-8:]
    text = bytes_to_string(data)
    if verify_crc and bytes_to_string(crc_bytes) != crc32([u8(b) for b in data]):
        raise ValueError("CRC mismatch")
    return text


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


# ============================================================
# 抽样：sample(arr, num)，点数不足时原样返回副本
# ============================================================
def sample(arr, num):
    """对应 _0x1b7568.sample：粗略实现——点少于阈值时原样返回。
    若需要严格降采样逻辑，可按真实 SAMPLE_NUM 调整。"""
    if len(arr) <= num or num <= 0:
        return [list(x) if isinstance(x, list) else x for x in arr]
    # 均匀抽样到 num 个
    step = (len(arr) - 1) / (num - 1)
    return [arr[round(i * step)] for i in range(num)]


def _num_to_str(n):
    """模拟 JS 的 Number + ''：整数去 .0，其余最短往返表示。"""
    return str(int(n)) if n == int(n) else repr(n)


# ============================================================
# 总封装：构造完整 data
# ============================================================
def build_data(token, atom_trace, trace_data, jigsaw_left_px, mouse_down_counts):
    """
    token            : 会话 token
    atom_trace       : 原始四元组列表 [[x,y,t,type], ...]
    trace_data       : 已逐帧 xor_encode 的密文字符串列表（即 this.traceData）
    jigsaw_left_px   : 拼图块最终 left，像素，如 "150px" 或 150 或 97.5
    mouse_down_counts: 按下次数
    返回 dict（可 json.dumps）
    """
    # d：抽样后的逐帧密文用 ':' 拼接，再 encrypt
    d_plain = ":".join(sample(trace_data, 2))
    d = encrypt(d_plain)

    # p：拼图最终位置百分比
    if isinstance(jigsaw_left_px, str):
        left = int(float(re.match(r'[+-]?\d+(?:\.\d+)?', jigsaw_left_px.strip()).group()))
    else:
        left = int(float(jigsaw_left_px))
    p = encrypt(xor_encode(token, _num_to_str(left / 320 * 100)))

    # f：行为特征
    feats = feature_extract(sample(atom_trace, 2))
    f = encrypt(xor_encode(token, ",".join(_num_to_str(v) for v in feats)))

    # ext：按下次数,轨迹长度
    ext = encrypt(xor_encode(token, f"{mouse_down_counts},{len(trace_data)}"))

    return {"d": d, "m": "", "p": p, "f": f, "ext": ext}


# ============================================================
# 自验证
# ============================================================
if __name__ == "__main__":
    print("=== encrypt/decrypt 真实配对 ===")
    enc_pairs = [
        ("/Ezj1AgP", "f1PbyxAdbj8dqPq+OVTUfyqCYKsC6I2S/kvIFasXDXqO/n0ft085VUdnI+aV1hfb8y/urp2i9kYJ+1ire68/TBqz59M7"),
        ("dvnEZWYMjIfxnvDI39uqb4ypKK4eL6m6", "gn6ergsoPSRXf9ah.BzE/mCtD9EGMmHaKgpZnLMPvZrQsDFl+PY4w0YeWudurQ4oD0yIlwvNJczjNgS/tRPRvjfhFHs7"),
    ]
    for pt, ct in enc_pairs:
        n = [i8(v) for v in _b64_decode(ct, ENC_ALPHA, ENC_PAD)[:4]]
        print(f"  enc {'OK' if encrypt(pt, n)==ct else 'XX'}  dec {'OK' if decrypt(ct)==pt else 'XX'}  {pt!r}")

    print("\n=== xor_encode 真实配对 (token=93fb...) ===")
    XT = "93fb9749f8764ffaa0d68c8a7044fab0"
    xor_pairs = [
        ("178,-468,443288,1", "xiOHPwp1icgk1iNg/4DHPvi3"),
        ("188,-466,458888,1", "xiWHPwp1icLk1izl1gDHPvi3"),
    ]
    for pt, ct in xor_pairs:
        print(f"  {'OK' if xor_encode(XT, pt)==ct else 'XX'}  {pt!r} -> {xor_encode(XT, pt)}")

    print("\n=== feature_extract (47 特征) ===")
    fdata = [[5,2,74,1],[7,3,79,1],[12,3,87,1],[18,4,97,1],[26,7,103,1],[34,7,111,1],[42,8,119,1],[49,11,128,1],[56,12,135,1],[63,14,143,1],[70,15,151,1],[76,16,161,1],[80,17,169,1],[83,17,177,1],[85,17,185,1],[87,17,192,1],[89,17,200,1],[90,17,215,1],[90,17,223,1]]
    fwant = [18,11,11.6316,5.5933,19,0,1.3333,0.6007,0.3567,13,0.308,0.875,0,0.5,0.1112,0.1351,8,0,0.1384,0,1.4145,0.6107,0.3684,18,0.302,0.9015,-0.0556,0.0733,-0.0038,0.029,15,-0.0179,0,-0.0833,0.04,-0.0039,0.0267,12,-0.0156,0.0125,-0.0735,0.0807,-0.0048,0.0306,17,-0.0185,0.004]
    fgot = feature_extract(fdata)
    print(f"  {'OK 全部匹配' if fgot==fwant else 'XX 不匹配'}  (len={len(fgot)})")

    print("\n=== build_data 演示 ===")
    demo_token = "c3717ee27ba74bfb90249010ad004a5c"
    # 用 atom_trace 同时生成 trace_data（逐帧 xor_encode）
    demo_atom = fdata
    demo_trace = [xor_encode(demo_token, f"{x},{y},{t},{tp}") for x, y, t, tp in demo_atom]
    data = build_data(demo_token, demo_atom, demo_trace, "97.5px", 1)
    print(json.dumps(data, ensure_ascii=False, indent=2))
    # 验证 p 字段能正确还原
    print("\n  p 解密 ->", xor_decode(demo_token, decrypt(data["p"])), "(期望 30.312499999999996)")
    print("  ext 解密 ->", xor_decode(demo_token, decrypt(data["ext"])))
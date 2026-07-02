
"""
网易易盾 encrypt / decrypt 的独立复现（无浏览器依赖）。
对应混淆函数 _0x3ebd00 (encrypt) 及其逆运算。

结构：明文 → +CRC32 → 填充切64字节块 →
  每块: toBlock置换 → xors(会话密钥) → shifts(链值,加法) → xors(链值) → subBytes×2 → 更新链值(CBC)
  → 开头拼4字节nonce → 私有base64

注意：encrypt 用的 base64 是【默认表】(MB.CfHU... / pad '7')，
      与单帧 xorEncode 用的表(i/x1XgU0... / pad '3') 不同。
"""
import random
from urllib.parse import quote

SEED_KEY = "fd6a43ae25f74398b61c03c83be37449"
ROUND_KEY = "037606da0296055c"
ENC_ALPHA = "MB.CfHUzEeJpsuGkgNwhqiSaI4Fd9L6jYKZAxn1/Vml0c5rbXRP+8tD3QTO2vWyo"
ENC_PAD = "7"
ENC_INDEX = {c: i for i, c in enumerate(ENC_ALPHA)}

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


def i8(x):
    """折叠到有符号 int8 [-128,127]，对应 _0x3ab4e1。"""
    x &= 0xFF
    return x - 256 if x > 127 else x


def u8(x):
    return x & 0xFF


def str_bytes(s):
    """encodeURIComponent 版字符串转有符号字节，对应 _0x312bea。"""
    enc = quote(s, safe="!*'()")
    out, i = [], 0
    while i < len(enc):
        if enc[i] == '%':
            out.append(i8(int(enc[i + 1:i + 3], 16))); i += 3
        else:
            out.append(i8(ord(enc[i]))); i += 1
    return out


def xor_byte(a, b):
    return i8(i8(a) ^ i8(b))


def add_byte(a, b):
    return i8(a + b)


def xors(d, k):
    kl = len(k)
    return [xor_byte(d[i], k[i % kl]) for i in range(len(d))]


def shifts(d, k):
    kl = len(k)
    return [add_byte(d[i], k[i % kl]) for i in range(len(d))]


def unshifts(d, k):
    kl = len(k)
    return [i8(d[i] - k[i % kl]) for i in range(len(d))]


SBOX = [i8(int(SBOX_HEX[i:i + 2], 16)) for i in range(0, len(SBOX_HEX), 2)]
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[u8(_v)] = _i


def sub_bytes(d):
    return [SBOX[u8(b)] for b in d]


def inv_sub_bytes(d):
    return [i8(INV_SBOX[u8(b)]) for b in d]


# ---- CRC32 -> 8字符小写hex ----
def _make_crc_table():
    t = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        t.append(c & 0xFFFFFFFF)
    return t


CRC_TABLE = _make_crc_table()


def crc32(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ CRC_TABLE[0xFF & (crc ^ b)]
    crc = (0xFFFFFFFF ^ crc) & 0xFFFFFFFF
    return "%08x" % crc


def int4(x):
    x &= 0xFFFFFFFF
    return [i8((x >> 24) & 0xFF), i8((x >> 16) & 0xFF), i8((x >> 8) & 0xFF), i8(x & 0xFF)]


def bytes4_to_int(b):
    return ((u8(b[0]) << 24) | (u8(b[1]) << 16) | (u8(b[2]) << 8) | u8(b[3])) & 0xFFFFFFFF


def prep(data):
    L = len(data)
    pad = 64 - (L % 64) - 4 if (L % 64) <= 60 else 128 - (L % 64) - 4
    return data + [0] * pad + int4(L)


def chunk64(d):
    return [d[i:i + 64] for i in range(0, len(d), 64)]


# ---- toBlock 置换 ----
def dec_byte(two):
    return i8((int(two[0], 16) << 4) + int(two[1], 16))


def _op(idx, b, k):
    k = i8(k)
    if idx == 0:
        return list(b)
    if idx == 1:
        return [xor_byte(x, k) for x in b]
    if idx == 2:
        return [add_byte(x, k) for x in b]
    if idx == 3:
        return [xor_byte(x, i8(k + j)) for j, x in enumerate(b)]
    if idx == 4:
        return [add_byte(x, i8(k + j)) for j, x in enumerate(b)]
    if idx == 5:
        return [xor_byte(x, i8(k - j)) for j, x in enumerate(b)]
    if idx == 6:
        return [add_byte(x, i8(k - j)) for j, x in enumerate(b)]
    raise ValueError(idx)


def _inv_op(idx, b, k):
    k = i8(k)
    if idx == 0:
        return list(b)
    if idx == 1:
        return [xor_byte(x, k) for x in b]
    if idx == 2:
        return [i8(x - k) for x in b]
    if idx == 3:
        return [xor_byte(x, i8(k + j)) for j, x in enumerate(b)]
    if idx == 4:
        return [i8(x - i8(k + j)) for j, x in enumerate(b)]
    if idx == 5:
        return [xor_byte(x, i8(k - j)) for j, x in enumerate(b)]
    if idx == 6:
        return [i8(x - i8(k - j)) for j, x in enumerate(b)]
    raise ValueError(idx)


def _round_steps():
    steps = []
    for i in range(0, len(ROUND_KEY), 4):
        seg = ROUND_KEY[i:i + 4]
        steps.append((dec_byte(seg[0:2]), dec_byte(seg[2:4])))
    return steps


def to_block(b):
    for op, arg in _round_steps():
        b = _op(op, b, arg)
    return b


def inv_to_block(b):
    for op, arg in reversed(_round_steps()):
        b = _inv_op(op, b, arg)
    return b


# ---- 会话密钥 ----
def fit64(a):
    if not a:
        return [0] * 64
    if len(a) >= 64:
        return a[:64]
    return [a[i % len(a)] for i in range(64)]


def derive_key(nonce):
    s = fit64(str_bytes(SEED_KEY))
    s = xors(s, fit64(nonce))
    s = fit64(s)
    return s


def gen_nonce():
    return [i8(random.randint(0, 255)) for _ in range(4)]


# ---- 私有 base64 ----
def b64_encode(data, alpha=ENC_ALPHA, pad=ENC_PAD):
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


def b64_decode(s, alpha=ENC_ALPHA, pad=ENC_PAD):
    idx = {c: i for i, c in enumerate(alpha)}
    out = []
    for i in range(0, len(s), 4):
        g = s[i:i + 4]
        e = [idx.get(c, 0) for c in g]
        while len(e) < 4:
            e.append(0)
        np = g.count(pad)
        out.append(((e[0] << 2) | ((e[1] >> 4) & 3)) & 0xFF)
        if np < 2:
            out.append(((e[1] << 4) | ((e[2] >> 2) & 15)) & 0xFF)
        if np < 1:
            out.append(((e[2] << 6) | e[3]) & 0xFF)
    return out


def bytes_to_string(d):
    return bytes(u8(b) for b in d).decode("utf-8", errors="replace")


# ============== 公开 API ==============
def encrypt(text, nonce=None):
    if nonce is None:
        nonce = gen_nonce()
    data = str_bytes(text)
    session_key = derive_key(nonce)
    crc = str_bytes(crc32([u8(b) for b in data]))
    blocks = chunk64(prep(data + crc))
    out = list(nonce)
    chain = session_key
    for blk in blocks:
        b = to_block(blk)
        x = xors(b, session_key)
        s = shifts(x, chain)
        x = xors(s, chain)
        chain = sub_bytes(sub_bytes(x))
        out = out + chain
    return b64_encode(out)


def decrypt(token, verify_crc=False):
    raw = b64_decode(token)
    nonce = [i8(v) for v in raw[:4]]
    body = raw[4:]
    session_key = derive_key(nonce)
    plain = []
    chain = session_key
    i = 0
    while i + 64 <= len(body):
        cb = [i8(v) for v in body[i:i + 64]]
        x = inv_sub_bytes(inv_sub_bytes(cb))
        s = xors(x, chain)
        xx = unshifts(s, chain)
        b = xors(xx, session_key)
        plain += inv_to_block(b)
        chain = cb
        i += 64
    L = bytes4_to_int(plain[-4:])
    combined = plain[:L]
    data = combined[:-8]
    crc_bytes = combined[-8:]
    text = bytes_to_string(data)
    if verify_crc and bytes_to_string(crc_bytes) != crc32([u8(b) for b in data]):
        raise ValueError("CRC mismatch")
    return text


if __name__ == "__main__":
    pairs = [
        ("/Ezj1AgP", "f1PbyxAdbj8dqPq+OVTUfyqCYKsC6I2S/kvIFasXDXqO/n0ft085VUdnI+aV1hfb8y/urp2i9kYJ+1ire68/TBqz59M7"),
        ("irm0xi33", "mzhWmgD3Lvye0ERAfvTmvMJDrgEIN2+bbY1/oIKwCs6EN0.BRM5biVOgudMsJcRFo4in9USsl2KaNstLrTsN+pcGzAI7"),
        ("dvnEZWYMjIfxnvDI39uqb4ypKK4eL6m6", "gn6ergsoPSRXf9ah.BzE/mCtD9EGMmHaKgpZnLMPvZrQsDFl+PY4w0YeWudurQ4oD0yIlwvNJczjNgS/tRPRvjfhFHs7"),
    ]
    ok = 0
    for pt, ct in pairs:
        nonce = [i8(v) for v in b64_decode(ct)[:4]]
        my = encrypt(pt, nonce)
        enc_ok = my == ct
        dec_ok = decrypt(ct) == pt
        ok += enc_ok and dec_ok
        print(f"{'OK' if enc_ok else 'XX'} encrypt  {'OK' if dec_ok else 'XX'} decrypt   pt={pt!r}")
    print(f"\n{ok}/{len(pairs)} passed")
    rt = "hello,world:123,-4,5,1"
    print("\nrandom-nonce roundtrip:", decrypt(encrypt(rt)) == rt)
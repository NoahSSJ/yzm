import math
import random
from urllib.parse import quote

# xor_encode 函数（你原来的，已确认可用）
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
    x = [(d[i] ^ k[i % kl]) & 0xFF for i in range(len(d))]

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


# 1. 生成轨迹函数
def generate_slide_trace(target_x: int, duration_ms: int = 1200) -> list:
    trace = []
    current_x = 0
    current_y = random.randint(5, 15)
    t = 0
    steps = random.randint(18, 28)
    
    for i in range(steps):
        progress = i / (steps - 1)
        ease = progress * progress * (3 - 2 * progress)   # 缓动
        x = int(current_x + (target_x - current_x) * ease)
        x += random.randint(-2, 2)
        y = current_y + int(math.sin(progress * math.pi * 3) * random.uniform(1.5, 3.5))
        dt = random.randint(12, 45) if i < steps * 0.6 else random.randint(25, 55)
        t += dt
        trace.append([max(0, x), y, t, 1])
        current_x = x
        current_y = y
    
    # 最后强制对齐
    trace[-1][0] = target_x
    trace[-1][1] += random.randint(-1, 1)
    return trace


# 2. 加密轨迹点函数
def encrypt_trace_points(token: str, trace_arr: list) -> list:
    encrypted = []
    for point in trace_arr:
        point_str = ','.join(map(str, point))   # 如 "179,-462,350400,1"
        enc = xor_encode(token, point_str)
        encrypted.append(enc)
    return encrypted


# ================ 测试运行 ================
if __name__ == "__main__":
    token = "d7787aa7cbde4549892cbab2e7169703"
    target_x = 180                     # 假设本次滑块位置
    
    trace_arr = generate_slide_trace(target_x, duration_ms=1100)
    
    print("轨迹点数量:", len(trace_arr))
    print("第一个点:", trace_arr[0])
    print("最后一个点:", trace_arr[-1])
    print("\n前3个加密点:")
    encrypted = encrypt_trace_points(token, trace_arr)
    print(encrypted[:3])
    print("...")
    print("后2个加密点:", encrypted[-2:])
    print("\n完整加密轨迹字符串（d 参数用这个）:")
    print(':'.join(encrypted))
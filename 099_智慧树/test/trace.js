/**
 * 网易易盾 encrypt / decrypt 的独立复现（无 DOM 依赖）
 * 对应混淆函数 _0x3ebd00 (encrypt) 及其逆运算。
 *
 * 结构：明文 → +CRC32 → 填充切64字节块 →
 *   每块: toBlock置换 → xors(会话密钥) → shifts(链值,加法) → xors(链值) → subBytes×2 → 更新链值(CBC)
 *   → 开头拼4字节nonce → 私有base64
 *
 * 注意：这里用的 base64 字母表是 encrypt 的【默认表】(MB.CfHU... / pad '7')，
 *       和单帧 xorEncode 用的表(i/x1XgU0... / pad '3')不同！
 */

// ---- 有符号字节折叠 [-128,127] (混淆里的 _0x3ab4e1) ----
function i8(x) {
  x = ((x % 256) + 256) % 256;
  return x > 127 ? x - 256 : x;
}

// ---- 字符串 → 字节 (encodeURIComponent 版, _0x312bea) ----
function strBytes(s) {
  s = encodeURIComponent(s);
  const out = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '%') { out.push(i8(parseInt(s.substr(i + 1, 2), 16))); i += 2; }
    else out.push(i8(s.charCodeAt(i)));
  }
  return out;
}

// ---- 单字节运算 ----
const xorByte = (a, b) => i8(i8(a) ^ i8(b));     // _0x9e274a
const addByte = (a, b) => i8(a + b);             // _0x6470c6

// ---- 数组级运算 ----
const xors  = (d, k) => d.map((v, i) => xorByte(v, k[i % k.length]));  // _0x5b1ad2
const shifts = (d, k) => d.map((v, i) => addByte(v, k[i % k.length])); // _0x474f75

// ---- S-box (有符号) 与代换 ----
const SBOX_HEX =
  "a7be3f3933fa8c5fcf86c4b6908b569ba1e26c1a6d7cfbf60ae4b00e074a194d" +
  "ac4b73e7f898541159a39d08183b76eedee3ed341e6685d2357440158394b1ff" +
  "03a9004cbbb5ca7dcb7f41489a16e03dcc9c71eb3c9796685b1d01b4d56193a6" +
  "e1f1a2470445c191ae49c5d82765dc82c350f263387a24a502fcbf442e2dddaa" +
  "d0e936d9ea22b89275307b42518fbc3a626ba806d4ecd6d725f50cc8c72fefa4" +
  "551ccd6fc9b2b7ab954f815c7264c6e51f4eaf99885a79892b1b60a0b3526e57" +
  "ba5d178d370958847eb9fd28f9ce0bc023f4148a2adfe632126769057043d3bd" +
  "8eda0df7872629f3809ef05310e83113216afe202c460fc23e789f77d1addb5e";
const SBOX = [];
for (let i = 0; i < SBOX_HEX.length; i += 2) SBOX.push(i8(parseInt(SBOX_HEX.substr(i, 2), 16)));
const INV_SBOX = new Array(256);
SBOX.forEach((v, i) => { INV_SBOX[((v % 256) + 256) % 256] = i; });

const subBytes    = (d) => d.map(b => SBOX[((b % 256) + 256) % 256]);       // _0x1556d2
const invSubBytes = (d) => d.map(b => i8(INV_SBOX[((b % 256) + 256) % 256]));

// ---- CRC32 (输出8字符小写hex) (_0x1f706f) ----
const CRC_TABLE = (() => {
  const t = [];
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
function crc32(data) {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) crc = (crc >>> 8) ^ CRC_TABLE[0xff & (crc ^ data[i])];
  crc = (0xffffffff ^ crc) >>> 0;
  const hx = b => "0123456789abcdef"[(b >>> 4) & 0xf] + "0123456789abcdef"[b & 0xf];
  return [(crc >>> 24) & 0xff, (crc >>> 16) & 0xff, (crc >>> 8) & 0xff, crc & 0xff].map(hx).join('');
}

// ---- 32位整数 → 4字节(有符号) (_0x1128f7) ----
const int4 = x => [i8((x >>> 24) & 0xff), i8((x >>> 16) & 0xff), i8((x >>> 8) & 0xff), i8(0xff & x)];
const bytes4ToInt = b => ((( ((b[0]%256+256)%256) << 24) | (((b[1]%256+256)%256) << 16) | (((b[2]%256+256)%256) << 8) | ((b[3]%256+256)%256)) >>> 0);

// ---- 填充 (_0x5dfb84) / 分块 (_0x541d79) ----
function prep(data) {
  const L = data.length;
  const pad = L % 64 <= 60 ? 64 - (L % 64) - 4 : 128 - (L % 64) - 4;
  const out = data.slice();
  for (let i = 0; i < pad; i++) out.push(0);
  return out.concat(int4(L));
}
function chunk64(d) { const o = []; for (let i = 0; i < d.length; i += 64) o.push(d.slice(i, i + 64)); return o; }

// ---- toBlock 置换 (_0x34ece2) ----
// round key "037606da0296055c"，每4个hex = [op(2hex), arg(2hex)]，
// op/arg 都经 _0x1ca2ea 解码：两个hex字符 → (hi<<4)+lo → i8
const OPS = [
  (b) => b.slice(),                                                  // 0
  (b, k) => { k = i8(k); return b.map(x => xorByte(x, k)); },         // 1 xor const
  (b, k) => { k = i8(k); return b.map(x => addByte(x, k)); },         // 2 add const
  (b, k) => { k = i8(k); let a = k; return b.map(x => xorByte(x, a++)); }, // 3 xor inc
  (b, k) => { k = i8(k); let a = k; return b.map(x => addByte(x, a++)); }, // 4 add inc
  (b, k) => { k = i8(k); let a = k; return b.map(x => xorByte(x, a--)); }, // 5 xor dec
  (b, k) => { k = i8(k); let a = k; return b.map(x => addByte(x, a--)); }, // 6 add dec
];
function decByte(two) { return i8((parseInt(two[0], 16) << 4) + parseInt(two[1], 16)); } // _0x1ca2ea
const ROUND_KEY = "037606da0296055c";
function toBlock(b) {
  for (let i = 0; i < ROUND_KEY.length; i += 4) {
    const seg = ROUND_KEY.substr(i, 4);
    const op = decByte(seg.substr(0, 2));
    const arg = decByte(seg.substr(2, 2));
    b = OPS[op](b, arg);
  }
  return b;
}
const INV_OPS = [
  (b) => b.slice(),
  (b, k) => { k = i8(k); return b.map(x => xorByte(x, k)); },
  (b, k) => { k = i8(k); return b.map(x => i8(x - k)); },
  (b, k) => { k = i8(k); let a = k; return b.map(x => xorByte(x, a++)); },
  (b, k) => { k = i8(k); let a = k; return b.map(x => i8(x - (a++))); },
  (b, k) => { k = i8(k); let a = k; return b.map(x => xorByte(x, a--)); },
  (b, k) => { k = i8(k); let a = k; return b.map(x => i8(x - (a--))); },
];
function invToBlock(b) {
  const steps = [];
  for (let i = 0; i < ROUND_KEY.length; i += 4) {
    const seg = ROUND_KEY.substr(i, 4);
    steps.push([decByte(seg.substr(0, 2)), decByte(seg.substr(2, 2))]);
  }
  for (let i = steps.length - 1; i >= 0; i--) b = INV_OPS[steps[i][0]](b, steps[i][1]);
  return b;
}

// ---- 会话密钥 (_0x37afb7 的 deriveKey 部分) ----
const SEED_KEY = "fd6a43ae25f74398b61c03c83be37449";
function fit64(a) {
  if (!a.length) return new Array(64).fill(0);
  if (a.length >= 64) return a.slice(0, 64);
  const o = []; for (let i = 0; i < 64; i++) o[i] = a[i % a.length]; return o;
}
function deriveKey(nonce) {
  let s = fit64(strBytes(SEED_KEY));
  s = xors(s, fit64(nonce));
  s = fit64(s);
  return s;
}
function genNonce() { const o = []; for (let i = 0; i < 4; i++) o[i] = i8(Math.floor(256 * Math.random())); return o; }

// ---- 私有 base64 (_0x2a136f) ----
const ENC_ALPHA = "MB.CfHUzEeJpsuGkgNwhqiSaI4Fd9L6jYKZAxn1/Vml0c5rbXRP+8tD3QTO2vWyo";
const ENC_PAD = "7";
function b64Encode(data, alpha = ENC_ALPHA, pad = ENC_PAD) {
  const arr = data.map(b => ((b % 256) + 256) % 256);
  let o = "";
  for (let i = 0; i < arr.length; i += 3) {
    const n = Math.min(3, arr.length - i);
    const b0 = arr[i], b1 = n > 1 ? arr[i + 1] : 0, b2 = n > 2 ? arr[i + 2] : 0;
    o += alpha[(b0 >> 2) & 0x3f];
    o += alpha[((b0 << 4) & 0x30) | ((b1 >> 4) & 0x0f)];
    o += n > 1 ? alpha[((b1 << 2) & 0x3c) | ((b2 >> 6) & 0x03)] : pad;
    o += n > 2 ? alpha[b2 & 0x3f] : pad;
  }
  return o;
}
function b64Decode(s, alpha = ENC_ALPHA, pad = ENC_PAD) {
  const idx = {}; for (let i = 0; i < alpha.length; i++) idx[alpha[i]] = i;
  const out = [];
  for (let i = 0; i < s.length; i += 4) {
    const g = s.substr(i, 4);
    const e = [...g].map(c => idx[c] || 0);
    const np = [...g].filter(c => c === pad).length;
    out.push(((e[0] << 2) | ((e[1] >> 4) & 3)) & 0xff);
    if (np < 2) out.push(((e[1] << 4) | ((e[2] >> 2) & 15)) & 0xff);
    if (np < 1) out.push(((e[2] << 6) | (e[3] || 0)) & 0xff);
  }
  return out;
}

// ---- bytes → 字符串 ----
function bytesToString(d) {
  return decodeURIComponent(d.map(b => "%" + (((b % 256) + 256) % 256).toString(16).padStart(2, "0")).join(""));
}

// ============== 公开 API ==============
function encrypt(text, nonce) {
  if (!nonce) nonce = genNonce();
  const data = strBytes(text);
  const sessionKey = deriveKey(nonce);
  const crc = strBytes(crc32(data.map(b => ((b % 256) + 256) % 256)));
  const blocks = chunk64(prep(data.concat(crc)));
  let out = nonce.slice();
  let chain = sessionKey;
  for (const blk of blocks) {
    const b = toBlock(blk);
    let x = xors(b, sessionKey);
    const s = shifts(x, chain);
    x = xors(s, chain);
    chain = subBytes(subBytes(x));
    out = out.concat(chain);
  }
  return b64Encode(out);
}

function decrypt(token, verifyCrc = false) {
  const raw = b64Decode(token);
  const nonce = raw.slice(0, 4).map(i8);
  const body = raw.slice(4);
  const sessionKey = deriveKey(nonce);
  let plain = [];
  let chain = sessionKey;
  for (let i = 0; i + 64 <= body.length; i += 64) {
    const cb = body.slice(i, i + 64).map(i8);
    let x = invSubBytes(invSubBytes(cb));
    const s = xors(x, chain);
    const xx = s.map((v, j) => i8(v - chain[j % chain.length]));  // unshifts
    const b = xors(xx, sessionKey);
    plain = plain.concat(invToBlock(b));
    chain = cb;
  }
  const L = bytes4ToInt(plain.slice(-4));
  const combined = plain.slice(0, L);
  const data = combined.slice(0, -8);
  const crcBytes = combined.slice(-8);
  const text = bytesToString(data);
  if (verifyCrc && bytesToString(crcBytes) !== crc32(data.map(b => ((b % 256) + 256) % 256)))
    throw new Error("CRC mismatch");
  return text;
}

module.exports = { encrypt, decrypt, b64Encode, b64Decode };

// ============== 自验证 ==============
if (require.main === module) {
  const pairs = [
    ["/Ezj1AgP", "f1PbyxAdbj8dqPq+OVTUfyqCYKsC6I2S/kvIFasXDXqO/n0ft085VUdnI+aV1hfb8y/urp2i9kYJ+1ire68/TBqz59M7"],
    ["irm0xi33", "mzhWmgD3Lvye0ERAfvTmvMJDrgEIN2+bbY1/oIKwCs6EN0.BRM5biVOgudMsJcRFo4in9USsl2KaNstLrTsN+pcGzAI7"],
    ["dvnEZWYMjIfxnvDI39uqb4ypKK4eL6m6", "gn6ergsoPSRXf9ah.BzE/mCtD9EGMmHaKgpZnLMPvZrQsDFl+PY4w0YeWudurQ4oD0yIlwvNJczjNgS/tRPRvjfhFHs7"],
  ];
  let pass = 0;
  for (const [pt, ct] of pairs) {
    const nonce = b64Decode(ct).slice(0, 4).map(i8);  // 用密文里的nonce复算以对齐
    const my = encrypt(pt, nonce);
    const encOk = my === ct;
    const dec = decrypt(ct);
    const decOk = dec === pt;
    if (encOk && decOk) pass++;
    console.log(`${encOk ? 'OK' : 'XX'} encrypt  ${decOk ? 'OK' : 'XX'} decrypt   pt=${JSON.stringify(pt)}`);
  }
  console.log(`\n${pass}/${pairs.length} passed`);
  // 随机 nonce 的往返自洽
  const rt = "hello,world:123,-4,5,1";
  console.log("\nrandom-nonce roundtrip:", decrypt(encrypt(rt)) === rt);
}
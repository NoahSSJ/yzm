/*
 * 完整复现 core-optimi 的 cb-token 生成函数 _0x62692()
 *
 *   1) uuid(32)                  生成 32 位随机串
 *   2) 把 code="vfnv46" 的 6 个字符塞进固定位置 pos=[1,10,12,13,26,31]
 *   3) 整串过非标准 "aes" 加密返回
 *
 * 单文件、无依赖：node 直接跑，或浏览器 <script> 引入。
 */

/*
 * Reverse-engineered "aes" cipher from the core-optimi (NECaptcha / Yidun) bundle.
 *
 * NOT standard AES. A custom 64-byte-block cipher that borrows AES-style pieces
 * (256-byte S-box, round keys, XOR/add rounds), adds a CRC32 integrity tag,
 * a per-call 4-byte random nonce, and a private-alphabet Base64 output.
 *
 * Works in the unsigned 0..255 domain; the original uses a signed-byte wrap, but
 * since every result is masked the byte patterns and Base64 output are identical.
 *
 * Runs in Node and the browser. Node entrypoint at the bottom verifies it against
 * a real production token.
 */

// ---------------------------------------------------------------------------
// Constants (lifted verbatim from the bundle, module 0x1b)
// ---------------------------------------------------------------------------
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
for (let i = 0; i < SBOX_HEX.length; i += 2) SBOX.push(parseInt(SBOX_HEX.substr(i, 2), 16));
const INV_SBOX = new Array(256);
SBOX.forEach((v, i) => { INV_SBOX[v] = i; });

const SEED_KEY = "fd6a43ae25f74398b61c03c83be37449"; // used as a STRING, not hex-decoded
const ROUND_KEY = "037606da0296055c";                // the toBlock "program"
const B64_ALPHABET = "MB.CfHUzEeJpsuGkgNwhqiSaI4Fd9L6jYKZAxn1/Vml0c5rbXRP+8tD3QTO2vWyo";
const B64_PAD = "7";
const B64_INDEX = {};
for (let i = 0; i < B64_ALPHABET.length; i++) B64_INDEX[B64_ALPHABET[i]] = i;

const BLOCK = 64;

// ---------------------------------------------------------------------------
// Primitive byte ops
// ---------------------------------------------------------------------------
const add = (a, b) => (a + b) & 0xff;   // the misnamed "shift"
const sub = (a, b) => (a - b) & 0xff;   // inverse of add
const xor = (a, b) => (a ^ b) & 0xff;

const shifts   = (d, k) => d.map((v, i) => add(v, k[i % k.length]));
const unshifts = (d, k) => d.map((v, i) => sub(v, k[i % k.length]));
const xors     = (d, k) => d.map((v, i) => xor(v, k[i % k.length]));

const subBytes    = (d) => d.map((b) => SBOX[b]);
const invSubBytes = (d) => d.map((b) => INV_SBOX[b]);

// ---------------------------------------------------------------------------
// String <-> bytes (mirrors stringToBytes / bytesToString via encode/decodeURIComponent)
// ---------------------------------------------------------------------------
function stringToBytes(s) {
  const enc = encodeURIComponent(s);
  const out = [];
  for (let i = 0; i < enc.length; i++) {
    if (enc[i] === "%") { out.push(parseInt(enc.substr(i + 1, 2), 16)); i += 2; }
    else out.push(enc.charCodeAt(i) & 0xff);
  }
  return out;
}
function bytesToString(d) {
  return decodeURIComponent(d.map((b) => "%" + b.toString(16).padStart(2, "0")).join(""));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const intToBytes = (x) => [(x >>> 24) & 0xff, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff];
const bytesToInt = (b) => ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;

// standard CRC32 (the bundle ships the same reflected table) -> 8-char lowercase hex
function genCrc32(data) {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ data[i]) & 0xff];
  }
  crc = (0xffffffff ^ crc) >>> 0;
  return crc.toString(16).padStart(8, "0");
}
const CRC_TABLE = (() => {
  const t = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function fitTo64(arr) {
  if (!arr.length) return new Array(BLOCK).fill(0);
  if (arr.length >= BLOCK) return arr.slice(0, BLOCK);
  const out = [];
  for (let i = 0; i < BLOCK; i++) out[i] = arr[i % arr.length];
  return out;
}

// ---------------------------------------------------------------------------
// toBlock: permutation driven by ROUND_KEY (each 4 hex = op, arg)
// ---------------------------------------------------------------------------
const OPS = [
  (b) => b.slice(),                                          // 0 identity
  (b, k) => b.map((x) => xor(x, k)),                         // 1 xor const
  (b, k) => b.map((x) => add(x, k)),                         // 2 add const
  (b, k) => b.map((x, i) => xor(x, (k + i) & 0xff)),         // 3 xor inc
  (b, k) => b.map((x, i) => add(x, (k + i) & 0xff)),         // 4 add inc
  (b, k) => b.map((x, i) => xor(x, (k - i) & 0xff)),         // 5 xor dec
  (b, k) => b.map((x, i) => add(x, (k - i) & 0xff)),         // 6 add dec
];
const INV_OPS = [
  (b) => b.slice(),
  (b, k) => b.map((x) => xor(x, k)),                         // xor self-inverse
  (b, k) => b.map((x) => sub(x, k)),                         // add -> sub
  (b, k) => b.map((x, i) => xor(x, (k + i) & 0xff)),
  (b, k) => b.map((x, i) => sub(x, (k + i) & 0xff)),
  (b, k) => b.map((x, i) => xor(x, (k - i) & 0xff)),
  (b, k) => b.map((x, i) => sub(x, (k - i) & 0xff)),
];
function roundProgram() {
  const steps = [];
  for (let i = 0; i < ROUND_KEY.length; i += 4) {
    steps.push([parseInt(ROUND_KEY.substr(i, 2), 16), parseInt(ROUND_KEY.substr(i + 2, 2), 16)]);
  }
  return steps;
}
function toBlock(b) {
  for (const [op, arg] of roundProgram()) b = OPS[op](b, arg);
  return b;
}
function invToBlock(b) {
  for (const [op, arg] of roundProgram().reverse()) b = INV_OPS[op](b, arg);
  return b;
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------
function deriveKey(nonce) {
  let seed = stringToBytes(SEED_KEY);   // 32 ASCII bytes of the hex string
  seed = fitTo64(seed);
  seed = xors(seed, fitTo64(nonce));
  seed = fitTo64(seed);
  return seed;                           // 64-byte session key
}

// ---------------------------------------------------------------------------
// Padding / chunking
// ---------------------------------------------------------------------------
function prep(data) {
  if (!data.length) return new Array(BLOCK).fill(0);
  const L = data.length;
  const pad = L % BLOCK <= 60 ? BLOCK - (L % BLOCK) - 4 : 2 * BLOCK - (L % BLOCK) - 4;
  return data.concat(new Array(pad).fill(0)).concat(intToBytes(L));
}
function chunk64(data) {
  const out = [];
  for (let i = 0; i < data.length; i += BLOCK) out.push(data.slice(i, i + BLOCK));
  return out;
}

// ---------------------------------------------------------------------------
// Private-alphabet Base64
// ---------------------------------------------------------------------------
function b64Encode(data) {
  let out = "";
  for (let i = 0; i < data.length; i += 3) {
    const n = Math.min(3, data.length - i);
    const b0 = data[i], b1 = n > 1 ? data[i + 1] : 0, b2 = n > 2 ? data[i + 2] : 0;
    out += B64_ALPHABET[(b0 >> 2) & 0x3f];
    out += B64_ALPHABET[((b0 << 4) & 0x30) + ((b1 >> 4) & 0x0f)];
    out += n > 1 ? B64_ALPHABET[((b1 << 2) & 0x3c) + ((b2 >> 6) & 0x03)] : B64_PAD;
    out += n > 2 ? B64_ALPHABET[b2 & 0x3f] : B64_PAD;
  }
  return out;
}
function b64Decode(s) {
  const out = [];
  for (let i = 0; i < s.length; i += 4) {
    const g = s.substr(i, 4);
    const idx = [...g].map((c) => B64_INDEX[c] || 0);
    const nPad = (g.match(/7/g) || []).length;
    out.push(((idx[0] << 2) & 0xff) | ((idx[1] >> 4) & 0x03));
    if (nPad < 2) out.push(((idx[1] << 4) & 0xff) | ((idx[2] >> 2) & 0x0f));
    if (nPad < 1) out.push(((idx[2] << 6) & 0xff) | (idx[3] & 0x3f));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
function encrypt(text, nonce) {
  if (!nonce) nonce = [0, 1, 2, 3].map(() => Math.floor(Math.random() * 256));
  const data = stringToBytes(text);
  const sessionKey = deriveKey(nonce);
  const crc = stringToBytes(genCrc32(data));
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

function decrypt(token, verifyCrc = true) {
  const raw = b64Decode(token);
  const nonce = raw.slice(0, 4);
  const body = raw.slice(4);
  const sessionKey = deriveKey(nonce);

  let plain = [];
  let chain = sessionKey;
  for (let i = 0; i < body.length; i += BLOCK) {
    const cipherBlock = body.slice(i, i + BLOCK);
    let x = invSubBytes(invSubBytes(cipherBlock));
    const s = xors(x, chain);
    const xx = unshifts(s, chain);
    const b = xors(xx, sessionKey);
    plain = plain.concat(invToBlock(b));
    chain = cipherBlock;
  }

  const L = bytesToInt(plain.slice(-4));
  const combined = plain.slice(0, L);
  const data = combined.slice(0, -8);
  const crcBytes = combined.slice(-8);
  const text = bytesToString(data);
  if (verifyCrc && bytesToString(crcBytes) !== genCrc32(data)) {
    throw new Error("CRC mismatch");
  }
  return text;
}

// ===========================================================================
// uuid（复现自 core-optimi 的 uuid 函数）
// ===========================================================================
var UUID_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".split("");
function uuid(len, radix) {
  var chars = UUID_CHARS, arr = [], i;
  radix = radix || chars.length;
  if (len) {
    for (i = 0; i < len; i++) arr[i] = chars[0 | (Math.random() * radix)];
  } else {
    var r;
    arr[8] = arr[13] = arr[18] = arr[23] = "-";
    arr[14] = "4";
    for (i = 0; i < 36; i++) {
      if (!arr[i]) { r = 0 | (Math.random() * 16); arr[i] = chars[i === 19 ? (r & 0x3) | 0x8 : r]; }
    }
  }
  return arr.join("");
}

// ===========================================================================
// cb-token 生成（复现 _0x62692）
// ===========================================================================
function makeCbToken() {
  var conf = {
    suffix: "m25b40",                  // 仅作版本标识，函数里实际没用到
    code:   "vfnv46",                  // 要嵌入的暗记
    pos:    [1, 10, 12, 13, 26, 31]    // 嵌入位置
  };
  var code = conf.code;
  var pos  = conf.pos;
  var str  = uuid(32);                 // 32 位随机底串

  if (code && pos && Array.isArray(pos)) {
    var chars = str.split("");
    for (var i = 0; i < pos.length; i++) chars[pos[i]] = code.charAt(i);
    str = chars.join("");
  }
  return encrypt(str);                 // 非标准 aes 加密（即源码的 _0xb77ce）
}

// ===========================================================================
// 运行区
// ===========================================================================
// var cb = makeCbToken();
// console.log("cb token:", cb);

// // 解密回看，验证底串确实埋了 vfnv46（位置 1,10,12,13,26,31）
// var raw = decrypt(cb);
// console.log("解密底串:", raw);
// var pos = [1, 10, 12, 13, 26, 31];
// console.log("提取暗记:", pos.map(function (p) { return raw[p]; }).join(""));
// console.log(encrypt('ieIuvwZ/i/Wv:/pXin/cx/A9zr4u\\/iOk/p33:/pXgn/cx/Auzvvv\\/Agk/p33:icXUn/cxipLz6vOR/Agk/p33:/iZ1n/cxiiLz6vORip+k/p33:/pzgn/cxicDz6vORiA+k/p33:/crin/cx/igz6vOR1p9k/p33:iiNqnpX//wWjr4u6iwW\\:/eIuriI10pL\\vvg6Uiq3:/eIuriNX0pL\\vvDOUiq3:iczqnpX0ieWjr4+\\/OW\\:/cixn/cg/cOz6vvP/cLk/p33:/cjNn/cgicvz6vvPiivk/p33:/piNn/cX/cgz6vvPicvk/p33:/pjin/cXii/z6vvPiA+k/p33:/iNin/c0iAOz6vvP1pLk/p33:/ir1n/c/ieWjr4/\\iwW\\:/ipxn/cgx/Wjr4/vi/W\\:/ipNn/c0/eWjr4/nieW\\:/ipNn/cx0pL\\vE/rUiq3:/ip/niz2xpOn6vgk/p33:/ipgniA2xpOPrv7k/p33:/irxnip00pL\\v4O\\Uiq3:/irXnip00pL\\v4vpUiq3:/izXnip00pL\\v4+rUiq3:/iXxnii2xpOPv4+k/p33:/pZxnip2xpOP6g9k/p33:/pjin/cx0pL\\6vuRUiq3:/pr/n/c/0pL\\6vOnUiq3:/pNNn/c0i/Wjr4Dv1OW\\:/pign/c0iwWjr4Dp/wW\\:/ccxn/c0/eWjr4DH//W\\:/cZgn/c0x/Wjr4DRi/W\\:/cj/n/cXiwWjr4L\\/OW\\:/crNn/cX/eWjr4Lr1/W\\:/cN/n/cgi/Wjr4LP/OW\\:/ci/n/cgieWjr4LO//W\\:/ci0n/cgiwWjr4LR/eW\\:/cign/cgiwWjvvun/OW\\:/cXNn/cgiwWjvvuPi/W\\:/cX/n/cgiwWjvv9viwW\\:/cXXn/cgiwWjvv9P//W\\:1cNqnpqg0pLprg/OUiq3:1Arqnpqg0pLprgDvUiq3:iijqnpqx0pLprgLHUiq3:iiNqnpqx0pLprEgHUiq3:ipZqnpqx0pLpr4urUiq3:ipjqnpqx0pLpr4O\\Uiq3:ipZqnpqx0pLpvg7nUiq3:iiXqnpqx0pLpvEu6Uiq3'))

// validate_generator.js   保存后直接 node validate_generator.js
function i8(x) {
  x = ((x % 256) + 256) % 256;
  return x > 127 ? x - 256 : x;
}

function strBytes(s) {
  s = encodeURIComponent(s);
  const out = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '%') {
      if (i + 2 < s.length) {
        out.push(i8(parseInt(s.substr(i + 1, 2), 16)));
        i += 2;
      }
    } else {
      out.push(i8(s.charCodeAt(i)));
    }
  }
  return out;
}

// _0x127d20 字符替换
function replaceSpecial(str) {
  if (typeof str !== 'string') return '';
  const map = {'\\': '-', '/': '_', '+': '*'};
  return str.replace(/[\\/+]/g, m => map[m]);
}

// ====================== 下面是参考代码核心部分（已精简可用） ======================
const CRC_TABLE = (() => {
  const t = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? (0xedb88320 ^ (c >>> 1)) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(data) {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) crc = (crc >>> 8) ^ CRC_TABLE[0xff & (crc ^ data[i])];
  crc = ~crc >>> 0;
  return [(crc >>> 24)&0xff, (crc>>>16)&0xff, (crc>>>8)&0xff, crc&0xff];
}

const SBOX_HEX = "a7be3f3933fa8c5fcf86c4b6908b569ba1e26c1a6d7cfbf60ae4b00e074a194dac4b73e7f898541159a39d08183b76eedee3ed341e6685d2357440158394b1ff03a9004cbbb5ca7dcb7f41489a16e03dcc9c71eb3c9796685b1d01b4d56193a6e1f1a2470445c191ae49c5d82765dc82c350f263387a24a502fcbf442e2dddaad0e936d9ea22b89275307b42518fbc3a626ba806d4ecd6d725f50cc8c72fefa4551ccd6fc9b2b7ab954f815c7264c6e51f4eaf99885a79892b1b60a0b3526e57ba5d178d370958847eb9fd28f9ce0bc023f4148a2adfe632126769057043d3bd8eda0df7872629f3809ef05310e83113216afe202c460fc23e789f77d1addb5e";
const SBOX = [];
for (let i = 0; i < SBOX_HEX.length; i += 2) SBOX.push(i8(parseInt(SBOX_HEX.substr(i, 2), 16)));

const subBytes = (d) => d.map(b => SBOX[((b % 256) + 256) % 256]);

const xorByte = (a, b) => i8(i8(a) ^ i8(b));
const addByte = (a, b) => i8(a + b);
const xors = (d, k) => d.map((v, i) => xorByte(v, k[i % k.length]));
const shifts = (d, k) => d.map((v, i) => addByte(v, k[i % k.length]));

const ROUND_KEY = "037606da0296055c";
const OPS = [
  (b) => b.slice(),
  (b, k) => { k = i8(k); return b.map(x => xorByte(x, k)); },
  (b, k) => { k = i8(k); return b.map(x => addByte(x, k)); },
  (b, k) => { k = i8(k); let a = k; return b.map(x => xorByte(x, a++)); },
  (b, k) => { k = i8(k); let a = k; return b.map(x => addByte(x, a++)); },
  (b, k) => { k = i8(k); let a = k; return b.map(x => xorByte(x, a--)); },
  (b, k) => { k = i8(k); let a = k; return b.map(x => addByte(x, a--)); },
];

function decByte(two) { return i8((parseInt(two[0], 16) << 4) + parseInt(two[1], 16)); }

function toBlock(b) {
  let res = b.slice();
  for (let i = 0; i < ROUND_KEY.length; i += 4) {
    const seg = ROUND_KEY.substr(i, 4);
    const op = decByte(seg.substr(0, 2));
    const arg = decByte(seg.substr(2, 2));
    res = OPS[op](res, arg);
  }
  return res;
}

const SEED_KEY = "fd6a43ae25f74398b61c03c83be37449";
function fit64(a) {
  if (!a.length) return new Array(64).fill(0);
  if (a.length >= 64) return a.slice(0, 64);
  const o = [];
  for (let i = 0; i < 64; i++) o[i] = a[i % a.length];
  return o;
}

function deriveKey(nonce) {
  let s = fit64(strBytes(SEED_KEY));
  s = xors(s, fit64(nonce));
  return fit64(s);
}

const ENC_ALPHA = "MB.CfHUzEeJpsuGkgNwhqiSaI4Fd9L6jYKZAxn1/Vml0c5rbXRP+8tD3QTO2vWyo";
const ENC_PAD = "7";

function b64Encode(data) {
  const arr = data.map(b => ((b % 256) + 256) % 256);
  let o = "";
  for (let i = 0; i < arr.length; i += 3) {
    const n = Math.min(3, arr.length - i);
    const b0 = arr[i], b1 = n > 1 ? arr[i + 1] : 0, b2 = n > 2 ? arr[i + 2] : 0;
    o += ENC_ALPHA[(b0 >> 2) & 0x3f];
    o += ENC_ALPHA[((b0 << 4) & 0x30) | ((b1 >> 4) & 0x0f)];
    o += n > 1 ? ENC_ALPHA[((b1 << 2) & 0x3c) | ((b2 >> 6) & 0x03)] : ENC_PAD;
    o += n > 2 ? ENC_ALPHA[b2 & 0x3f] : ENC_PAD;
  }
  return o;
}

// _0xb77ce 主函数（简化版，核心逻辑）
function b77ce(inputStr) {
  const data = strBytes(inputStr);
  const nonce = [0x12, 0x34, 0x56, 0x78]; // 实际应从 _0x37afb7 生成，这里先用固定值测试，可后续优化
  const sessionKey = deriveKey(nonce);
  const crc = crc32(data.map(b => ((b % 256) + 256) % 256));
  const padded = data.concat(crc);
  const blocks = [];
  for (let i = 0; i < padded.length; i += 64) {
    blocks.push(padded.slice(i, i + 64));
  }
  let out = nonce.slice();
  let chain = sessionKey;
  for (let blk of blocks) {
    while (blk.length < 64) blk.push(0);
    let b = toBlock(blk);
    let x = xors(b, sessionKey);
    const s = shifts(x, chain);
    x = xors(s, chain);
    chain = subBytes(subBytes(x));
    out = out.concat(chain);
  }
  return b64Encode(out);
}

// ====================== 测试 ======================
const shortValidate = "smU5uUd8C4R6FE5occftQk3OC9zFQ3qvmQJlX0BjwKesaqK6BJ0Z0NtdiTPzf1li5AnFVmqv4ueCJqYCig55fjXMs136VcByxFqjWekRoiPTx2aTqxbgTfQdZ9sPKXLJ2KXWtAWhTc6HVBzl/S/2m9o3i60gnShYdnlxJ9wF6cc=";
const fingerprint = "Cv/eunqBTDEzhN0tijp4ai+dRwqcj8LKilkHKjG3ewS+YBlS90HCZ8RT5tWJRaSapGx5ctTdZ1xn5c82dt6/LcIAwUBkJLXE3QyI\\4G3iTi3uKOXMg3MAyih1A8CkTDXD4KtDhLCByZvdOinr6Wr4JI\\DUNHCj2IKKJMcT2gObR8/aYu:1782243703788";
const prefix = "NANP";

const raw = shortValidate + '::' + fingerprint;
console.log("raw length:", raw.length);

const temp = b77ce(raw);
const hash = replaceSpecial(temp);
const finalValidate = prefix + '_' + hash + '77_v_i_1';

console.log("最终 validate:");
console.log(finalValidate);
/*
 * gdit-crypto.js —— 纯 JS、零依赖的“内容加密/解密”模块。
 *
 * 重要说明（请务必理解）：
 *   这是纯前端(静态)方案。浏览器必须先执行 JS 才能解密渲染内容，
 *   因此任何懂开发工具的人都能改 JS 绕过校验。本模块的作用只是：
 *     1) 让真正的资料正文(姓名/学号/班级…)在源码与文件里不出现明文；
 *     2) 必须输入正确密码才能得到明文。
 *   它【不能】提供真正的安全保护，仅用于提高“查看门槛”。
 *
 * 算法：
 *   密钥 = PBKDF2-HMAC-SHA256(password, salt, iterations, 32字节)
 *   密钥流 = HMAC-SHA256(密钥, 计数器0,1,2,…) 产生的伪随机字节
 *   密文 = 明文(带标记前缀) XOR 密钥流
 *   明文(UTF-8) 以固定标记开头，用于在校验错误时识别“密码错误”。
 */
(function (root) {
  'use strict';

  var MARKER = '__GDIT_OK__';
  var DEFAULT_ITER = 20000;
  var KEY_LEN = 32; // 派生密钥长度 32 字节

  /* ---------------- SHA-256 ---------------- */

  var K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(bytes) {
    var l = bytes.length;
    var bitLenHi = Math.floor(l / 0x20000000); // 总比特数的高32位
    var bitLenLo = (l << 3) >>> 0;             // 总比特数的低32位
    var paddedLen = (((l + 1 + 8 + 63) >> 6) << 6); // 向上取整到 64 的倍数
    var msg = new Uint8Array(paddedLen);
    msg.set(bytes);
    msg[l] = 0x80;
    var dv = new DataView(msg.buffer);
    dv.setUint32(paddedLen - 8, bitLenHi);
    dv.setUint32(paddedLen - 4, bitLenLo);

    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var w = new Uint32Array(64);

    for (var base = 0; base < paddedLen; base += 64) {
      var i, t;
      for (i = 0; i < 16; i++) w[i] = dv.getUint32(base + i * 4);
      for (i = 16; i < 64; i++) {
        var w15 = w[i - 15], w2 = w[i - 2];
        var s0 = (w15 >>> 7) ^ (w15 >>> 18) ^ (w15 >>> 3);
        var s1 = (w2 >>> 17) ^ (w2 >>> 19) ^ (w2 >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ ((~e) & g);
        var temp1 = (h + S1 + ch + K256[t] + w[t]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + temp1) | 0; d = c; c = b; b = a; a = (temp1 + temp2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) {
      out[i * 4] = (H[i] >>> 24) & 255;
      out[i * 4 + 1] = (H[i] >>> 16) & 255;
      out[i * 4 + 2] = (H[i] >>> 8) & 255;
      out[i * 4 + 3] = H[i] & 255;
    }
    return out;
  }

  /* ---------------- HMAC-SHA256 ---------------- */

  function hmacSha256(key, msg) {
    var keyBytes = (key.length > 64) ? sha256(key) : key;
    var ipad = new Uint8Array(64), opad = new Uint8Array(64);
    for (var i = 0; i < 64; i++) {
      var kk = (i < keyBytes.length) ? keyBytes[i] : 0;
      ipad[i] = kk ^ 0x36;
      opad[i] = kk ^ 0x5c;
    }
    var inner = new Uint8Array(64 + msg.length);
    inner.set(ipad, 0);
    inner.set(msg, 64);
    var ih = sha256(inner);
    var outer = new Uint8Array(64 + ih.length);
    outer.set(opad, 0);
    outer.set(ih, 64);
    return sha256(outer);
  }

  /* ---------------- PBKDF2-HMAC-SHA256 ---------------- */

  function pbkdf2(password, salt, iterations, dkLen) {
    var out = new Uint8Array(dkLen);
    var numBlocks = Math.ceil(dkLen / 32);
    for (var block = 1; block <= numBlocks; block++) {
      var blockMsg = new Uint8Array(salt.length + 4);
      blockMsg.set(salt, 0);
      blockMsg[salt.length] = (block >>> 24) & 255;
      blockMsg[salt.length + 1] = (block >>> 16) & 255;
      blockMsg[salt.length + 2] = (block >>> 8) & 255;
      blockMsg[salt.length + 3] = block & 255;
      var U = hmacSha256(password, blockMsg);
      var T = new Uint8Array(U);
      for (var r = 1; r < iterations; r++) {
        U = hmacSha256(password, U);
        for (var m = 0; m < 32; m++) T[m] ^= U[m];
      }
      var start = (block - 1) * 32;
      for (var q = 0; q < 32 && (start + q) < dkLen; q++) out[start + q] = T[q];
    }
    return out;
  }

  /* ---------------- 密钥流(计数器模式 HMAC) ---------------- */

  function stretch(key32, len) {
    var out = new Uint8Array(len);
    var cnt = new Uint8Array(4);
    var counter = 0, pos = 0;
    while (pos < len) {
      cnt[0] = (counter >>> 24) & 255;
      cnt[1] = (counter >>> 16) & 255;
      cnt[2] = (counter >>> 8) & 255;
      cnt[3] = counter & 255;
      var h = hmacSha256(key32, cnt);
      for (var j = 0; j < 32 && pos < len; j++) out[pos++] = h[j];
      counter++;
    }
    return out;
  }

  /* ---------------- UTF-8 ---------------- */

  function utf8Encode(str) {
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
      var code = str.charCodeAt(i);
      if (code >= 0xD800 && code <= 0xDBFF && i + 1 < str.length) {
        var lo = str.charCodeAt(i + 1);
        if (lo >= 0xDC00 && lo <= 0xDFFF) {
          code = 0x10000 + ((code - 0xD800) << 10) + (lo - 0xDC00);
          i++;
        }
      }
      if (code < 0x80) bytes.push(code);
      else if (code < 0x800) bytes.push(0xC0 | (code >> 6), 0x80 | (code & 63));
      else if (code < 0x10000) bytes.push(0xE0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
      else bytes.push(0xF0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
    }
    return Uint8Array.from(bytes);
  }

  function utf8DecodeStrict(bytes) {
    function fail() { throw new Error('BAD_UTF8'); }
    var out = [];
    var i = 0, n = bytes.length;
    while (i < n) {
      var b0 = bytes[i], cp, need;
      if (b0 < 0x80) { out.push(b0); i++; continue; }
      else if ((b0 & 0xE0) === 0xC0) { need = 1; cp = b0 & 0x1F; }
      else if ((b0 & 0xF0) === 0xE0) { need = 2; cp = b0 & 0x0F; }
      else if ((b0 & 0xF8) === 0xF0) { need = 3; cp = b0 & 0x07; }
      else fail();
      if (i + need >= n) fail();
      for (var j = 1; j <= need; j++) {
        var bn = bytes[i + j];
        if ((bn & 0xC0) !== 0x80) fail();
        cp = (cp << 6) | (bn & 0x3F);
      }
      if ((need === 1 && cp < 0x80) || (need === 2 && cp < 0x800) || (need === 3 && cp < 0x10000)) fail();
      if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) fail();
      i += need + 1;
      if (cp <= 0xFFFF) out.push(cp);
      else {
        cp -= 0x10000;
        out.push(0xD800 + ((cp >> 10) & 0x3FF), 0xDC00 + (cp & 0x3FF));
      }
    }
    return String.fromCharCode.apply(null, out);
  }

  /* ---------------- hex / base64 ---------------- */

  function bytesToHex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) {
      var h = b[i].toString(16);
      s += (h.length < 2) ? '0' + h : h;
    }
    return s;
  }

  function hexToBytes(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.substr(i, 2), 16);
    return out;
  }

  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  function bytesToBase64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i += 3) {
      var b0 = bytes[i];
      var b1 = (i + 1 < bytes.length) ? bytes[i + 1] : -1;
      var b2 = (i + 2 < bytes.length) ? bytes[i + 2] : -1;
      s += B64.charAt(b0 >> 2);
      s += B64.charAt(((b0 & 3) << 4) | (b1 >= 0 ? (b1 >> 4) : 0));
      s += (b1 >= 0) ? B64.charAt(((b1 & 15) << 2) | (b2 >= 0 ? (b2 >> 6) : 0)) : '=';
      s += (b2 >= 0) ? B64.charAt(b2 & 63) : '=';
    }
    return s;
  }

  function base64ToBytes(s) {
    var lut = {};
    for (var i = 0; i < 64; i++) lut[B64.charAt(i)] = i;
    var clean = s.replace(/[\r\n]/g, '');
    var out = [];
    var n = clean.length;
    for (i = 0; i < n; i += 4) {
      var c0 = lut[clean.charAt(i)], c1 = lut[clean.charAt(i + 1)];
      if (c0 === undefined || c1 === undefined) throw new Error('BAD_B64');
      var has2 = (i + 2 < n) && clean.charAt(i + 2) !== '=';
      var has3 = (i + 3 < n) && clean.charAt(i + 3) !== '=';
      var c2 = has2 ? lut[clean.charAt(i + 2)] : 0;
      var c3 = has3 ? lut[clean.charAt(i + 3)] : 0;
      out.push((c0 << 2) | (c1 >> 4));
      if (has2) out.push(((c1 & 15) << 4) | (c2 >> 2));
      if (has3) out.push(((c2 & 3) << 6) | c3);
    }
    return Uint8Array.from(out);
  }

  /* ---------------- 加密 / 解密 ---------------- */

  function deriveKey(password, saltHex, iterations) {
    return pbkdf2(utf8Encode(password), hexToBytes(saltHex), iterations, KEY_LEN);
  }

  function encrypt(plainText, password, saltHex, iterations) {
    var data = utf8Encode(MARKER + plainText);
    var key = deriveKey(password, saltHex, iterations);
    var ks = stretch(key, data.length);
    var cipher = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i++) cipher[i] = data[i] ^ ks[i];
    return bytesToBase64(cipher);
  }

  function decrypt(cipherB64, password, saltHex, iterations) {
    var cipher = base64ToBytes(cipherB64);
    var key = deriveKey(password, saltHex, iterations);
    var ks = stretch(key, cipher.length);
    var data = new Uint8Array(cipher.length);
    for (var i = 0; i < cipher.length; i++) data[i] = cipher[i] ^ ks[i];
    var text = utf8DecodeStrict(data);
    if (text.slice(0, MARKER.length) !== MARKER) throw new Error('BAD_PASSWORD');
    return text.slice(MARKER.length);
  }

  /* ---------------- 导出 ---------------- */

  var api = {
    MARKER: MARKER,
    DEFAULT_ITER: DEFAULT_ITER,
    utf8Encode: utf8Encode,
    utf8DecodeStrict: utf8DecodeStrict,
    bytesToHex: bytesToHex,
    hexToBytes: hexToBytes,
    bytesToBase64: bytesToBase64,
    base64ToBytes: base64ToBytes,
    sha256: sha256,
    hmacSha256: hmacSha256,
    pbkdf2: pbkdf2,
    stretch: stretch,
    deriveKey: deriveKey,
    encrypt: encrypt,
    decrypt: decrypt
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GditCrypto = api;
})(typeof self !== 'undefined' ? self : this);

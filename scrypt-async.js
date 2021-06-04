/*!
 * Fast "async" scrypt implementation in JavaScript.
 *
 * Copyright (c) 2013-2016 Dmitry Chestnykh
 * Copyright (c) 2021 sum305 <https://github.com/sum305>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * scrypt(password, salt, opts, callback)
 *
 * where
 *
 * password and salt are arrays of bytes (Array or Uint8Array)
 * opts is
 *
 * {
 *    N:      // CPU/memory cost parameter, must be power of two
 *            // (alternatively, you can specify logN)
 *    r:      // block size
 *    p:      // parallelization parameter
 *    dkLen:  // length of derived key
 *    interruptStep: // optional, steps to split calculations
 * }
 *
 * Derives a key from password and salt and calls callback
 * with derived key as the only argument.
 *
 * Calculations are interrupted with setImmediate (or zero setTimeout) at the
 * given interruptSteps to avoid freezing the browser. If it's undefined or zero,
 * the callback is called immediately after the calculation, avoiding setImmediate.
 */
function scrypt(password, salt, opts, callback) {
  'use strict';

  function SHA256(m) {
    /** @const */ var K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
      0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
      0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
      0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
      0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
      0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
      0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
      0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
        h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19,
        w = new Array(64);

    function blocks(p) {
      var off = 0, len = p.length;
      while (len >= 64) {
        var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7,
            u, i, j, t1, t2;

        for (i = 0; i < 16; i++) {
          j = off + i*4;
          w[i] = ((p[j+0] & 0xff)<<24) | ((p[j+1] & 0xff)<<16) |
                 ((p[j+2] & 0xff)<<8)  | ((p[j+3] & 0xff)<<0);
        }

        for (i = 16; i < 64; i++) {
          u = w[i-2];
          t1 = ((u>>>17) | (u<<(32-17))) ^ ((u>>>19) | (u<<(32-19))) ^ (u>>>10);

          u = w[i-15];
          t2 = ((u>>>7) | (u<<(32-7))) ^ ((u>>>18) | (u<<(32-18))) ^ (u>>>3);

          w[i] = (((t1 + w[i-7]) | 0) + ((t2 + w[i-16]) | 0)) | 0;
        }

        for (i = 0; i < 64; i++) {
          t1 = ((((((e>>>6) | (e<<(32-6))) ^ ((e>>>11) | (e<<(32-11))) ^
               ((e>>>25) | (e<<(32-25)))) + ((e & f) ^ (~e & g))) | 0) +
               ((h + ((K[i] + w[i]) | 0)) | 0)) | 0;

          t2 = ((((a>>>2) | (a<<(32-2))) ^ ((a>>>13) | (a<<(32-13))) ^
               ((a>>>22) | (a<<(32-22)))) + ((a & b) ^ (a & c) ^ (b & c))) | 0;

          h = g;
          g = f;
          f = e;
          e = (d + t1) | 0;
          d = c;
          c = b;
          b = a;
          a = (t1 + t2) | 0;
        }

        h0 = (h0 + a) | 0;
        h1 = (h1 + b) | 0;
        h2 = (h2 + c) | 0;
        h3 = (h3 + d) | 0;
        h4 = (h4 + e) | 0;
        h5 = (h5 + f) | 0;
        h6 = (h6 + g) | 0;
        h7 = (h7 + h) | 0;

        off += 64;
        len -= 64;
      }
    }

    blocks(m);

    var i, bytesLeft = m.length % 64,
        bitLenHi = (m.length / 0x20000000) | 0,
        bitLenLo = m.length << 3,
        numZeros = (bytesLeft < 56) ? 56 : 120,
        p = Array.prototype.slice.call(m, m.length - bytesLeft);

    p.push(0x80);
    for (i = bytesLeft + 1; i < numZeros; i++) p.push(0);
    p.push((bitLenHi>>>24) & 0xff);
    p.push((bitLenHi>>>16) & 0xff);
    p.push((bitLenHi>>>8)  & 0xff);
    p.push((bitLenHi>>>0)  & 0xff);
    p.push((bitLenLo>>>24) & 0xff);
    p.push((bitLenLo>>>16) & 0xff);
    p.push((bitLenLo>>>8)  & 0xff);
    p.push((bitLenLo>>>0)  & 0xff);

    blocks(p);

    return [
      (h0>>>24) & 0xff, (h0>>>16) & 0xff, (h0>>>8) & 0xff, (h0>>>0) & 0xff,
      (h1>>>24) & 0xff, (h1>>>16) & 0xff, (h1>>>8) & 0xff, (h1>>>0) & 0xff,
      (h2>>>24) & 0xff, (h2>>>16) & 0xff, (h2>>>8) & 0xff, (h2>>>0) & 0xff,
      (h3>>>24) & 0xff, (h3>>>16) & 0xff, (h3>>>8) & 0xff, (h3>>>0) & 0xff,
      (h4>>>24) & 0xff, (h4>>>16) & 0xff, (h4>>>8) & 0xff, (h4>>>0) & 0xff,
      (h5>>>24) & 0xff, (h5>>>16) & 0xff, (h5>>>8) & 0xff, (h5>>>0) & 0xff,
      (h6>>>24) & 0xff, (h6>>>16) & 0xff, (h6>>>8) & 0xff, (h6>>>0) & 0xff,
      (h7>>>24) & 0xff, (h7>>>16) & 0xff, (h7>>>8) & 0xff, (h7>>>0) & 0xff
    ];
  }

  function PBKDF2_HMAC_SHA256_OneIter(password, salt, dkLen) {
    // compress password if it's longer than hash block length
    if (password.length > 64) {
      password = SHA256(password);
    }

    var i, innerLen = 64 + salt.length + 4,
        inner = new Array(innerLen),
        outerKey = new Array(64),
        dk = [];

    // inner = (password ^ ipad) || salt || counter
    for (i = 0; i < 64; i++) inner[i] = 0x36;
    for (i = 0; i < password.length; i++) inner[i] ^= password[i];
    for (i = 0; i < salt.length; i++) inner[64+i] = salt[i];
    for (i = innerLen - 4; i < innerLen; i++) inner[i] = 0;

    // outerKey = password ^ opad
    for (i = 0; i < 64; i++) outerKey[i] = 0x5c;
    for (i = 0; i < password.length; i++) outerKey[i] ^= password[i];

    // increments counter inside inner
    function incrementCounter() {
      for (var i = innerLen-1; i >= innerLen-4; i--) {
        if (inner[i] < 0xff) {
          inner[i]++;
          return;
        }
        inner[i] = 0;
      }
    }

    // output blocks = SHA256(outerKey || SHA256(inner)) ...
    while (dk.length < dkLen) {
      incrementCounter();
      Array.prototype.push.apply(dk, SHA256(outerKey.concat(SHA256(inner))));
    }
    dk.length = dkLen;
    return dk;
  }

  function salsaXOR(B, bin, bout) {
    var j0  = B[0]  ^ B[bin+0],
        j1  = B[1]  ^ B[bin+1],
        j2  = B[2]  ^ B[bin+2],
        j3  = B[3]  ^ B[bin+3],
        j4  = B[4]  ^ B[bin+4],
        j5  = B[5]  ^ B[bin+5],
        j6  = B[6]  ^ B[bin+6],
        j7  = B[7]  ^ B[bin+7],
        j8  = B[8]  ^ B[bin+8],
        j9  = B[9]  ^ B[bin+9],
        j10 = B[10] ^ B[bin+10],
        j11 = B[11] ^ B[bin+11],
        j12 = B[12] ^ B[bin+12],
        j13 = B[13] ^ B[bin+13],
        j14 = B[14] ^ B[bin+14],
        j15 = B[15] ^ B[bin+15],
        u, i;

    var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
        x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14,
        x15 = j15;

    for (i = 0; i < 8; i += 2) {
      u =  x0 + x12;   x4 ^= u<<7  | u>>>(32-7);
      u =  x4 +  x0;   x8 ^= u<<9  | u>>>(32-9);
      u =  x8 +  x4;  x12 ^= u<<13 | u>>>(32-13);
      u = x12 +  x8;   x0 ^= u<<18 | u>>>(32-18);

      u =  x5 +  x1;   x9 ^= u<<7  | u>>>(32-7);
      u =  x9 +  x5;  x13 ^= u<<9  | u>>>(32-9);
      u = x13 +  x9;   x1 ^= u<<13 | u>>>(32-13);
      u =  x1 + x13;   x5 ^= u<<18 | u>>>(32-18);

      u = x10 +  x6;  x14 ^= u<<7  | u>>>(32-7);
      u = x14 + x10;   x2 ^= u<<9  | u>>>(32-9);
      u =  x2 + x14;   x6 ^= u<<13 | u>>>(32-13);
      u =  x6 +  x2;  x10 ^= u<<18 | u>>>(32-18);

      u = x15 + x11;   x3 ^= u<<7  | u>>>(32-7);
      u =  x3 + x15;   x7 ^= u<<9  | u>>>(32-9);
      u =  x7 +  x3;  x11 ^= u<<13 | u>>>(32-13);
      u = x11 +  x7;  x15 ^= u<<18 | u>>>(32-18);

      u =  x0 +  x3;   x1 ^= u<<7  | u>>>(32-7);
      u =  x1 +  x0;   x2 ^= u<<9  | u>>>(32-9);
      u =  x2 +  x1;   x3 ^= u<<13 | u>>>(32-13);
      u =  x3 +  x2;   x0 ^= u<<18 | u>>>(32-18);

      u =  x5 +  x4;   x6 ^= u<<7  | u>>>(32-7);
      u =  x6 +  x5;   x7 ^= u<<9  | u>>>(32-9);
      u =  x7 +  x6;   x4 ^= u<<13 | u>>>(32-13);
      u =  x4 +  x7;   x5 ^= u<<18 | u>>>(32-18);

      u = x10 +  x9;  x11 ^= u<<7  | u>>>(32-7);
      u = x11 + x10;   x8 ^= u<<9  | u>>>(32-9);
      u =  x8 + x11;   x9 ^= u<<13 | u>>>(32-13);
      u =  x9 +  x8;  x10 ^= u<<18 | u>>>(32-18);

      u = x15 + x14;  x12 ^= u<<7  | u>>>(32-7);
      u = x12 + x15;  x13 ^= u<<9  | u>>>(32-9);
      u = x13 + x12;  x14 ^= u<<13 | u>>>(32-13);
      u = x14 + x13;  x15 ^= u<<18 | u>>>(32-18);
    }

    B[bout+0]  = B[0]  = (x0  + j0)  | 0;
    B[bout+1]  = B[1]  = (x1  + j1)  | 0;
    B[bout+2]  = B[2]  = (x2  + j2)  | 0;
    B[bout+3]  = B[3]  = (x3  + j3)  | 0;
    B[bout+4]  = B[4]  = (x4  + j4)  | 0;
    B[bout+5]  = B[5]  = (x5  + j5)  | 0;
    B[bout+6]  = B[6]  = (x6  + j6)  | 0;
    B[bout+7]  = B[7]  = (x7  + j7)  | 0;
    B[bout+8]  = B[8]  = (x8  + j8)  | 0;
    B[bout+9]  = B[9]  = (x9  + j9)  | 0;
    B[bout+10] = B[10] = (x10 + j10) | 0;
    B[bout+11] = B[11] = (x11 + j11) | 0;
    B[bout+12] = B[12] = (x12 + j12) | 0;
    B[bout+13] = B[13] = (x13 + j13) | 0;
    B[bout+14] = B[14] = (x14 + j14) | 0;
    B[bout+15] = B[15] = (x15 + j15) | 0;
  }

  function blockCopy(B, di, si, len) {
    for (var i = 0; i < len; i++) B[di+i] = B[si+i];
  }

  function blockXOR(B, di, si, len) {
    for (var i = 0; i < len; i++) B[di+i] ^= B[si+i];
  }

  function blockMix(B, bin, bout, r) {
    blockCopy(B, 0, bin + (2*r-1)*16, 16);
    for (var i = 0; i < 2*r; i += 2) {
      salsaXOR(B, bin + i*16,      bout + i*8);
      salsaXOR(B, bin + i*16 + 16, bout + i*8 + r*16);
    }
  }

  function integerify(B, bi, r) {
    return B[bi+(2*r-1)*16];
  }

  // Generate key.

  var MAX_INT = ((1<<31)>>>0)-1,
      N = opts.N,
      r = opts.r,
      p = opts.p,
      dkLen = opts.dkLen,
      interruptStep = opts.interruptStep;

  if (typeof N !== 'undefined') {
    if (N < 2 || N > MAX_INT)
      throw new Error('scrypt: N is out of range');

    if ((N&(N-1)) !== 0)
      throw new Error('scrypt: N is not a power of 2');

  } else {
    if (typeof opts.logN === 'undefined')
      throw new Error('scrypt: missing N parameter');

    if (opts.logN < 1 || opts.logN > 30)
      throw new Error('scrypt: logN must be between 1 and 30');

    N = 1<<opts.logN;
  }

  if (r < 1)
    throw new Error('scrypt: invalid r');

  if (p < 1)
    throw new Error('scrypt: invalid p');

  if (r*p >= 1<<30 || r > MAX_INT/128/p || r > MAX_INT/256 || N > MAX_INT/128/r)
    throw new Error('scrypt: parameters are too large');

  var B = PBKDF2_HMAC_SHA256_OneIter(password, salt, p*128*r),
      R = 32 * r,
      V;

  if (typeof Int32Array !== 'undefined') {
    //XXX We can use Uint32Array, but Int32Array is faster in Safari.
    V = new Int32Array(16 + 32*N*r + 64*r);
  } else {
    V = [];
  }

  var xi = 16 + 32*N*r, yi = xi + R;

  function smixStart(pos) {
    for (var i = 0; i < R; i++) {
      var j = pos + i*4;
      V[16+i] = ((B[j+3] & 0xff)<<24) | ((B[j+2] & 0xff)<<16) |
                ((B[j+1] & 0xff)<<8)  | ((B[j+0] & 0xff)<<0);
    }
  }

  function smixStep1(start, end) {
    for (var i = start; i < end; i++) {
      blockMix(V, 16 + i*R, 16 + (i+1)*R, r);
    }
  }

  function smixStep2(start, end) {
    for (var i = start; i < end; i += 2) {
      var j = integerify(V, xi, r) & (N-1);
      blockXOR(V, xi, 16 + j*R, R);
      blockMix(V, xi, yi, r);

      j = integerify(V, yi, r) & (N-1);
      blockXOR(V, yi, 16 + j*R, R);
      blockMix(V, yi, xi, r);
    }
  }

  function smixFinish(pos) {
    for (var i = 0; i < R; i++) {
      var j = V[xi+i];
      B[pos + i*4 + 0] = (j>>>0)  & 0xff;
      B[pos + i*4 + 1] = (j>>>8)  & 0xff;
      B[pos + i*4 + 2] = (j>>>16) & 0xff;
      B[pos + i*4 + 3] = (j>>>24) & 0xff;
    }
  }

  var nextTick = (typeof setImmediate !== 'undefined') ? setImmediate : setTimeout;

  function interruptedFor(start, end, step, fn, donefn) {
    nextTick(function() {
      if (start+step < end) {
        interruptedFor(start+step, end, step, fn, donefn);
        fn(start, start+step);
      } else {
        donefn();
        fn(start, end);
      }
    });
  }

  // Blocking variant.
  function calculateSync() {
    for (var i = 0; i < p; i++) {
      smixStart(i*128*r);
      smixStep1(0, N);
      smixStep2(0, N);
      smixFinish(i*128*r);
    }
    callback(PBKDF2_HMAC_SHA256_OneIter(password, B, dkLen));
  }

  // Async variant.
  function calculateAsync(i) {
    interruptedFor(0, N, interruptStep*2, smixStep1, function() {
      interruptedFor(0, N, interruptStep*2, smixStep2, function() {
        nextTick(function() {
          if (i + 1 < p) {
            calculateAsync(i + 1);
            smixFinish(i*128*r);
          } else {
            smixFinish(i*128*r);
            callback(PBKDF2_HMAC_SHA256_OneIter(password, B, dkLen));
          }
        });
      });
    });
    smixStart(i*128*r);
  }

  if (interruptStep > 0) {
    calculateAsync(0);
  } else {
    calculateSync();
  }
}

if (typeof module !== 'undefined') module.exports = scrypt;

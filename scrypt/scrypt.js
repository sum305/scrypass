(() => {
	"use strict";

	const sha256K = new Int32Array([
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	]);

	const sha256Block = (v, w, m, len) => {
		for (let pos = 0; len-pos >= 64; pos += 64) {
			for (let i = 0; i < 16; i++) {
				const j = pos + i*4;
				w[i] = (m[j+0]<<24) | (m[j+1]<<16) | (m[j+2]<<8) | m[j+3];
			}

			for (let i = 16; i < 64; i++) {
				const u1 = w[i-2];
				const t1 = ((u1>>>17) | (u1<<(32-17))) ^ ((u1>>>19) | (u1<<(32-19))) ^ (u1>>>10);

				const u2 = w[i-15];
				const t2 = ((u2>>>7) | (u2<<(32-7))) ^ ((u2>>>18) | (u2<<(32-18))) ^ (u2>>>3);

				w[i] = ((t1 + w[i-7]) | 0) + ((t2 + w[i-16]) | 0);
			}

			let a = v[0];
			let b = v[1];
			let c = v[2];
			let d = v[3];
			let e = v[4];
			let f = v[5];
			let g = v[6];
			let h = v[7];

			for (let i = 0; i < 64; i++) {
				const t1 = ((((((e>>>6) | (e<<(32-6))) ^ ((e>>>11) | (e<<(32-11))) ^
					((e>>>25) | (e<<(32-25)))) + ((e & f) ^ (~e & g))) | 0) +
					((h + ((sha256K[i] + w[i]) | 0)) | 0)) | 0;

				const t2 = ((((a>>>2) | (a<<(32-2))) ^ ((a>>>13) | (a<<(32-13))) ^
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

			v[0] += a;
			v[1] += b;
			v[2] += c;
			v[3] += d;
			v[4] += e;
			v[5] += f;
			v[6] += g;
			v[7] += h;
		}
	};

	const sha256 = (v, w, p, m, out, pos) => {
		v[0] = 0x6a09e667;
		v[1] = 0xbb67ae85;
		v[2] = 0x3c6ef372;
		v[3] = 0xa54ff53a;
		v[4] = 0x510e527f;
		v[5] = 0x9b05688c;
		v[6] = 0x1f83d9ab;
		v[7] = 0x5be0cd19;

		sha256Block(v, w, m, m.length);

		const leftLen = m.length % 64;
		const leftPos = m.length - leftLen;
		const bitLenHi = (m.length / 0x20000000) | 0;
		const bitLenLo = m.length << 3;
		const padLen = (leftLen < 56) ? 64 : 128;

		for (let i = 0; i < leftLen; i++) p[i] = m[leftPos+i];
		p[leftLen] = 0x80;
		for (let i = leftLen+1; i < padLen-8; i++) p[i] = 0;
		p[padLen-8] = bitLenHi >>> 24;
		p[padLen-7] = bitLenHi >>> 16;
		p[padLen-6] = bitLenHi >>> 8;
		p[padLen-5] = bitLenHi >>> 0;
		p[padLen-4] = bitLenLo >>> 24;
		p[padLen-3] = bitLenLo >>> 16;
		p[padLen-2] = bitLenLo >>> 8;
		p[padLen-1] = bitLenLo >>> 0;

		sha256Block(v, w, p, padLen);

		for (let i = 0; i < 8; i++) {
			const j = pos + i*4;
			const u = v[i];
			out[j+0] = u >>> 24;
			out[j+1] = u >>> 16;
			out[j+2] = u >>> 8;
			out[j+3] = u >>> 0;
		}
	};

	const pbkdf2HmacSha256Once = (password, salt, dkLen) => {
		const innerLen = 64 + salt.length + 4;
		const inner = new Uint8Array(innerLen);
		const outer = new Uint8Array(64 + 32);
		const dk = new Uint8Array(dkLen + 32 - 1);

		const v = new Int32Array(8);
		const w = new Int32Array(64);
		const p = new Uint8Array(128);

		if (password.length > 64) {
			sha256(v, w, p, password, inner, 0);
		} else {
			inner.set(password);
		}
		for (let i = 0; i < 64; i++) {
			const u = inner[i];
			inner[i] = u ^ 0x36;
			outer[i] = u ^ 0x5c;
		}
		inner.set(salt, 64);

		let j = 0;
		for (let i = 0; i < dkLen; i += 32) {
			j++;
			inner[innerLen-4] = j >>> 24;
			inner[innerLen-3] = j >>> 16;
			inner[innerLen-2] = j >>> 8;
			inner[innerLen-1] = j >>> 0;

			sha256(v, w, p, inner, outer, 64);
			sha256(v, w, p, outer, dk, i);
		}
		return dk.subarray(0, dkLen);
	};

	const funcToURL = (fn) => {
		return URL.createObjectURL(new Blob(["(" + fn + ")();"]));
	};

	const workerURL = funcToURL(() => {
		"use strict";

		const blockXOR = (B, dst, src, R) => {
			for (let i = 0; i < R; i += 32) {
				const di = dst + i;
				const si = src + i;
				B[di+0]  ^= B[si+0];
				B[di+1]  ^= B[si+1];
				B[di+2]  ^= B[si+2];
				B[di+3]  ^= B[si+3];
				B[di+4]  ^= B[si+4];
				B[di+5]  ^= B[si+5];
				B[di+6]  ^= B[si+6];
				B[di+7]  ^= B[si+7];
				B[di+8]  ^= B[si+8];
				B[di+9]  ^= B[si+9];
				B[di+10] ^= B[si+10];
				B[di+11] ^= B[si+11];
				B[di+12] ^= B[si+12];
				B[di+13] ^= B[si+13];
				B[di+14] ^= B[si+14];
				B[di+15] ^= B[si+15];
				B[di+16] ^= B[si+16];
				B[di+17] ^= B[si+17];
				B[di+18] ^= B[si+18];
				B[di+19] ^= B[si+19];
				B[di+20] ^= B[si+20];
				B[di+21] ^= B[si+21];
				B[di+22] ^= B[si+22];
				B[di+23] ^= B[si+23];
				B[di+24] ^= B[si+24];
				B[di+25] ^= B[si+25];
				B[di+26] ^= B[si+26];
				B[di+27] ^= B[si+27];
				B[di+28] ^= B[si+28];
				B[di+29] ^= B[si+29];
				B[di+30] ^= B[si+30];
				B[di+31] ^= B[si+31];
			}
		};

		const blockMix = (B, last, inp, out, r) => {
			let w0  = B[last+0];
			let w1  = B[last+1];
			let w2  = B[last+2];
			let w3  = B[last+3];
			let w4  = B[last+4];
			let w5  = B[last+5];
			let w6  = B[last+6];
			let w7  = B[last+7];
			let w8  = B[last+8];
			let w9  = B[last+9];
			let w10 = B[last+10];
			let w11 = B[last+11];
			let w12 = B[last+12];
			let w13 = B[last+13];
			let w14 = B[last+14];
			let w15 = B[last+15];

			let u = 0;
			for (let i = 0; i < 2*r; i++) {
				const ii = inp + i*16;
				const oi = out + i*8 + (i&1)*(r*16-8);

				let x0  = w0  ^= B[ii+0];
				let x1  = w1  ^= B[ii+1];
				let x2  = w2  ^= B[ii+2];
				let x3  = w3  ^= B[ii+3];
				let x4  = w4  ^= B[ii+4];
				let x5  = w5  ^= B[ii+5];
				let x6  = w6  ^= B[ii+6];
				let x7  = w7  ^= B[ii+7];
				let x8  = w8  ^= B[ii+8];
				let x9  = w9  ^= B[ii+9];
				let x10 = w10 ^= B[ii+10];
				let x11 = w11 ^= B[ii+11];
				let x12 = w12 ^= B[ii+12];
				let x13 = w13 ^= B[ii+13];
				let x14 = w14 ^= B[ii+14];
				let x15 = w15 ^= B[ii+15];

				for (let j = 0; j < 8; j += 2) {
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

				B[oi+0]  = w0  = (w0  + x0)  | 0;
				B[oi+1]  = w1  = (w1  + x1)  | 0;
				B[oi+2]  = w2  = (w2  + x2)  | 0;
				B[oi+3]  = w3  = (w3  + x3)  | 0;
				B[oi+4]  = w4  = (w4  + x4)  | 0;
				B[oi+5]  = w5  = (w5  + x5)  | 0;
				B[oi+6]  = w6  = (w6  + x6)  | 0;
				B[oi+7]  = w7  = (w7  + x7)  | 0;
				B[oi+8]  = w8  = (w8  + x8)  | 0;
				B[oi+9]  = w9  = (w9  + x9)  | 0;
				B[oi+10] = w10 = (w10 + x10) | 0;
				B[oi+11] = w11 = (w11 + x11) | 0;
				B[oi+12] = w12 = (w12 + x12) | 0;
				B[oi+13] = w13 = (w13 + x13) | 0;
				B[oi+14] = w14 = (w14 + x14) | 0;
				B[oi+15] = w15 = (w15 + x15) | 0;
			}
		};

		self.onmessage = (e) => {
			const B = e.data.B;
			const N = e.data.N;
			const r = e.data.r;

			const L = (2*r-1) * 16;
			const R = 32 * r;
			const V = new Int32Array(N*R + 2*R);
			const xi = N * R;
			const yi = xi + R;

			for (let i = 0; i < R; i++) {
				const j = i * 4;
				V[i] = B[j+0] | (B[j+1]<<8) | (B[j+2]<<16) | (B[j+3]<<24);
			}

			for (let i = 0; i < xi; i += R) {
				blockMix(V, i+L, i, i+R, r);
			}

			for (let i = 0; i < N; i += 2) {
				blockXOR(V, xi, (V[xi+L]&(N-1))*R, R);
				blockMix(V, xi+L, xi, yi, r);

				blockXOR(V, yi, (V[yi+L]&(N-1))*R, R);
				blockMix(V, yi+L, yi, xi, r);
			}

			for (let i = 0; i < R; i++) {
				const j = i * 4;
				const u = V[xi+i];
				B[j+0] = u >>> 0;
				B[j+1] = u >>> 8;
				B[j+2] = u >>> 16;
				B[j+3] = u >>> 24;
			}
			self.postMessage(B, [B.buffer]);
		};
	});

	const scrypt = (password, salt, N, r, p, dkLen, callback) => {
		const maxInt = 0x7fffffff;

		if (N < 2 || N > maxInt) {
			throw new Error("scrypt: N is out of range");
		}
		if ((N&(N-1)) !== 0) {
			throw new Error("scrypt: N is not a power of 2");
		}
		if (r < 1) {
			throw new Error("scrypt: invalid r");
		}
		if (p < 1) {
			throw new Error("scrypt: invalid p");
		}
		if (r*p >= 1<<30 || r > maxInt/128/p || r > maxInt/256 || N > maxInt/128/r) {
			throw new Error("scrypt: parameters are too large");
		}

		const B = pbkdf2HmacSha256Once(password, salt, p*128*r);

		const workers = [];
		const terminateAll = () => {
			for (const w of workers) w.terminate();
			workers.length = 0;
		};

		let j = 0;
		for (let i = 0; i < p; i++) {
			const b = B.slice(i*128*r, (i+1)*128*r);
			const w = new Worker(workerURL);
			w.postMessage({B: b, N: N, r: r}, [b.buffer]);
			w.onmessage = (e) => {
				B.set(e.data, i*128*r);
				j++;
				if (j === workers.length) {
					terminateAll();
					callback(pbkdf2HmacSha256Once(password, B, dkLen));
				}
			};
			workers.push(w);
		}
		return terminateAll;
	};

	self.scrypt = scrypt;
})();

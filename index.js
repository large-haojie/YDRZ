(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
    typeof define === 'function' && define.amd ? define(['exports'], factory) :
    (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.h5 = {}));
})(this, (function (exports) { 'use strict';

    /*! *****************************************************************************
    Copyright (c) Microsoft Corporation.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
    REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
    INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
    LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
    OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
    PERFORMANCE OF THIS SOFTWARE.
    ***************************************************************************** */

    var __assign = function() {
        __assign = Object.assign || function __assign(t) {
            for (var s, i = 1, n = arguments.length; i < n; i++) {
                s = arguments[i];
                for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
            }
            return t;
        };
        return __assign.apply(this, arguments);
    };

    var md5$1 = {exports: {}};

    var crypt = {exports: {}};

    (function() {
      var base64map
          = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',

      crypt$1 = {
        // Bit-wise rotation left
        rotl: function(n, b) {
          return (n << b) | (n >>> (32 - b));
        },

        // Bit-wise rotation right
        rotr: function(n, b) {
          return (n << (32 - b)) | (n >>> b);
        },

        // Swap big-endian to little-endian and vice versa
        endian: function(n) {
          // If number given, swap endian
          if (n.constructor == Number) {
            return crypt$1.rotl(n, 8) & 0x00FF00FF | crypt$1.rotl(n, 24) & 0xFF00FF00;
          }

          // Else, assume array and swap all items
          for (var i = 0; i < n.length; i++)
            n[i] = crypt$1.endian(n[i]);
          return n;
        },

        // Generate an array of any length of random bytes
        randomBytes: function(n) {
          for (var bytes = []; n > 0; n--)
            bytes.push(Math.floor(Math.random() * 256));
          return bytes;
        },

        // Convert a byte array to big-endian 32-bit words
        bytesToWords: function(bytes) {
          for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
            words[b >>> 5] |= bytes[i] << (24 - b % 32);
          return words;
        },

        // Convert big-endian 32-bit words to a byte array
        wordsToBytes: function(words) {
          for (var bytes = [], b = 0; b < words.length * 32; b += 8)
            bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
          return bytes;
        },

        // Convert a byte array to a hex string
        bytesToHex: function(bytes) {
          for (var hex = [], i = 0; i < bytes.length; i++) {
            hex.push((bytes[i] >>> 4).toString(16));
            hex.push((bytes[i] & 0xF).toString(16));
          }
          return hex.join('');
        },

        // Convert a hex string to a byte array
        hexToBytes: function(hex) {
          for (var bytes = [], c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
          return bytes;
        },

        // Convert a byte array to a base-64 string
        bytesToBase64: function(bytes) {
          for (var base64 = [], i = 0; i < bytes.length; i += 3) {
            var triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
            for (var j = 0; j < 4; j++)
              if (i * 8 + j * 6 <= bytes.length * 8)
                base64.push(base64map.charAt((triplet >>> 6 * (3 - j)) & 0x3F));
              else
                base64.push('=');
          }
          return base64.join('');
        },

        // Convert a base-64 string to a byte array
        base64ToBytes: function(base64) {
          // Remove non-base-64 characters
          base64 = base64.replace(/[^A-Z0-9+\/]/ig, '');

          for (var bytes = [], i = 0, imod4 = 0; i < base64.length;
              imod4 = ++i % 4) {
            if (imod4 == 0) continue;
            bytes.push(((base64map.indexOf(base64.charAt(i - 1))
                & (Math.pow(2, -2 * imod4 + 8) - 1)) << (imod4 * 2))
                | (base64map.indexOf(base64.charAt(i)) >>> (6 - imod4 * 2)));
          }
          return bytes;
        }
      };

      crypt.exports = crypt$1;
    })();

    var charenc = {
      // UTF-8 encoding
      utf8: {
        // Convert a string to a byte array
        stringToBytes: function(str) {
          return charenc.bin.stringToBytes(unescape(encodeURIComponent(str)));
        },

        // Convert a byte array to a string
        bytesToString: function(bytes) {
          return decodeURIComponent(escape(charenc.bin.bytesToString(bytes)));
        }
      },

      // Binary encoding
      bin: {
        // Convert a string to a byte array
        stringToBytes: function(str) {
          for (var bytes = [], i = 0; i < str.length; i++)
            bytes.push(str.charCodeAt(i) & 0xFF);
          return bytes;
        },

        // Convert a byte array to a string
        bytesToString: function(bytes) {
          for (var str = [], i = 0; i < bytes.length; i++)
            str.push(String.fromCharCode(bytes[i]));
          return str.join('');
        }
      }
    };

    var charenc_1 = charenc;

    (function(){
      var crypt$1 = crypt.exports,
          utf8 = charenc_1.utf8,
          bin = charenc_1.bin,

      // The core
      md5 = function (message, options) {
        // Convert to byte array
        if (message.constructor == String)
          if (options && options.encoding === 'binary')
            message = bin.stringToBytes(message);
          else
            message = utf8.stringToBytes(message);
        else if (typeof Buffer != 'undefined' &&
            typeof Buffer.isBuffer == 'function' && Buffer.isBuffer(message))
          message = Array.prototype.slice.call(message, 0);
        else if (!Array.isArray(message))
          message = message.toString();
        // else, assume byte array already

        var m = crypt$1.bytesToWords(message),
            l = message.length * 8,
            a =  1732584193,
            b = -271733879,
            c = -1732584194,
            d =  271733878;

        // Swap endian
        for (var i = 0; i < m.length; i++) {
          m[i] = ((m[i] <<  8) | (m[i] >>> 24)) & 0x00FF00FF |
                 ((m[i] << 24) | (m[i] >>>  8)) & 0xFF00FF00;
        }

        // Padding
        m[l >>> 5] |= 0x80 << (l % 32);
        m[(((l + 64) >>> 9) << 4) + 14] = l;

        // Method shortcuts
        var FF = md5._ff,
            GG = md5._gg,
            HH = md5._hh,
            II = md5._ii;

        for (var i = 0; i < m.length; i += 16) {

          var aa = a,
              bb = b,
              cc = c,
              dd = d;

          a = FF(a, b, c, d, m[i+ 0],  7, -680876936);
          d = FF(d, a, b, c, m[i+ 1], 12, -389564586);
          c = FF(c, d, a, b, m[i+ 2], 17,  606105819);
          b = FF(b, c, d, a, m[i+ 3], 22, -1044525330);
          a = FF(a, b, c, d, m[i+ 4],  7, -176418897);
          d = FF(d, a, b, c, m[i+ 5], 12,  1200080426);
          c = FF(c, d, a, b, m[i+ 6], 17, -1473231341);
          b = FF(b, c, d, a, m[i+ 7], 22, -45705983);
          a = FF(a, b, c, d, m[i+ 8],  7,  1770035416);
          d = FF(d, a, b, c, m[i+ 9], 12, -1958414417);
          c = FF(c, d, a, b, m[i+10], 17, -42063);
          b = FF(b, c, d, a, m[i+11], 22, -1990404162);
          a = FF(a, b, c, d, m[i+12],  7,  1804603682);
          d = FF(d, a, b, c, m[i+13], 12, -40341101);
          c = FF(c, d, a, b, m[i+14], 17, -1502002290);
          b = FF(b, c, d, a, m[i+15], 22,  1236535329);

          a = GG(a, b, c, d, m[i+ 1],  5, -165796510);
          d = GG(d, a, b, c, m[i+ 6],  9, -1069501632);
          c = GG(c, d, a, b, m[i+11], 14,  643717713);
          b = GG(b, c, d, a, m[i+ 0], 20, -373897302);
          a = GG(a, b, c, d, m[i+ 5],  5, -701558691);
          d = GG(d, a, b, c, m[i+10],  9,  38016083);
          c = GG(c, d, a, b, m[i+15], 14, -660478335);
          b = GG(b, c, d, a, m[i+ 4], 20, -405537848);
          a = GG(a, b, c, d, m[i+ 9],  5,  568446438);
          d = GG(d, a, b, c, m[i+14],  9, -1019803690);
          c = GG(c, d, a, b, m[i+ 3], 14, -187363961);
          b = GG(b, c, d, a, m[i+ 8], 20,  1163531501);
          a = GG(a, b, c, d, m[i+13],  5, -1444681467);
          d = GG(d, a, b, c, m[i+ 2],  9, -51403784);
          c = GG(c, d, a, b, m[i+ 7], 14,  1735328473);
          b = GG(b, c, d, a, m[i+12], 20, -1926607734);

          a = HH(a, b, c, d, m[i+ 5],  4, -378558);
          d = HH(d, a, b, c, m[i+ 8], 11, -2022574463);
          c = HH(c, d, a, b, m[i+11], 16,  1839030562);
          b = HH(b, c, d, a, m[i+14], 23, -35309556);
          a = HH(a, b, c, d, m[i+ 1],  4, -1530992060);
          d = HH(d, a, b, c, m[i+ 4], 11,  1272893353);
          c = HH(c, d, a, b, m[i+ 7], 16, -155497632);
          b = HH(b, c, d, a, m[i+10], 23, -1094730640);
          a = HH(a, b, c, d, m[i+13],  4,  681279174);
          d = HH(d, a, b, c, m[i+ 0], 11, -358537222);
          c = HH(c, d, a, b, m[i+ 3], 16, -722521979);
          b = HH(b, c, d, a, m[i+ 6], 23,  76029189);
          a = HH(a, b, c, d, m[i+ 9],  4, -640364487);
          d = HH(d, a, b, c, m[i+12], 11, -421815835);
          c = HH(c, d, a, b, m[i+15], 16,  530742520);
          b = HH(b, c, d, a, m[i+ 2], 23, -995338651);

          a = II(a, b, c, d, m[i+ 0],  6, -198630844);
          d = II(d, a, b, c, m[i+ 7], 10,  1126891415);
          c = II(c, d, a, b, m[i+14], 15, -1416354905);
          b = II(b, c, d, a, m[i+ 5], 21, -57434055);
          a = II(a, b, c, d, m[i+12],  6,  1700485571);
          d = II(d, a, b, c, m[i+ 3], 10, -1894986606);
          c = II(c, d, a, b, m[i+10], 15, -1051523);
          b = II(b, c, d, a, m[i+ 1], 21, -2054922799);
          a = II(a, b, c, d, m[i+ 8],  6,  1873313359);
          d = II(d, a, b, c, m[i+15], 10, -30611744);
          c = II(c, d, a, b, m[i+ 6], 15, -1560198380);
          b = II(b, c, d, a, m[i+13], 21,  1309151649);
          a = II(a, b, c, d, m[i+ 4],  6, -145523070);
          d = II(d, a, b, c, m[i+11], 10, -1120210379);
          c = II(c, d, a, b, m[i+ 2], 15,  718787259);
          b = II(b, c, d, a, m[i+ 9], 21, -343485551);

          a = (a + aa) >>> 0;
          b = (b + bb) >>> 0;
          c = (c + cc) >>> 0;
          d = (d + dd) >>> 0;
        }

        return crypt$1.endian([a, b, c, d]);
      };

      // Auxiliary functions
      md5._ff  = function (a, b, c, d, x, s, t) {
        var n = a + (b & c | ~b & d) + (x >>> 0) + t;
        return ((n << s) | (n >>> (32 - s))) + b;
      };
      md5._gg  = function (a, b, c, d, x, s, t) {
        var n = a + (b & d | c & ~d) + (x >>> 0) + t;
        return ((n << s) | (n >>> (32 - s))) + b;
      };
      md5._hh  = function (a, b, c, d, x, s, t) {
        var n = a + (b ^ c ^ d) + (x >>> 0) + t;
        return ((n << s) | (n >>> (32 - s))) + b;
      };
      md5._ii  = function (a, b, c, d, x, s, t) {
        var n = a + (c ^ (b | ~d)) + (x >>> 0) + t;
        return ((n << s) | (n >>> (32 - s))) + b;
      };

      // Package private blocksize
      md5._blocksize = 16;
      md5._digestsize = 16;

      md5$1.exports = function (message, options) {
        if(typeof message == 'undefined')
          return;

        var digestbytes = crypt$1.wordsToBytes(md5(message, options));
        return options && options.asBytes ? digestbytes :
            options && options.asString ? bin.bytesToString(digestbytes) :
            crypt$1.bytesToHex(digestbytes);
      };

    })();

    var md5 = md5$1.exports;

    /*
    CryptoJS v3.1.2
    code.google.com/p/crypto-js
    (c) 2009-2013 by Jeff Mott. All rights reserved.
    code.google.com/p/crypto-js/wiki/License
    */

    var CryptoJS = CryptoJS || (function (u, p) {
        let d = {};
        let l = d.lib = {};
        let s = function () {};
        let t = l.Base = {
            extend: function (a) {
                s.prototype = this;
                let c = new s();
                a && c.mixIn(a);
                c.hasOwnProperty('init') || (c.init = function () {
                    c.$super.init.apply(this, arguments);
                });
                c.init.prototype = c;
                c.$super = this;
                return c;
            },
            create: function () {
                let a = this.extend();
                a.init.apply(a, arguments);
                return a;
            },
            init: function () {},
            mixIn: function (a) {
                for (let c in a) {a.hasOwnProperty(c) && (this[c] = a[c]);}
                a.hasOwnProperty('toString') && (this.toString = a.toString);
            },
            clone: function () {
                return this.init.prototype.extend(this);
            },
        };
        var r = l.WordArray = t.extend({
            init: function (a, c) {
                a = this.words = a || [];
                this.sigBytes = c != p ? c : 4 * a.length;
            },
            toString: function (a) {
                return (a || v).stringify(this);
            },
            concat: function (a) {
                let c = this.words;
                let e = a.words;
                let j = this.sigBytes;
                a = a.sigBytes;
                this.clamp();
                if (j % 4) {for (var k = 0; k < a; k++) {c[j + k >>> 2] |= (e[k >>> 2] >>> 24 - 8 * (k % 4) & 255) << 24 - 8 * ((j + k) % 4);}}
                else if (65535 < e.length) {for (k = 0; k < a; k += 4) {c[j + k >>> 2] = e[k >>> 2];}}
                else {c.push.apply(c, e);}
                this.sigBytes += a;
                return this;
            },
            clamp: function () {
                let a = this.words;
                let c = this.sigBytes;
                a[c >>> 2] &= 4294967295
                        << 32 - 8 * (c % 4);
                a.length = u.ceil(c / 4);
            },
            clone: function () {
                let a = t.clone.call(this);
                a.words = this.words.slice(0);
                return a;
            },
            random: function (a) {
                for (var c = [], e = 0; e < a; e += 4) {c.push(4294967296 * u.random() | 0);}
                return new r.init(c, a);
            },
        });
        let w = d.enc = {};
        var v = w.Hex = {
            stringify: function (a) {
                let c = a.words;
                a = a.sigBytes;
                for (var e = [], j = 0; j < a; j++) {
                    let k = c[j >>> 2] >>> 24 - 8 * (j % 4) & 255;
                    e.push((k >>> 4).toString(16));
                    e.push((k & 15).toString(16));
                }
                return e.join('');
            },
            parse: function (a) {
                for (var c = a.length, e = [], j = 0; j < c; j += 2) {
                    e[j >>> 3] |= parseInt(a.substr(j,
                        2), 16) << 24 - 4 * (j % 8);
                }
                return new r.init(e, c / 2);
            },
        };
        let b = w.Latin1 = {
            stringify: function (a) {
                let c = a.words;
                a = a.sigBytes;
                for (var e = [], j = 0; j < a; j++) {e.push(String.fromCharCode(c[j >>> 2] >>> 24 - 8 * (j % 4) & 255));}
                return e.join('');
            },
            parse: function (a) {
                for (var c = a.length, e = [], j = 0; j < c; j++) {e[j >>> 2] |= (a.charCodeAt(j) & 255) << 24 - 8 * (j % 4);}
                return new r.init(e, c);
            },
        };
        let x = w.Utf8 = {
            stringify: function (a) {
                try {
                    return decodeURIComponent(escape(b.stringify(a)));
                }
                catch (c) {
                    throw Error('Malformed UTF-8 data');
                }
            },
            parse: function (a) {
                return b.parse(unescape(encodeURIComponent(a)));
            },
        };
        let q = l.BufferedBlockAlgorithm = t.extend({
            reset: function () {
                this._data = new r.init();
                this._nDataBytes = 0;
            },
            _append: function (a) {
                'string' === typeof a && (a = x.parse(a));
                this._data.concat(a);
                this._nDataBytes += a.sigBytes;
            },
            _process: function (a) {
                let c = this._data;
                let e = c.words;
                let j = c.sigBytes;
                let k = this.blockSize;
                var b = j / (4 * k);
                var b = a ? u.ceil(b) : u.max((b | 0) - this._minBufferSize, 0);
                a = b * k;
                j = u.min(4 * a, j);
                if (a) {
                    for (var q = 0; q < a; q += k) {this._doProcessBlock(e, q);}
                    q = e.splice(0, a);
                    c.sigBytes -= j;
                }
                return new r.init(q, j);
            },
            clone: function () {
                let a = t.clone.call(this);
                a._data = this._data.clone();
                return a;
            },
            _minBufferSize: 0,
        });
        l.Hasher = q.extend({
            cfg: t.extend(),
            init: function (a) {
                this.cfg = this.cfg.extend(a);
                this.reset();
            },
            reset: function () {
                q.reset.call(this);
                this._doReset();
            },
            update: function (a) {
                this._append(a);
                this._process();
                return this;
            },
            finalize: function (a) {
                a && this._append(a);
                return this._doFinalize();
            },
            blockSize: 16,
            _createHelper: function (a) {
                return function (b, e) {
                    return (new a.init(e)).finalize(b);
                };
            },
            _createHmacHelper: function (a) {
                return function (b, e) {
                    return (new n.HMAC.init(a,
                        e)).finalize(b);
                };
            },
        });
        var n = d.algo = {};
        return d;
    }(Math));
    (function () {
        let u = CryptoJS;
        let p = u.lib.WordArray;
        u.enc.Base64 = {
            stringify: function (d) {
                let l = d.words;
                let p = d.sigBytes;
                let t = this._map;
                d.clamp();
                d = [];
                for (let r = 0; r < p; r += 3) {for (let w = (l[r >>> 2] >>> 24 - 8 * (r % 4) & 255) << 16 | (l[r + 1 >>> 2] >>> 24 - 8 * ((r + 1) % 4) & 255) << 8 | l[r + 2 >>> 2] >>> 24 - 8 * ((r + 2) % 4) & 255, v = 0; 4 > v && r + 0.75 * v < p; v++) {d.push(t.charAt(w >>> 6 * (3 - v) & 63));}}
                if (l = t.charAt(64)) {for (; d.length % 4;) {d.push(l);}}
                return d.join('');
            },
            parse: function (d) {
                let l = d.length;
                let s = this._map;
                var t = s.charAt(64);
                t && (t = d.indexOf(t), -1 != t && (l = t));
                for (var t = [], r = 0, w = 0; w
                    < l; w++) {
                    if (w % 4) {
                        let v = s.indexOf(d.charAt(w - 1)) << 2 * (w % 4);
                        let b = s.indexOf(d.charAt(w)) >>> 6 - 2 * (w % 4);
                        t[r >>> 2] |= (v | b) << 24 - 8 * (r % 4);
                        r++;
                    }
                } return p.create(t, r);
            },
            _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
        };
    })();
    (function (u) {
        function p(b, n, a, c, e, j, k) {
            b = b + (n & a | ~n & c) + e + k;
            return (b << j | b >>> 32 - j) + n;
        }

        function d(b, n, a, c, e, j, k) {
            b = b + (n & c | a & ~c) + e + k;
            return (b << j | b >>> 32 - j) + n;
        }

        function l(b, n, a, c, e, j, k) {
            b = b + (n ^ a ^ c) + e + k;
            return (b << j | b >>> 32 - j) + n;
        }

        function s(b, n, a, c, e, j, k) {
            b = b + (a ^ (n | ~c)) + e + k;
            return (b << j | b >>> 32 - j) + n;
        }
        for (var t = CryptoJS, r = t.lib, w = r.WordArray, v = r.Hasher, r = t.algo, b = [], x = 0; 64 > x; x++) {b[x] = 4294967296 * u.abs(u.sin(x + 1)) | 0;}
        r = r.MD5 = v.extend({
            _doReset: function () {
                this._hash = new w.init([1732584193, 4023233417, 2562383102, 271733878]);
            },
            _doProcessBlock: function (q, n) {
                for (var a = 0; 16 > a; a++) {
                    var c = n + a;
                    var e = q[c];
                    q[c] = (e << 8 | e >>> 24) & 16711935 | (e << 24 | e >>> 8) & 4278255360;
                }
                var a = this._hash.words;
                var c = q[n + 0];
                var e = q[n + 1];
                let j = q[n + 2];
                let k = q[n + 3];
                let z = q[n + 4];
                let r = q[n + 5];
                let t = q[n + 6];
                let w = q[n + 7];
                let v = q[n + 8];
                let A = q[n + 9];
                let B = q[n + 10];
                let C = q[n + 11];
                let u = q[n + 12];
                let D = q[n + 13];
                let E = q[n + 14];
                let x = q[n + 15];
                var f = a[0];
                var m = a[1];
                var g = a[2];
                var h = a[3];
                var f = p(f, m, g, h, c, 7, b[0]);
                var h = p(h, f, m, g, e, 12, b[1]);
                var g = p(g, h, f, m, j, 17, b[2]);
                var m = p(m, g, h, f, k, 22, b[3]);
                var f = p(f, m, g, h, z, 7, b[4]);
                var h = p(h, f, m, g, r, 12, b[5]);
                var g = p(g, h, f, m, t, 17, b[6]);
                var m = p(m, g, h, f, w, 22, b[7]);
                var f = p(f, m, g, h, v, 7, b[8]);
                var h = p(h, f, m, g, A, 12, b[9]);
                var g = p(g, h, f, m, B, 17, b[10]);
                var m = p(m, g, h, f, C, 22, b[11]);
                var f = p(f, m, g, h, u, 7, b[12]);
                var h = p(h, f, m, g, D, 12, b[13]);
                var g = p(g, h, f, m, E, 17, b[14]);
                var m = p(m, g, h, f, x, 22, b[15]);
                var f = d(f, m, g, h, e, 5, b[16]);
                var h = d(h, f, m, g, t, 9, b[17]);
                var g = d(g, h, f, m, C, 14, b[18]);
                var m = d(m, g, h, f, c, 20, b[19]);
                var f = d(f, m, g, h, r, 5, b[20]);
                var h = d(h, f, m, g, B, 9, b[21]);
                var g = d(g, h, f, m, x, 14, b[22]);
                var m = d(m, g, h, f, z, 20, b[23]);
                var f = d(f, m, g, h, A, 5, b[24]);
                var h = d(h, f, m, g, E, 9, b[25]);
                var g = d(g, h, f, m, k, 14, b[26]);
                var m = d(m, g, h, f, v, 20, b[27]);
                var f = d(f, m, g, h, D, 5, b[28]);
                var h = d(h, f,
                    m, g, j, 9, b[29]);
                var g = d(g, h, f, m, w, 14, b[30]);
                var m = d(m, g, h, f, u, 20, b[31]);
                var f = l(f, m, g, h, r, 4, b[32]);
                var h = l(h, f, m, g, v, 11, b[33]);
                var g = l(g, h, f, m, C, 16, b[34]);
                var m = l(m, g, h, f, E, 23, b[35]);
                var f = l(f, m, g, h, e, 4, b[36]);
                var h = l(h, f, m, g, z, 11, b[37]);
                var g = l(g, h, f, m, w, 16, b[38]);
                var m = l(m, g, h, f, B, 23, b[39]);
                var f = l(f, m, g, h, D, 4, b[40]);
                var h = l(h, f, m, g, c, 11, b[41]);
                var g = l(g, h, f, m, k, 16, b[42]);
                var m = l(m, g, h, f, t, 23, b[43]);
                var f = l(f, m, g, h, A, 4, b[44]);
                var h = l(h, f, m, g, u, 11, b[45]);
                var g = l(g, h, f, m, x, 16, b[46]);
                var m = l(m, g, h, f, j, 23, b[47]);
                var f = s(f, m, g, h, c, 6, b[48]);
                var h = s(h, f, m, g, w, 10, b[49]);
                var g = s(g, h, f, m,
                    E, 15, b[50]);
                var m = s(m, g, h, f, r, 21, b[51]);
                var f = s(f, m, g, h, u, 6, b[52]);
                var h = s(h, f, m, g, k, 10, b[53]);
                var g = s(g, h, f, m, B, 15, b[54]);
                var m = s(m, g, h, f, e, 21, b[55]);
                var f = s(f, m, g, h, v, 6, b[56]);
                var h = s(h, f, m, g, x, 10, b[57]);
                var g = s(g, h, f, m, t, 15, b[58]);
                var m = s(m, g, h, f, D, 21, b[59]);
                var f = s(f, m, g, h, z, 6, b[60]);
                var h = s(h, f, m, g, C, 10, b[61]);
                var g = s(g, h, f, m, j, 15, b[62]);
                var m = s(m, g, h, f, A, 21, b[63]);
                a[0] = a[0] + f | 0;
                a[1] = a[1] + m | 0;
                a[2] = a[2] + g | 0;
                a[3] = a[3] + h | 0;
            },
            _doFinalize: function () {
                let b = this._data;
                let n = b.words;
                let a = 8 * this._nDataBytes;
                let c = 8 * b.sigBytes;
                n[c >>> 5] |= 128 << 24 - c % 32;
                let e = u.floor(a
                    / 4294967296);
                n[(c + 64 >>> 9 << 4) + 15] = (e << 8 | e >>> 24) & 16711935 | (e << 24 | e >>> 8) & 4278255360;
                n[(c + 64 >>> 9 << 4) + 14] = (a << 8 | a >>> 24) & 16711935 | (a << 24 | a >>> 8) & 4278255360;
                b.sigBytes = 4 * (n.length + 1);
                this._process();
                b = this._hash;
                n = b.words;
                for (a = 0; 4 > a; a++) {c = n[a], n[a] = (c << 8 | c >>> 24) & 16711935 | (c << 24 | c >>> 8) & 4278255360;}
                return b;
            },
            clone: function () {
                let b = v.clone.call(this);
                b._hash = this._hash.clone();
                return b;
            },
        });
        t.MD5 = v._createHelper(r);
        t.HmacMD5 = v._createHmacHelper(r);
    })(Math);
    (function () {
        let u = CryptoJS;
        var p = u.lib;
        let d = p.Base;
        let l = p.WordArray;
        var p = u.algo;
        let s = p.EvpKDF = d.extend({
            cfg: d.extend({
                keySize: 4,
                hasher: p.MD5,
                iterations: 1,
            }),
            init: function (d) {
                this.cfg = this.cfg.extend(d);
            },
            compute: function (d, r) {
                for (var p = this.cfg, s = p.hasher.create(), b = l.create(), u = b.words, q = p.keySize, p = p.iterations; u.length < q;) {
                    n && s.update(n);
                    var n = s.update(d).finalize(r);
                    s.reset();
                    for (let a = 1; a < p; a++) {n = s.finalize(n), s.reset();}
                    b.concat(n);
                }
                b.sigBytes = 4 * q;
                return b;
            },
        });
        u.EvpKDF = function (d, l, p) {
            return s.create(p).compute(d,
                l);
        };
    })();
    CryptoJS.lib.Cipher || (function (u) {
        var p = CryptoJS;
        let d = p.lib;
        let l = d.Base;
        let s = d.WordArray;
        let t = d.BufferedBlockAlgorithm;
        let r = p.enc.Base64;
        let w = p.algo.EvpKDF;
        let v = d.Cipher = t.extend({
            cfg: l.extend(),
            createEncryptor: function (e, a) {
                return this.create(this._ENC_XFORM_MODE, e, a);
            },
            createDecryptor: function (e, a) {
                return this.create(this._DEC_XFORM_MODE, e, a);
            },
            init: function (e, a, b) {
                this.cfg = this.cfg.extend(b);
                this._xformMode = e;
                this._key = a;
                this.reset();
            },
            reset: function () {
                t.reset.call(this);
                this._doReset();
            },
            process: function (e) {
                this._append(e);
                return this._process();
            },
            finalize: function (e) {
                e && this._append(e);
                return this._doFinalize();
            },
            keySize: 4,
            ivSize: 4,
            _ENC_XFORM_MODE: 1,
            _DEC_XFORM_MODE: 2,
            _createHelper: function (e) {
                return {
                    encrypt: function (b, k, d) {
                        return ('string' === typeof k ? c : a).encrypt(e, b, k, d);
                    },
                    decrypt: function (b, k, d) {
                        return ('string' === typeof k ? c : a).decrypt(e, b, k, d);
                    },
                };
            },
        });
        d.StreamCipher = v.extend({
            _doFinalize: function () {
                return this._process(!0);
            },
            blockSize: 1,
        });
        var b = p.mode = {};
        let x = function (e, a, b) {
            let c = this._iv;
            c ? this._iv = u : c = this._prevBlock;
            for (let d = 0; d < b; d++) {
                e[a + d]
                    ^= c[d];
            }
        };
        let q = (d.BlockCipherMode = l.extend({
            createEncryptor: function (e, a) {
                return this.Encryptor.create(e, a);
            },
            createDecryptor: function (e, a) {
                return this.Decryptor.create(e, a);
            },
            init: function (e, a) {
                this._cipher = e;
                this._iv = a;
            },
        })).extend();
        q.Encryptor = q.extend({
            processBlock: function (e, a) {
                let b = this._cipher;
                let c = b.blockSize;
                x.call(this, e, a, c);
                b.encryptBlock(e, a);
                this._prevBlock = e.slice(a, a + c);
            },
        });
        q.Decryptor = q.extend({
            processBlock: function (e, a) {
                let b = this._cipher;
                let c = b.blockSize;
                let d = e.slice(a, a + c);
                b.decryptBlock(e, a);
                x.call(this,
                    e, a, c);
                this._prevBlock = d;
            },
        });
        b = b.CBC = q;
        q = (p.pad = {}).Pkcs7 = {
            pad: function (a, b) {
                for (var c = 4 * b, c = c - a.sigBytes % c, d = c << 24 | c << 16 | c << 8 | c, l = [], n = 0; n < c; n += 4) {l.push(d);}
                c = s.create(l, c);
                a.concat(c);
            },
            unpad: function (a) {
                a.sigBytes -= a.words[a.sigBytes - 1 >>> 2] & 255;
            },
        };
        d.BlockCipher = v.extend({
            cfg: v.cfg.extend({
                mode: b,
                padding: q,
            }),
            reset: function () {
                v.reset.call(this);
                var a = this.cfg;
                let b = a.iv;
                var a = a.mode;
                if (this._xformMode == this._ENC_XFORM_MODE) {var c = a.createEncryptor;}
                else {c = a.createDecryptor, this._minBufferSize = 1;}
                this._mode = c.call(a,
                    this, b && b.words);
            },
            _doProcessBlock: function (a, b) {
                this._mode.processBlock(a, b);
            },
            _doFinalize: function () {
                let a = this.cfg.padding;
                if (this._xformMode == this._ENC_XFORM_MODE) {
                    a.pad(this._data, this.blockSize);
                    var b = this._process(!0);
                }
                else {b = this._process(!0), a.unpad(b);}
                return b;
            },
            blockSize: 4,
        });
        let n = d.CipherParams = l.extend({
            init: function (a) {
                this.mixIn(a);
            },
            toString: function (a) {
                return (a || this.formatter).stringify(this);
            },
        });
        var b = (p.format = {}).OpenSSL = {
            stringify: function (a) {
                let b = a.ciphertext;
                a = a.salt;
                return (a ? s.create([1398893684,
                    1701076831,
                ]).concat(a).concat(b) : b).toString(r);
            },
            parse: function (a) {
                a = r.parse(a);
                let b = a.words;
                if (1398893684 == b[0] && 1701076831 == b[1]) {
                    var c = s.create(b.slice(2, 4));
                    b.splice(0, 4);
                    a.sigBytes -= 16;
                }
                return n.create({
                    ciphertext: a,
                    salt: c,
                });
            },
        };
        var a = d.SerializableCipher = l.extend({
            cfg: l.extend({
                format: b,
            }),
            encrypt: function (a, b, c, d) {
                d = this.cfg.extend(d);
                let l = a.createEncryptor(c, d);
                b = l.finalize(b);
                l = l.cfg;
                return n.create({
                    ciphertext: b,
                    key: c,
                    iv: l.iv,
                    algorithm: a,
                    mode: l.mode,
                    padding: l.padding,
                    blockSize: a.blockSize,
                    formatter: d.format,
                });
            },
            decrypt: function (a, b, c, d) {
                d = this.cfg.extend(d);
                b = this._parse(b, d.format);
                return a.createDecryptor(c, d).finalize(b.ciphertext);
            },
            _parse: function (a, b) {
                return 'string' === typeof a ? b.parse(a, this) : a;
            },
        });
        var p = (p.kdf = {}).OpenSSL = {
            execute: function (a, b, c, d) {
                d || (d = s.random(8));
                a = w.create({
                    keySize: b + c,
                }).compute(a, d);
                c = s.create(a.words.slice(b), 4 * c);
                a.sigBytes = 4 * b;
                return n.create({
                    key: a,
                    iv: c,
                    salt: d,
                });
            },
        };
        var c = d.PasswordBasedCipher = a.extend({
            cfg: a.cfg.extend({
                kdf: p,
            }),
            encrypt: function (b, c, d, l) {
                l = this.cfg.extend(l);
                d = l.kdf.execute(d,
                    b.keySize, b.ivSize);
                l.iv = d.iv;
                b = a.encrypt.call(this, b, c, d.key, l);
                b.mixIn(d);
                return b;
            },
            decrypt: function (b, c, d, l) {
                l = this.cfg.extend(l);
                c = this._parse(c, l.format);
                d = l.kdf.execute(d, b.keySize, b.ivSize, c.salt);
                l.iv = d.iv;
                return a.decrypt.call(this, b, c, d.key, l);
            },
        });
    }());
    (function () {
        for (var u = CryptoJS, p = u.lib.BlockCipher, d = u.algo, l = [], s = [], t = [], r = [], w = [], v = [], b = [], x = [], q = [], n = [], a = [], c = 0; 256 > c; c++) {a[c] = 128 > c ? c << 1 : c << 1 ^ 283;}
        for (var e = 0, j = 0, c = 0; 256 > c; c++) {
            var k = j ^ j << 1 ^ j << 2 ^ j << 3 ^ j << 4;
            var k = k >>> 8 ^ k & 255 ^ 99;
            l[e] = k;
            s[k] = e;
            let z = a[e];
            let F = a[z];
            let G = a[F];
            let y = 257 * a[k] ^ 16843008 * k;
            t[e] = y << 24 | y >>> 8;
            r[e] = y << 16 | y >>> 16;
            w[e] = y << 8 | y >>> 24;
            v[e] = y;
            y = 16843009 * G ^ 65537 * F ^ 257 * z ^ 16843008 * e;
            b[k] = y << 24 | y >>> 8;
            x[k] = y << 16 | y >>> 16;
            q[k] = y << 8 | y >>> 24;
            n[k] = y;
            e ? (e = z ^ a[a[a[G ^ z]]], j ^= a[a[j]]) : e = j = 1;
        }
        let H = [0, 1, 2, 4, 8,
            16, 32, 64, 128, 27, 54,
        ];
        var d = d.AES = p.extend({
            _doReset: function () {
                for (var a = this._key, c = a.words, d = a.sigBytes / 4, a = 4 * ((this._nRounds = d + 6) + 1), e = this._keySchedule = [], j = 0; j < a; j++) {
                    if (j < d) {e[j] = c[j];}
                    else {
                        var k = e[j - 1];
                        j % d ? 6 < d && 4 == j % d && (k = l[k >>> 24] << 24 | l[k >>> 16 & 255] << 16 | l[k >>> 8 & 255] << 8 | l[k & 255]) : (k = k << 8 | k >>> 24, k = l[k >>> 24] << 24 | l[k >>> 16 & 255] << 16 | l[k >>> 8 & 255] << 8 | l[k & 255], k ^= H[j / d | 0] << 24);
                        e[j] = e[j - d] ^ k;
                    }
                } c = this._invKeySchedule = [];
                for (d = 0; d < a; d++) {
                    j = a - d, k = d % 4 ? e[j] : e[j - 4], c[d] = 4 > d || 4 >= j ? k : b[l[k >>> 24]] ^ x[l[k >>> 16 & 255]] ^ q[l[k
                        >>> 8 & 255]] ^ n[l[k & 255]];
                }
            },
            encryptBlock: function (a, b) {
                this._doCryptBlock(a, b, this._keySchedule, t, r, w, v, l);
            },
            decryptBlock: function (a, c) {
                let d = a[c + 1];
                a[c + 1] = a[c + 3];
                a[c + 3] = d;
                this._doCryptBlock(a, c, this._invKeySchedule, b, x, q, n, s);
                d = a[c + 1];
                a[c + 1] = a[c + 3];
                a[c + 3] = d;
            },
            _doCryptBlock: function (a, b, c, d, e, j, l, f) {
                for (var m = this._nRounds, g = a[b] ^ c[0], h = a[b + 1] ^ c[1], k = a[b + 2] ^ c[2], n = a[b + 3] ^ c[3], p = 4, r = 1; r < m; r++) {
                    var q = d[g >>> 24] ^ e[h >>> 16 & 255] ^ j[k >>> 8 & 255] ^ l[n & 255] ^ c[p++];
                    var s = d[h >>> 24] ^ e[k >>> 16 & 255] ^ j[n >>> 8 & 255] ^ l[g & 255] ^ c[p++];
                    var t
                        = d[k >>> 24] ^ e[n >>> 16 & 255] ^ j[g >>> 8 & 255] ^ l[h & 255] ^ c[p++];
                    var n = d[n >>> 24] ^ e[g >>> 16 & 255] ^ j[h >>> 8 & 255] ^ l[k & 255] ^ c[p++];
                    var g = q;
                    var h = s;
                    var k = t;
                }
                q = (f[g >>> 24] << 24 | f[h >>> 16 & 255] << 16 | f[k >>> 8 & 255] << 8 | f[n & 255]) ^ c[p++];
                s = (f[h >>> 24] << 24 | f[k >>> 16 & 255] << 16 | f[n >>> 8 & 255] << 8 | f[g & 255]) ^ c[p++];
                t = (f[k >>> 24] << 24 | f[n >>> 16 & 255] << 16 | f[g >>> 8 & 255] << 8 | f[h & 255]) ^ c[p++];
                n = (f[n >>> 24] << 24 | f[g >>> 16 & 255] << 16 | f[h >>> 8 & 255] << 8 | f[k & 255]) ^ c[p++];
                a[b] = q;
                a[b + 1] = s;
                a[b + 2] = t;
                a[b + 3] = n;
            },
            keySize: 8,
        });
        u.AES = p._createHelper(d);
    })();


    CryptoJS.encrypt = function (word, key, iv) {
        return encrypt(word, key, iv);
    };



    /**
     * 加密
     * word：原密码
     * key ：key
     * iv  ： iv
     */
    function encrypt(word, key, iv) {
        var key = CryptoJS.enc.Utf8.parse(key);
        var iv = CryptoJS.enc.Utf8.parse(iv);
        let encrypted = '';
        let srcs = '';
        if (typeof (word) === 'string') {
            srcs = word;
        }
        else if (typeof (word) === 'object') { // 对象格式的转成json字符串
            srcs = CryptoJS.enc.Utf8.parse(word);
        }
        encrypted = CryptoJS.AES.encrypt(srcs, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7,
        });
        return encrypted.ciphertext.toString();
    }


    /**
     * @example
     * var CryptoJS = require('./../../../util/aes.js')
     * var key = CryptoJS.enc.Utf8.parse("key");
     * var iv = CryptoJS.enc.Utf8.parse("iv");
     * var pwd = CryptoJS.encrypt(this.data.pwdVal, key, iv)
     * var original = CryptoJS.encrypt(pwd, key, iv)
     */
    var aes = CryptoJS;

    let chrsz$1 = 8; /* bits per input character. 8 - ASCII; 16 - Unicode      */

    /*
     * These are the functions you'll usually want to call
     * They take string arguments and return either hex or base-64 encoded strings
     */
    function hex_md5$1(s) {
        return binl2hex$1(core_md5$1(str2binl$1(s), s.length * chrsz$1));
    }

    /*
     * Calculate the MD5 of an array of little-endian words, and a bit length
     */
    function core_md5$1(x, len) {
        /* append padding */
        x[len >> 5] |= 0x80 << ((len) % 32);
        x[(((len + 64) >>> 9) << 4) + 14] = len;

        let a = 1732584193;
        let b = -271733879;
        let c = -1732584194;
        let d = 271733878;

        for (let i = 0; i < x.length; i += 16) {
            let olda = a;
            let oldb = b;
            let oldc = c;
            let oldd = d;

            a = md5_ff$1(a, b, c, d, x[i + 0], 7, -680876936);
            d = md5_ff$1(d, a, b, c, x[i + 1], 12, -389564586);
            c = md5_ff$1(c, d, a, b, x[i + 2], 17, 606105819);
            b = md5_ff$1(b, c, d, a, x[i + 3], 22, -1044525330);
            a = md5_ff$1(a, b, c, d, x[i + 4], 7, -176418897);
            d = md5_ff$1(d, a, b, c, x[i + 5], 12, 1200080426);
            c = md5_ff$1(c, d, a, b, x[i + 6], 17, -1473231341);
            b = md5_ff$1(b, c, d, a, x[i + 7], 22, -45705983);
            a = md5_ff$1(a, b, c, d, x[i + 8], 7, 1770035416);
            d = md5_ff$1(d, a, b, c, x[i + 9], 12, -1958414417);
            c = md5_ff$1(c, d, a, b, x[i + 10], 17, -42063);
            b = md5_ff$1(b, c, d, a, x[i + 11], 22, -1990404162);
            a = md5_ff$1(a, b, c, d, x[i + 12], 7, 1804603682);
            d = md5_ff$1(d, a, b, c, x[i + 13], 12, -40341101);
            c = md5_ff$1(c, d, a, b, x[i + 14], 17, -1502002290);
            b = md5_ff$1(b, c, d, a, x[i + 15], 22, 1236535329);

            a = md5_gg$1(a, b, c, d, x[i + 1], 5, -165796510);
            d = md5_gg$1(d, a, b, c, x[i + 6], 9, -1069501632);
            c = md5_gg$1(c, d, a, b, x[i + 11], 14, 643717713);
            b = md5_gg$1(b, c, d, a, x[i + 0], 20, -373897302);
            a = md5_gg$1(a, b, c, d, x[i + 5], 5, -701558691);
            d = md5_gg$1(d, a, b, c, x[i + 10], 9, 38016083);
            c = md5_gg$1(c, d, a, b, x[i + 15], 14, -660478335);
            b = md5_gg$1(b, c, d, a, x[i + 4], 20, -405537848);
            a = md5_gg$1(a, b, c, d, x[i + 9], 5, 568446438);
            d = md5_gg$1(d, a, b, c, x[i + 14], 9, -1019803690);
            c = md5_gg$1(c, d, a, b, x[i + 3], 14, -187363961);
            b = md5_gg$1(b, c, d, a, x[i + 8], 20, 1163531501);
            a = md5_gg$1(a, b, c, d, x[i + 13], 5, -1444681467);
            d = md5_gg$1(d, a, b, c, x[i + 2], 9, -51403784);
            c = md5_gg$1(c, d, a, b, x[i + 7], 14, 1735328473);
            b = md5_gg$1(b, c, d, a, x[i + 12], 20, -1926607734);

            a = md5_hh$1(a, b, c, d, x[i + 5], 4, -378558);
            d = md5_hh$1(d, a, b, c, x[i + 8], 11, -2022574463);
            c = md5_hh$1(c, d, a, b, x[i + 11], 16, 1839030562);
            b = md5_hh$1(b, c, d, a, x[i + 14], 23, -35309556);
            a = md5_hh$1(a, b, c, d, x[i + 1], 4, -1530992060);
            d = md5_hh$1(d, a, b, c, x[i + 4], 11, 1272893353);
            c = md5_hh$1(c, d, a, b, x[i + 7], 16, -155497632);
            b = md5_hh$1(b, c, d, a, x[i + 10], 23, -1094730640);
            a = md5_hh$1(a, b, c, d, x[i + 13], 4, 681279174);
            d = md5_hh$1(d, a, b, c, x[i + 0], 11, -358537222);
            c = md5_hh$1(c, d, a, b, x[i + 3], 16, -722521979);
            b = md5_hh$1(b, c, d, a, x[i + 6], 23, 76029189);
            a = md5_hh$1(a, b, c, d, x[i + 9], 4, -640364487);
            d = md5_hh$1(d, a, b, c, x[i + 12], 11, -421815835);
            c = md5_hh$1(c, d, a, b, x[i + 15], 16, 530742520);
            b = md5_hh$1(b, c, d, a, x[i + 2], 23, -995338651);

            a = md5_ii$1(a, b, c, d, x[i + 0], 6, -198630844);
            d = md5_ii$1(d, a, b, c, x[i + 7], 10, 1126891415);
            c = md5_ii$1(c, d, a, b, x[i + 14], 15, -1416354905);
            b = md5_ii$1(b, c, d, a, x[i + 5], 21, -57434055);
            a = md5_ii$1(a, b, c, d, x[i + 12], 6, 1700485571);
            d = md5_ii$1(d, a, b, c, x[i + 3], 10, -1894986606);
            c = md5_ii$1(c, d, a, b, x[i + 10], 15, -1051523);
            b = md5_ii$1(b, c, d, a, x[i + 1], 21, -2054922799);
            a = md5_ii$1(a, b, c, d, x[i + 8], 6, 1873313359);
            d = md5_ii$1(d, a, b, c, x[i + 15], 10, -30611744);
            c = md5_ii$1(c, d, a, b, x[i + 6], 15, -1560198380);
            b = md5_ii$1(b, c, d, a, x[i + 13], 21, 1309151649);
            a = md5_ii$1(a, b, c, d, x[i + 4], 6, -145523070);
            d = md5_ii$1(d, a, b, c, x[i + 11], 10, -1120210379);
            c = md5_ii$1(c, d, a, b, x[i + 2], 15, 718787259);
            b = md5_ii$1(b, c, d, a, x[i + 9], 21, -343485551);

            a = safe_add$1(a, olda);
            b = safe_add$1(b, oldb);
            c = safe_add$1(c, oldc);
            d = safe_add$1(d, oldd);
        }
        return Array(a, b, c, d);

    }


    /*
     * These functions implement the four basic operations the algorithm uses.
     */
    function md5_cmn$1(q, a, b, x, s, t) {
        return safe_add$1(bit_rol$1(safe_add$1(safe_add$1(a, q), safe_add$1(x, t)), s), b);
    }

    function md5_ff$1(a, b, c, d, x, s, t) {
        return md5_cmn$1((b & c) | ((~b) & d), a, b, x, s, t);
    }

    function md5_gg$1(a, b, c, d, x, s, t) {
        return md5_cmn$1((b & d) | (c & (~d)), a, b, x, s, t);
    }

    function md5_hh$1(a, b, c, d, x, s, t) {
        return md5_cmn$1(b ^ c ^ d, a, b, x, s, t);
    }

    function md5_ii$1(a, b, c, d, x, s, t) {
        return md5_cmn$1(c ^ (b | (~d)), a, b, x, s, t);
    }

    /*
     * Add integers, wrapping at 2^32. This uses 16-bit operations internally
     * to work around bugs in some JS interpreters.
     */
    function safe_add$1(x, y) {
        let lsw = (x & 0xFFFF) + (y & 0xFFFF);
        let msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    /*
     * Bitwise rotate a 32-bit number to the left.
     */
    function bit_rol$1(num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }

    /*
     * Convert a string to an array of little-endian words
     * If chrsz is ASCII, characters >255 have their hi-byte silently ignored.
     */
    function str2binl$1(str) {
        let bin = Array();
        let mask = (1 << chrsz$1) - 1;
        for (let i = 0; i < str.length * chrsz$1; i += chrsz$1) {bin[i >> 5] |= (str.charCodeAt(i / chrsz$1) & mask) << (i % 32);}
        return bin;
    }

    /*
     * Convert an array of little-endian words to a hex string.
     */
    function binl2hex$1(binarray) {
        let hex_tab = '0123456789abcdef';
        let str = '';
        for (let i = 0; i < binarray.length * 4; i++) {
            str += hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF)
    			+ hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8)) & 0xF);
        }
        return str;
    }

    function isJSON(str) {
        if (typeof str === 'string') {
            try {
                let obj = JSON.parse(str);
                if (typeof obj === 'object' && obj) {
                    return true;
                }
                return false;


            }
            catch (e) {

                return false;
            }
        }
    }
    // 生成uuid
    function getUuid$1(len, radix) {
        let chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
        let uuid = [];
        let i;
        radix = radix || chars.length;

        if (len) {
            for (i = 0; i < len; i++) {uuid[i] = chars[0 | Math.random() * radix];}
        }
        else {
            let r;

            uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-';
            uuid[14] = '4';

            for (i = 0; i < 36; i++) {
                if (!uuid[i]) {
                    r = 0 | Math.random() * 16;
                    uuid[i] = chars[(i == 19) ? (r & 0x3) | 0x8 : r];
                }
            }
        }
        return uuid.join('');
    }

    function dateFormat$2(obj, fmt) {
        let o = {
            'M+': obj.getMonth() + 1, // 月份
            'd+': obj.getDate(), // 日
            'h+': obj.getHours(), // 小时
            'm+': obj.getMinutes(), // 分
            's+': obj.getSeconds(), // 秒
            'q+': Math.floor((obj.getMonth() + 3) / 3), // 季度
            'S+': obj.getMilliseconds(), // 毫秒
        };
        if (/(y+)/.test(fmt)) {
            fmt = fmt.replace(RegExp.$1, (obj.getFullYear() + '').substr(4 - RegExp.$1.length));
        }
        for (let k in o) {
            if (new RegExp('(' + k + ')').test(fmt)) {
                fmt = fmt.replace(RegExp.$1, (RegExp.$1.length == 1) ? (o[k]) : ((((RegExp.$1.length == 3 && k == 'S+') ? '000'
                    : '00') + o[k]).substr(('' + o[k]).length)));
            }
        }
        return fmt;
    }

    function getSystem() {
        const res = wx.getSystemInfoSync();
        if (res.platform === 'android') {
            return '0';
        }
        else if (res.platform === 'ios') {
            return '1';
        }
        return '2';

    }

    function getCurUrl() {
        let pages = getCurrentPages(); // 获取加载的页面
        let currentPage = pages[pages.length - 1]; // 获取当前页面的对象
        let url = currentPage.route; // 当前页面url

        let options = currentPage.options;
        if (options) {
            let param = '';
            for (let key in options) {
                let str = key + '=' + options[key];
                param = param + str + '&';
            }
            url = url + '?' + param;
            url = url.substr(0, url.length - 1);
        }
        return url;
    }




    /**
     * 获取最外层窗口浏览器的信息,获取不到就返回为空
     */
    function getBrowserInfo$1() {
        try {
            const res = wx.getSystemInfoSync();
            let str = res.brand + '@@'
    			+ res.model + '@@'
    			+ res.pixelRatio + '@@'
    			+ res.screenWidth + '@@'
    			+ res.screenHeight + '@@'
    			+ res.language + '@@'
    			+ res.version + '@@'
    			+ res.system + '@@'
    			+ res.platform + '@@'
    			+ res.SDKVersion + '@@'
    			+ res.benchmarkLevel + '@@'
    			+ new Date().getTimezoneOffset();
            let BrowserInfo = encodeURIComponent(res.brand + '@@' + res.version + '@@' + res.system + '@@' + hex_md5$1(str));
            return BrowserInfo;
        }
        catch (e) {
            // Do something when catch error
        }

    }

    // 创建公共参数
    let optparam$1 = {
        v: '20210721',
        traceId: '',
        msgId: '',
        timestamp: dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS'),
        userInformation: getBrowserInfo$1(),
        businessType: '8',
        ywType: 'CT',
        isLoading: true,
        maskPhone: '',
        httpsPreGetmobile: {
            test01: 'https://testcert.cmpassport.com:7009/h5/httpsPreGetmobile',
            // test01: "https://120.197.235.102:7009/h5/httpsPreGetmobile",
            // test01: "https://120.197.235.102:7009/h5/httpsPreGetmobile",
            pro: 'https://verify.cmpassport.com/h5/httpsPreGetmobile',
        },

        // 电信预取号
        getTelecomUrl: {
            test01: 'http://120.197.235.102/h5/onekeylogin/getNewTelecomPhonescrip',
            // test01: "http://10.153.99.55:35081/h5/onekeylogin/getNewTelecomPhonescrip",
            pro: 'https://www.cmpassport.com/h5/onekeylogin/getNewTelecomPhonescrip',
        },
        // 电信回调
        getTelecomToken: {
            test01: 'http://120.197.235.102/h5/onekeylogin/CTCallback',
            // test01: "http://10.153.99.55:35081/h5/onekeylogin/CTCallback",
            pro: 'https://www.cmpassport.com/h5/onekeylogin/CTCallback',
        },
        // 联通预取号
        getUnicomUrl: {
            test01: 'http://120.197.235.102//h5/onekeylogin/getNewUnicomPhonescrip',
            // test01: "http://10.153.99.55:35081//h5/onekeylogin/getNewUnicomPhonescrip",
            pro: 'https://www.cmpassport.com/h5/onekeylogin/getNewUnicomPhonescrip',
        },
        // 联通回调
        getUnicomToken: {
            test01: 'http://120.197.235.102//h5/onekeylogin/CUCallback',
            // test01: "http://10.153.99.55:35081//h5/onekeylogin/CUCallback",
            pro: 'https://www.cmpassport.com/h5/onekeylogin/CUCallback',
        },
        logReport: {
            pro: 'https://log-h5.cmpassport.com:9443/log/logReport',
        },
        getToken: {
            test01: 'http://120.197.235.102/h5/onekeylogin/authGetToken',
            // test01:'http://10.153.99.55:35082/h5/onekeylogin/authGetToken',
            pro: 'https://www.cmpassport.com//h5/onekeylogin/authGetToken',
        },
        jssdkLog: {
            traceid: '',
            appScene: '1',
            wxappid: '',
            appid: '',
            networkType: '',
            clientType: '',
            costtime_GetOwnerAppValidate: '',
            CMrequestTime_PreGetmobile: '',
            CMresponseTime_PreGetmobile: '',
            CM_resultCode: '',
            CTrequestTime_PreGetmobile: '',
            CTresponseTime_PreGetmobile: '',
            CT_resultCode: '',
            CUrequestTime_PreGetmobile: '',
            CUresponseTime_PreGetmobile: '',
            CU_resultCode: '',
            polling_PreGetmobile: '',
        },
    };
    var yd_auth = {
        // 获取网络类型
        getConnection: function (data) {
            let net = null;
            if (optparam$1.msgId == '') {
                optparam$1.msgId = getUuid$1(32, 32);
            }
            try {
                wx.getNetworkType({
                    success: function (res) {
                        net = {
                            appid: data.appId,
                            msgid: optparam$1.msgId,
                            netType: res.networkType,
                            message: '获取成功',
                        };
                        data.success(net);
                    },
                    fail: function (res) {
                        net = {
                            appid: data.appId,
                            msgid: optparam$1.msgId,
                            netType: '',
                            message: '获取失败',
                        };
                        data.error(net);
                    },

                });
            }
            catch (e) {}
        },
        getTokenInfo: function (opt) {
            let _this = this;
            if (!optparam$1.isLoading) {
                return;
            }
            for (let key in optparam$1.jssdkLog) {
                optparam$1.jssdkLog[key] = '';
            }
            optparam$1.isLoading = false;
            optparam$1.ywType = 'CT';
            const accountInfo = wx.getAccountInfoSync();
            optparam$1.msgId = opt.data.traceId;
            let options = {
                version: opt.data.version,
                // 业务方参数
                appId: opt.data.appId,
                openType: opt.data.openType,
                expandParams: opt.data.expandParams,
                isTest: opt.data.isTest,
                sign: opt.data.sign,
                succ: opt.success,
                err: opt.error,
                traceId: opt.data.traceId,
                msgId: opt.data.traceId,
                timestamp: opt.data.timestamp,
                // 公共参数
                userInformation: optparam$1.userInformation,
                wxappid: accountInfo.miniProgram.appId,
                businessType: optparam$1.businessType,
            };
            optparam$1.jssdkLog.appid = options.appId;
            optparam$1.jssdkLog.appScene = '1';
            optparam$1.jssdkLog.traceid = options.traceId;
            optparam$1.jssdkLog.wxappid = options.wxappid;
            optparam$1.jssdkLog.clientType = wx.getSystemInfoSync().platform;
            wx.getNetworkType({
                success: function (res) {
                    if (res.networkType == 'wifi') {
                        optparam$1.jssdkLog.networkType = res.networkType;
                        let error = {
                            code: '504',
                            message: '网络环境不支持取号',
                            msgId: options.msgId,
                        };
                        optparam$1.isLoading = true;
                        options.err(error);

                    }
                    else {

                        _this.getYDPhoneNumber(options);
                    }
                },
                fail: function (res) {
                    net = {
                        appid: data.appId,
                        msgid: optparam$1.msgId,
                        netType: '',
                        message: '获取网络环境失败',
                    };
                    data.error(net);
                },

            });

        },
        getYDPhoneNumber: function (options) {
            let _this = this;

            // 组装请求参数
            let param = {
                // header: {
                version: options.version,
                timestamp: options.timestamp,
                appId: options.appId,
                businessType: options.businessType,
                traceId: options.traceId,
                // },
                // body: {
                sign: options.sign,
                msgId: options.msgId,
                userInformation: options.userInformation,
                expandParams: options.expandParams,
                wxappid: options.wxappid,
                // }
            };
            let reqUrl = options.isTest === '0' ? optparam$1.httpsPreGetmobile.test01 : optparam$1.httpsPreGetmobile.pro;
            optparam$1.jssdkLog.CMrequestTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
            wx.request({
                url: reqUrl,
                data: JSON.stringify(param),
                method: 'post',
                header: {
                    'content-type': 'application/json',
                },
                success(res) {
                    res = res.data.body;
                    optparam$1.jssdkLog.CMresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                    optparam$1.jssdkLog.CM_resultCode = res.resultCode;
                    if (res.resultCode === '103000') {
                        let option = {
                            resultCode: res.resultCode,
                            authPageUrl: res.authPageUrl,
                            traceId: options.traceId,
                            accessToken: res.accessToken,
                            maskPhone: res.maskPhone,
                            authLevel: res.authLevel,
                            appName: res.appName,
                            userInformation: options.userInformation,
                            appId: options.appId,
                            expandParams: options.expandParams,
                            isTest: options.isTest,
                            succ: options.succ,
                            err: options.err,
                            customerPrivacyConfig: res.customerPrivacyConfig,
                            oper: 'CM',
                        };
                        _this.getAuthentication(option);
                    }
                    else {
                        options.YDData = {
                            code: res.resultCode,
                            message: res.resultDesc,
                        };
                        _this.getYWpre(options);

                    }

                },
                fail(res) {
                    optparam$1.jssdkLog.CMresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                    optparam$1.jssdkLog.CM_resultCode = '500';
                    options.YDData = {
                        code: '500',
                        message: '网络异常，请检查网络设置',
                    };
                    _this.getYWpre(options);
                },
            });
        },
        // 异网预取号
        getYWpre: function (opt) {
            let _this = this;
            let encrypted = getUuid$1(16, 16);

            let keyStr = hex_md5$1(encrypted).substr(8, 16).toUpperCase();
            let mobilesystem = getSystem();

            let sign = hex_md5$1(opt.appId + '1.0' + opt.msgId + opt.timestamp).toLowerCase();

            let reqdata = {
                ver: '1.0',
                appId: opt.appId,
                interfaceVersion: '1.0',
                expandParams: opt.expandParams,
                msgId: opt.msgId,
                timestamp: opt.timestamp,
                mobilesystem: mobilesystem,
                wxappid: opt.wxappid,
                sign: sign,
            };
            reqdata = JSON.stringify(reqdata);
            reqdata = aes.encrypt(reqdata, keyStr, '0000000000000000');

            let param = {
                header: {
                    appId: opt.appId,
                    interfaceVersion: opt.version,
                    traceId: opt.traceId,
                    'content-type': 'application/json',
                },
                body: {
                    encrypted: encrypted,
                    reqdata: reqdata,
                    businessType: opt.businessType,
                    wxappid: opt.wxappid,
                },

            };
            if (optparam$1.ywType == 'CT') {
                var reqUrl = opt.isTest === '0' ? optparam$1.getTelecomUrl.test01 : optparam$1.getTelecomUrl.pro;
                optparam$1.jssdkLog.CTrequestTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
            }
            else if (optparam$1.ywType == 'CU') {
                var reqUrl = opt.isTest === '0' ? optparam$1.getUnicomUrl.test01 : optparam$1.getUnicomUrl.pro;
                optparam$1.jssdkLog.CUrequestTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');

            }

            wx.request({
                url: reqUrl,
                header: param.header,
                data: JSON.stringify(param.body),
                method: 'post',
                success(res) {
                    res = res.data;
                    if (res.resultCode == '103000') {
                        _this.getYW(opt, res.data);
                    }
                    else if (res.resultCode != '103000' && optparam$1.ywType == 'CT') {
                        optparam$1.jssdkLog.CTresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                        optparam$1.jssdkLog.CT_resultCode = res.resultCode;
                        opt.CTData = {
                            code: res.resultCode,
                            message: res.desc,
                        };
                        optparam$1.ywType = 'CU';
                        _this.getYWpre(opt);


                    }
                    else {
                        optparam$1.jssdkLog.CUresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                        optparam$1.jssdkLog.CU_resultCode = res.resultCode;
                        opt.CUData = {
                            code: res.resultCode,
                            message: res.desc,
                        };
                        let error = {
                            msgId: opt.msgId,
                            CUData: opt.CUData,
                            CTData: opt.CTData,
                            YDData: opt.YDData,
                        };
                        optparam$1.isLoading = true;
                        opt.err(error);
                        _this.getLog();
                    }

                },
                fail(res) {
                    if (optparam$1.ywType == 'CT') {
                        optparam$1.jssdkLog.CTresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                        optparam$1.jssdkLog.CT_resultCode = '500';
                        opt.CTData = {
                            code: '500',
                            message: '网络异常，请检查网络设置',
                        };
                        optparam$1.ywType = 'CU';
                        _this.getYWpre(opt);
                    }
                    else {
                        optparam$1.jssdkLog.CUresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                        optparam$1.jssdkLog.CU_resultCode = '500';
                        opt.CUData = {
                            code: '500',
                            message: '网络异常，请检查网络设置',
                        };
                        let error = {
                            msgId: opt.msgId,
                            CUData: opt.CUData,
                            CTData: opt.CTData,
                            YDData: opt.YDData,
                        };
                        optparam$1.isLoading = true;
                        opt.err(error);
                        _this.getLog();
                    }
                },
            });

        },
        // 异网取号
        getYW: function (opt, reqUrl) {
            let _this = this;
            wx.request({
                url: reqUrl,
                method: 'get',
                success(res) {

                    res = res.data;

                    if (JSON.stringify(res).indexOf('(') > 0) {
                        var ds = JSON.parse(res.match(/\(([^)]*)\)/)[1]);
                    }
                    else {
                        var ds = res;
                    }
                    if (ds.result == '0') {
                        _this.getYWcb(opt, ds.data);
                    }
                    else {
                        if (optparam$1.ywType == 'CT') {
                            optparam$1.jssdkLog.CTresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                            optparam$1.jssdkLog.CT_resultCode = ds.result.toString();
                            opt.CTData = {
                                code: ds.result.toString(),
                                message: ds.data,
                            };
                            optparam$1.ywType = 'CU';
                            _this.getYWpre(opt);
                        }
                        else {
                            optparam$1.jssdkLog.CUresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                            optparam$1.jssdkLog.CU_resultCode = ds.code;
                            // 返回错误
                            opt.CUData = {
                                code: ds.code,
                                message: ds.msg,
                                result: ds.result,
                            };
                            let error = {
                                msgId: opt.msgId,
                                CUData: opt.CUData,
                                CTData: opt.CTData,
                                YDData: opt.YDData,
                            };
                            optparam$1.isLoading = true;
                            opt.err(error);
                            _this.getLog();
                        }

                    }
                },
                fail(res) {
                    if (optparam$1.ywType == 'CT') {
                        optparam$1.jssdkLog.CTresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                        optparam$1.jssdkLog.CT_resultCode = '500';
                        opt.CTData = {
                            code: '500',
                            message: '网络异常，请检查网络设置',
                        };
                        optparam$1.ywType = 'CU';
                        _this.getYWpre(opt);
                    }
                    else {
                        optparam$1.jssdkLog.CUresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                        optparam$1.jssdkLog.CU_resultCode = '500';
                        opt.CUData = {
                            code: '500',
                            message: '网络异常，请检查网络设置',
                        };
                        let error = {
                            msgId: opt.msgId,
                            CUData: opt.CUData,
                            CTData: opt.CTData,
                            YDData: opt.YDData,
                        };
                        optparam$1.isLoading = true;
                        opt.err(error);
                        _this.getLog();
                    }
                },
            });

        },
        // 异网取号回调
        getYWcb: function (opt, data) {
            let _this = this;
            let param = {
                header: {
                    appId: opt.appId,
                    interfaceVersion: opt.version,
                    traceId: opt.traceId,
                    businessType: opt.businessType,
                    timestamp: opt.timestamp,
                    wxappid: opt.wxappid,
                    'content-type': 'application/json',
                },
                body: {
                    data: data,
                    ver: '1.0',
                    userInformation: opt.userInformation,
                },

            };
            if (optparam$1.ywType == 'CT') {
                var reqUrl = opt.isTest === '0' ? optparam$1.getTelecomToken.test01 : optparam$1.getTelecomToken.pro;
            }
            else if (optparam$1.ywType == 'CU') {
                var reqUrl = opt.isTest === '0' ? optparam$1.getUnicomToken.test01 : optparam$1.getUnicomToken.pro;
            }
            wx.request({
                url: reqUrl,
                header: param.header,
                data: JSON.stringify(param.body),
                method: 'post',
                success(res) {
                    res = res.data;
                    if (optparam$1.ywType == 'CT') {
                        optparam$1.jssdkLog.CTresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                        optparam$1.jssdkLog.CT_resultCode = res.resultCode;
                    }
                    else {
                        optparam$1.jssdkLog.CUresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                        optparam$1.jssdkLog.CU_resultCode = res.resultCode;
                    }
                    if (res.resultCode == '103000' && res.accessToken != '') {

                        let option = {
                            resultCode: res.resultCode,
                            authPageUrl: res.authPageUrl,
                            traceId: opt.traceId,
                            accessToken: res.accessToken,
                            maskPhone: res.maskPhone,
                            authLevel: res.authLevel,
                            appName: res.appName,
                            userInformation: opt.userInformation,
                            appId: opt.appId,
                            expandParams: opt.expandParams,
                            isTest: opt.isTest,
                            succ: opt.succ,
                            err: opt.err,
                            oper: optparam$1.ywType,
                            customerPrivacyConfig: res.customerPrivacyConfig,
                        };
                        _this.getAuthentication(option);
                    }
                    else {
                        if (optparam$1.ywType == 'CT') {
                            opt.CTData = {
                                code: '',
                                message: '',
                            };
                            opt.CTData.code = res.resultCode == '103000' ? '502' : res.resultCode;
                            opt.CTData.message = res.resultCode == '103000' ? '电信取号能力关闭' : res.desc;

                            var error = {
                                msgId: opt.msgId,
                                CUData: {},
                                CTData: opt.CTData,
                                YDData: opt.YDData,
                            };
                            optparam$1.isLoading = true;
                            opt.err(error);
                            _this.getLog();
                        }
                        else {
                            opt.CUData = {
                                code: '',
                                message: '',
                            };
                            opt.CUData.code = res.resultCode == '103000' ? '502' : res.resultCode;
                            opt.CUData.message = res.resultCode == '103000' ? '联通取号能力关闭' : res.desc;

                            var error = {
                                msgId: opt.msgId,
                                CUData: opt.CUData,
                                CTData: opt.CTData,
                                YDData: opt.YDData,
                            };
                            optparam$1.isLoading = true;
                            opt.err(error);
                            _this.getLog();

                        }
                    }

                },
                fail(res) {
                    if (optparam$1.ywType == 'CT') {
                        optparam$1.jssdkLog.CTresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                        optparam$1.jssdkLog.CT_resultCode = '500';
                        opt.CTData = {
                            code: '500',
                            message: '网络异常，请检查网络设置',
                        };
                        var error = {
                            msgId: opt.msgId,
                            CUData: {},
                            CTData: opt.CTData,
                            YDData: opt.YDData,
                        };
                        optparam$1.isLoading = true;
                        opt.err(error);
                        _this.getLog();
                    }
                    else {
                        optparam$1.jssdkLog.CUresponseTime_PreGetmobile = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
                        optparam$1.jssdkLog.CU_resultCode = '500';
                        opt.CUData = {
                            code: '500',
                            message: '网络异常，请检查网络设置',
                        };
                        var error = {
                            msgId: opt.msgId,
                            CUData: opt.CUData,
                            CTData: opt.CTData,
                            YDData: opt.YDData,
                        };
                        optparam$1.isLoading = true;
                        opt.err(error);
                        _this.getLog();
                    }
                },
            });

        },
        getAuthentication(option) {
            let _this = this;
            if (!!option.authPageUrl && !!option.authLevel && !!option.accessToken && option.authLevel != '5') {
                let url = getCurUrl();
                let authUrl = option.authPageUrl
    				+ '?traceId=' + option.traceId
    				+ '&accessToken=' + option.accessToken
    				+ '&maskPhone=' + option.maskPhone
    				+ '&authLevel=' + option.authLevel
    				+ '&authName=' + option.appName
    				+ '&userInformation=' + option.userInformation
    				+ '&appId=' + option.appId
    				+ '&expandParams=' + option.expandParams
    				+ '&isTest=' + option.isTest
    				+ '&oper=' + option.oper
    				+ '&cur=' + url
    				+ '&v=' + optparam$1.v;

                if (isJSON(option.customerPrivacyConfig)) {
                    authUrl += '&customerPrivacyConfig=' + encodeURIComponent(option.customerPrivacyConfig);
                }
                optparam$1.isLoading = true;
                option.succ({
                    code: option.resultCode,
                    authUrl: authUrl,
                });
                _this.getLog();
            }
            else if (!!option.authPageUrl && !!option.authLevel && !!option.accessToken && option.authLevel == '5') {
                optparam$1.maskPhone = option.maskPhone;
                let obj = {
                    code: option.resultCode,
                    oper: option.oper,
                    maskPhone: option.maskPhone,
                    accessToken: option.accessToken,
                    traceId: option.traceId,
                    message: '获取AccessToken成功',
                };
                optparam$1.isLoading = true;
                option.succ(obj);
                _this.getLog();
            }
            else {
                let error = {
                    code: '503',
                    message: '参数缺失',
                    msgId: option.traceId,
                };
                optparam$1.isLoading = true;
                option.err(error);
                _this.getLog();
            }

        },
        authGetToken: function (opt) {
            let maskPhone = opt.data.maskPhone ? opt.data.maskPhone : optparam$1.maskPhone;
            let str = maskPhone.replace(/\*+/g, opt.data.maskVal);
            let phone = hex_md5$1(str);
            optparam$1.authGetTokenSucc = 'undefined' === typeof opt.success ? function () {} : opt.success;
            optparam$1.authGetTokenErr = 'undefined' === typeof opt.error ? function () {} : opt.error;
            let param = {
                header: {
                    interfaceVersion: opt.data.version,
                    timestamp: dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS'),
                    appId: opt.data.appId,
                    businessType: optparam$1.businessType,
                    traceId: opt.data.traceId,
                    'Content-Type': 'application/json',
                },
                body: {
                    wxappid: wx.getAccountInfoSync().miniProgram.appId,
                    accessToken: opt.data.accessToken,
                    phone: phone,
                    userInformation: optparam$1.userInformation,
                    expandParams: opt.data.expandParams,
                },
            };
            let reqUrl = opt.data.isTest === '0' ? optparam$1.getToken.test01 : optparam$1.getToken.pro;
            wx.request({
                url: reqUrl,
                data: JSON.stringify(param.body),
                method: 'post',
                header: param.header,
                success(res) {
                    if (res.data.resultCode == '103000') {
                        var obj = {
                            code: res.data.resultCode,
                            message: res.data.desc,
                            msgId: opt.data.traceId,
                            token: res.data.token,
                            userInformation: optparam$1.userInformation,
                        };
                        optparam$1.authGetTokenSucc(obj);
                    }
                    else {
                        var obj = {
                            code: res.data.resultCode,
                            message: res.data.desc,
                            msgId: opt.data.traceId,
                        };
                        optparam$1.authGetTokenErr(obj);
                    }
                },
                fail(res) {

                },
            });
        },
        getLog() {
            let version = '2.0';
            let appId = optparam$1.jssdkLog.appid;
            let timestamp = dateFormat$2(new Date(), 'yyyyMMddhhmmssSSS');
            let str = version + appId + timestamp + optparam$1.jssdkLog.traceid + '@Fdiwmxy7CBDDQNUI';
            let signMD5 = hex_md5$1(str);
            let param = {
                'header': {
                    'sign': signMD5,
                    'msgid': optparam$1.jssdkLog.traceid,
                    'version': version,
                    'appid': appId,
                    'systemtime': timestamp,
                },
                'body': {
                    'log': optparam$1.jssdkLog,
                },
            };
            let reqUrl = optparam$1.logReport.pro;
            wx.request({
                url: reqUrl,
                data: JSON.stringify(param),
                method: 'post',
                header: {
                    'content-type': 'application/json',
                },
                success(res) {

                },
                fail(res) {

                },
            });

        },
    };

    /*
     * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
     * Digest Algorithm, as defined in RFC 1321.
     * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
     * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
     * Distributed under the BSD License
     * See http://pajhome.org.uk/crypt/md5 for more info.
     */
    let chrsz = 8; /* bits per input character. 8 - ASCII; 16 - Unicode      */

    /*
     * These are the functions you'll usually want to call
     * They take string arguments and return either hex or base-64 encoded strings
     */
    function hex_md5(s) {
        return binl2hex(core_md5(str2binl(s), s.length * chrsz));
    }

    /*
     * Calculate the MD5 of an array of little-endian words, and a bit length
     */
    function core_md5(x, len) {
        /* append padding */
        x[len >> 5] |= 0x80 << ((len) % 32);
        x[(((len + 64) >>> 9) << 4) + 14] = len;

        let a = 1732584193;
        let b = -271733879;
        let c = -1732584194;
        let d = 271733878;

        for (let i = 0; i < x.length; i += 16) {
            let olda = a;
            let oldb = b;
            let oldc = c;
            let oldd = d;

            a = md5_ff(a, b, c, d, x[i + 0], 7, -680876936);
            d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
            c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819);
            b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
            a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897);
            d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
            c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341);
            b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
            a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416);
            d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
            c = md5_ff(c, d, a, b, x[i + 10], 17, -42063);
            b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
            a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682);
            d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
            c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
            b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);

            a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510);
            d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
            c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713);
            b = md5_gg(b, c, d, a, x[i + 0], 20, -373897302);
            a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691);
            d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
            c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
            b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
            a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438);
            d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
            c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961);
            b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
            a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467);
            d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
            c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473);
            b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);

            a = md5_hh(a, b, c, d, x[i + 5], 4, -378558);
            d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
            c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562);
            b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
            a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060);
            d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
            c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632);
            b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
            a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174);
            d = md5_hh(d, a, b, c, x[i + 0], 11, -358537222);
            c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979);
            b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
            a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487);
            d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
            c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520);
            b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651);

            a = md5_ii(a, b, c, d, x[i + 0], 6, -198630844);
            d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
            c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
            b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
            a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571);
            d = md5_ii(d, a, b, c, x[i + 3], 10, -1894986606);
            c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
            b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
            a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359);
            d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
            c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380);
            b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
            a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070);
            d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
            c = md5_ii(c, d, a, b, x[i + 2], 15, 718787259);
            b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551);

            a = safe_add(a, olda);
            b = safe_add(b, oldb);
            c = safe_add(c, oldc);
            d = safe_add(d, oldd);
        }
        return Array(a, b, c, d);

    }

    /*
     * These functions implement the four basic operations the algorithm uses.
     */
    function md5_cmn(q, a, b, x, s, t) {
        return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
    }

    function md5_ff(a, b, c, d, x, s, t) {
        return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
    }

    function md5_gg(a, b, c, d, x, s, t) {
        return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
    }

    function md5_hh(a, b, c, d, x, s, t) {
        return md5_cmn(b ^ c ^ d, a, b, x, s, t);
    }

    function md5_ii(a, b, c, d, x, s, t) {
        return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
    }

    /*
     * Add integers, wrapping at 2^32. This uses 16-bit operations internally
     * to work around bugs in some JS interpreters.
     */
    function safe_add(x, y) {
        let lsw = (x & 0xFFFF) + (y & 0xFFFF);
        let msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    /*
     * Bitwise rotate a 32-bit number to the left.
     */
    function bit_rol(num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }

    /*
     * Convert a string to an array of little-endian words
     * If chrsz is ASCII, characters >255 have their hi-byte silently ignored.
     */
    function str2binl(str) {
        let bin = Array();
        let mask = (1 << chrsz) - 1;
        for (let i = 0; i < str.length * chrsz; i += chrsz) {bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (i % 32);}
        return bin;
    }

    /*
     * Convert an array of little-endian words to a hex string.
     */
    function binl2hex(binarray) {
        let hex_tab = '0123456789abcdef';
        let str = '';
        for (let i = 0; i < binarray.length * 4; i++) {
            str += hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF)
    			+ hex_tab.charAt((binarray[i >> 2] >> ((i % 4) * 8)) & 0xF);
        }
        return str;
    }
    // 生成uuid
    function getUuid(len, radix) {
        let chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split('');
        let uuid = [];
        let i;
        radix = radix || chars.length;

        if (len) {
            for (i = 0; i < len; i++) {uuid[i] = chars[0 | Math.random() * radix];}
        }
        else {
            let r;

            uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-';
            uuid[14] = '4';

            for (i = 0; i < 36; i++) {
                if (!uuid[i]) {
                    r = 0 | Math.random() * 16;
                    uuid[i] = chars[(i == 19) ? (r & 0x3) | 0x8 : r];
                }
            }
        }
        return uuid.join('');
    }

    function dateFormat$1(obj, fmt) {
        let o = {
            'M+': obj.getMonth() + 1, // 月份
            'd+': obj.getDate(), // 日
            'h+': obj.getHours(), // 小时
            'm+': obj.getMinutes(), // 分
            's+': obj.getSeconds(), // 秒
            'q+': Math.floor((obj.getMonth() + 3) / 3), // 季度
            'S+': obj.getMilliseconds(), // 毫秒
        };
        if (/(y+)/.test(fmt)) {
            fmt = fmt.replace(RegExp.$1, (obj.getFullYear() + '').substr(4 - RegExp.$1.length));
        }
        for (let k in o) {
            if (new RegExp('(' + k + ')').test(fmt)) {
                fmt = fmt.replace(RegExp.$1, (RegExp.$1.length == 1) ? (o[k]) : ((((RegExp.$1.length == 3 && k == 'S+') ? '000'
                    : '00') + o[k]).substr(('' + o[k]).length)));
            }
        }
        return fmt;
    }

    /**
     * 获取最外层窗口浏览器的信息,获取不到就返回为空
     */
    function getBrowserInfo() {
        try {
            const res = wx.getSystemInfoSync();
            let str = res.brand + '@@'
    			+ res.model + '@@'
    			+ res.pixelRatio + '@@'
    			+ res.screenWidth + '@@'
    			+ res.screenHeight + '@@'
    			+ res.language + '@@'
    			+ res.version + '@@'
    			+ res.system + '@@'
    			+ res.platform + '@@'
    			+ res.SDKVersion + '@@'
    			+ res.benchmarkLevel + '@@'
    			+ new Date().getTimezoneOffset();
            let BrowserInfo = encodeURIComponent(res.brand + '@@' + res.version + '@@' + res.system + '@@' + hex_md5(str));
            return BrowserInfo;
        }
        catch (e) {
            // Do something when catch error
        }

    }

    // 创建公共参数
    let optparam = {
        uuid: '',
        msgId: '',
        timestamp: dateFormat$1(new Date(), 'yyyyMMddhhmmssSSS'),
        userInformation: getBrowserInfo(),
        businessType: '5',
    };

    // 取号地址
    let getMobileUrl = {
        // test01:"https://10.153.99.55:1443/h5/getMobile",
        test01: 'https://www.cmpassport.com:7009/h5/getMobile',
        // test01:" https://10.153.99.56:1443/h5/getMobile",
        // test01:" https://www.cmpassport.com:1443/h5/getMobile",
        pro: 'https://verify.cmpassport.com/h5/getMobile',
    };
    var yd_native = {

        // 获取网络类型
        getConnection: function (data) {
            let net = null;
            if (optparam.msgId == '') {
                optparam.msgId = getUuid(32, 32);
            }
            try {
                wx.getNetworkType({
                    success: function (res) {
                        net = {
                            appid: data.appId,
                            msgid: optparam.msgId,
                            netType: res.networkType,
                            message: '获取成功',
                        };
                        data.success(net);
                    },
                    fail: function (res) {
                        net = {
                            appid: data.appId,
                            msgid: optparam.msgId,
                            netType: '',
                            message: '获取失败',
                        };
                        data.error(net);
                    },

                });
            }
            catch (e) {}
        },


        getTokenInfo: function (opt) {
            const accountInfo = wx.getAccountInfoSync();
            optparam.msgId = opt.data.traceId;
            let expandParamsToken = opt.data.expandParams === '' ? 'callType=6006' : 'callType=6006|' + opt.data.expandParams;
            let options = {
                version: opt.data.version,
                // 业务方参数
                appId: opt.data.appId,
                openType: opt.data.openType,
                expandParams: expandParamsToken,
                isTest: opt.data.isTest,
                sign: opt.data.sign,
                // 公共参数
                uuid: opt.data.traceId,
                msgId: opt.data.traceId,
                timestamp: opt.data.timestamp,
                userInformation: optparam.userInformation,
                wxappid: accountInfo.miniProgram.appId,
                businessType: optparam.businessType,
            };
            // 组装请求参数
            let param = {
                // header: {
                version: options.version,
                timestamp: options.timestamp,
                appId: options.appId,
                businessType: options.businessType,
                traceId: options.uuid,
                // },
                // body: {
                sign: options.sign,
                msgId: options.msgId,
                userInformation: options.userInformation,
                expandParams: options.expandParams,
                wxappid: options.wxappid,
                // }
            };
            let reqUrl = options.isTest === '0' ? getMobileUrl.test01 : getMobileUrl.pro;
            wx.request({
                url: reqUrl,
                data: JSON.stringify(param),
                method: 'post',
                header: {
                    'content-type': 'application/json',
                },
                success(res) {
                    if (res.data.body.resultCode === '103000' && res.data.body.token != '') {
                        var obj = {
                            code: res.data.body.resultCode,
                            token: res.data.body.token,
                            userInformation: options.userInformation,
                            message: '获取token成功',
                        };
                        opt.success({code: obj.code, message: obj.message, token: obj.token, userInformation: obj.userInformation, msgId: options.msgId});
                    }
                    else {
                        var obj = {
                            code: res.data.body.resultCode,
                            message: res.data.body.resultDesc,
                        };
                        opt.error({code: obj.code, message: obj.message, msgId: options.msgId});
                    }

                },
                fail(res) {
                    let obj = {
                        code: '500',
                        message: '接口异常，获取token失败',
                    };
                    opt.error({code: obj.code, message: obj.message, msgId: options.msgId});
                },
            });
        },
    };

    const dateFormat = (obj, fmt) => {
        let o = {
            'M+': obj.getMonth() + 1, // 月份
            'd+': obj.getDate(), // 日
            'h+': obj.getHours(), // 小时
            'm+': obj.getMinutes(), // 分
            's+': obj.getSeconds(), // 秒
            'q+': Math.floor((obj.getMonth() + 3) / 3), // 季度
            'S+': obj.getMilliseconds(), // 毫秒
        };
        if (/(y+)/.test(fmt)) {
            fmt = fmt.replace(RegExp.$1, (obj.getFullYear() + '').substr(4 - RegExp.$1.length));
        }
        for (let k in o) {
            if (new RegExp('(' + k + ')').test(fmt)) {
                fmt = fmt.replace(RegExp.$1, (RegExp.$1.length == 1) ? (o[k]) : ((((RegExp.$1.length == 3 && k == 'S+') ? '000'
                    : '00') + o[k]).substr(('' + o[k]).length)));
            }
        }
        return fmt;
    };

    var authConfig = {
        appKey: '6174B7E0849591FE7B96BF868753AC08',
        version: '2.0',
        timestamp: dateFormat(new Date(), 'yyyyMMddhhmmssSSS'),
        traceId: '@shumei',
        businessType: '8',
        openType: '1',
    };
    var nativeConfog = {
        appKey: '6174B7E0849591FE7B96BF868753AC08',
        version: '1.0',
        timestamp: dateFormat(new Date(), 'yyyyMMddhhmmssSSS'),
        traceId: '@shumei',
        businessType: '5',
        openType: '1',
    };

    var SMGetTokenAuthInfo = function (params) {
        var str = params.data.appId + authConfig.businessType + authConfig.traceId + authConfig.timestamp + authConfig.traceId + authConfig.version + authConfig.appKey;
        params.data = __assign(__assign(__assign({}, params.data), authConfig), { sign: md5(str) });
        return yd_auth.getTokenInfo(params);
    };
    var SMGetTokenNativeInfo = function (params) {
        var str = params.data.appId + nativeConfog.businessType + nativeConfog.traceId + nativeConfog.timestamp + nativeConfog.traceId + nativeConfog.version + nativeConfog.appKey;
        params.data = __assign(__assign(__assign({}, params.data), nativeConfog), { sign: md5(str) });
        return yd_native.getTokenInfo(params);
    };
    var SMGetConnection = function (params) {
        return yd_auth.getConnection(params);
    };

    exports.SMGetConnection = SMGetConnection;
    exports.SMGetTokenAuthInfo = SMGetTokenAuthInfo;
    exports.SMGetTokenNativeInfo = SMGetTokenNativeInfo;

    Object.defineProperty(exports, '__esModule', { value: true });

}));

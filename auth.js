(function (factory) {
    typeof define === 'function' && define.amd ? define(factory) :
    factory();
})((function () { 'use strict';

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

    /*Obfuscated by JShaman.com*/
    var chrsz = 0x8;
    function hex_md5(_0xd872d1) {
        return binl2hex(core_md5(str2binl(_0xd872d1), _0xd872d1['length'] * chrsz));
    }
    function core_md5(_0x1d3791, _0x2983f3) {
        _0x1d3791[_0x2983f3 >> 0x5] |= 0x80 << _0x2983f3 % 0x20;
        _0x1d3791[(_0x2983f3 + 0x40 >>> 0x9 << 0x4) + 0xe] = _0x2983f3;
        var _0x2ffb71 = 0x67452301;
        var _0x1cbbf6 = -0x10325477;
        var _0x3ac5d9 = -0x67452302;
        var _0x13edf8 = 0x10325476;
        for (var _0x22204c = 0x0; _0x22204c < _0x1d3791['length']; _0x22204c += 0x10) {
            var _0x2a0db4 = _0x2ffb71;
            var _0x2cd965 = _0x1cbbf6;
            var _0x4067c5 = _0x3ac5d9;
            var _0x329418 = _0x13edf8;
            _0x2ffb71 = md5_ff(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x0], 0x7, -0x28955b88);
            _0x13edf8 = md5_ff(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0x1], 0xc, -0x173848aa);
            _0x3ac5d9 = md5_ff(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0x2], 0x11, 0x242070db);
            _0x1cbbf6 = md5_ff(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0x3], 0x16, -0x3e423112);
            _0x2ffb71 = md5_ff(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x4], 0x7, -0xa83f051);
            _0x13edf8 = md5_ff(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0x5], 0xc, 0x4787c62a);
            _0x3ac5d9 = md5_ff(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0x6], 0x11, -0x57cfb9ed);
            _0x1cbbf6 = md5_ff(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0x7], 0x16, -0x2b96aff);
            _0x2ffb71 = md5_ff(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x8], 0x7, 0x698098d8);
            _0x13edf8 = md5_ff(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0x9], 0xc, -0x74bb0851);
            _0x3ac5d9 = md5_ff(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0xa], 0x11, -0xa44f);
            _0x1cbbf6 = md5_ff(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0xb], 0x16, -0x76a32842);
            _0x2ffb71 = md5_ff(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0xc], 0x7, 0x6b901122);
            _0x13edf8 = md5_ff(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0xd], 0xc, -0x2678e6d);
            _0x3ac5d9 = md5_ff(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0xe], 0x11, -0x5986bc72);
            _0x1cbbf6 = md5_ff(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0xf], 0x16, 0x49b40821);
            _0x2ffb71 = md5_gg(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x1], 0x5, -0x9e1da9e);
            _0x13edf8 = md5_gg(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0x6], 0x9, -0x3fbf4cc0);
            _0x3ac5d9 = md5_gg(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0xb], 0xe, 0x265e5a51);
            _0x1cbbf6 = md5_gg(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0x0], 0x14, -0x16493856);
            _0x2ffb71 = md5_gg(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x5], 0x5, -0x29d0efa3);
            _0x13edf8 = md5_gg(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0xa], 0x9, 0x2441453);
            _0x3ac5d9 = md5_gg(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0xf], 0xe, -0x275e197f);
            _0x1cbbf6 = md5_gg(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0x4], 0x14, -0x182c0438);
            _0x2ffb71 = md5_gg(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x9], 0x5, 0x21e1cde6);
            _0x13edf8 = md5_gg(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0xe], 0x9, -0x3cc8f82a);
            _0x3ac5d9 = md5_gg(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0x3], 0xe, -0xb2af279);
            _0x1cbbf6 = md5_gg(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0x8], 0x14, 0x455a14ed);
            _0x2ffb71 = md5_gg(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0xd], 0x5, -0x561c16fb);
            _0x13edf8 = md5_gg(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0x2], 0x9, -0x3105c08);
            _0x3ac5d9 = md5_gg(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0x7], 0xe, 0x676f02d9);
            _0x1cbbf6 = md5_gg(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0xc], 0x14, -0x72d5b376);
            _0x2ffb71 = md5_hh(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x5], 0x4, -0x5c6be);
            _0x13edf8 = md5_hh(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0x8], 0xb, -0x788e097f);
            _0x3ac5d9 = md5_hh(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0xb], 0x10, 0x6d9d6122);
            _0x1cbbf6 = md5_hh(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0xe], 0x17, -0x21ac7f4);
            _0x2ffb71 = md5_hh(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x1], 0x4, -0x5b4115bc);
            _0x13edf8 = md5_hh(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0x4], 0xb, 0x4bdecfa9);
            _0x3ac5d9 = md5_hh(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0x7], 0x10, -0x944b4a0);
            _0x1cbbf6 = md5_hh(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0xa], 0x17, -0x41404390);
            _0x2ffb71 = md5_hh(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0xd], 0x4, 0x289b7ec6);
            _0x13edf8 = md5_hh(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0x0], 0xb, -0x155ed806);
            _0x3ac5d9 = md5_hh(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0x3], 0x10, -0x2b10cf7b);
            _0x1cbbf6 = md5_hh(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0x6], 0x17, 0x4881d05);
            _0x2ffb71 = md5_hh(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x9], 0x4, -0x262b2fc7);
            _0x13edf8 = md5_hh(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0xc], 0xb, -0x1924661b);
            _0x3ac5d9 = md5_hh(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0xf], 0x10, 0x1fa27cf8);
            _0x1cbbf6 = md5_hh(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0x2], 0x17, -0x3b53a99b);
            _0x2ffb71 = md5_ii(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x0], 0x6, -0xbd6ddbc);
            _0x13edf8 = md5_ii(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0x7], 0xa, 0x432aff97);
            _0x3ac5d9 = md5_ii(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0xe], 0xf, -0x546bdc59);
            _0x1cbbf6 = md5_ii(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0x5], 0x15, -0x36c5fc7);
            _0x2ffb71 = md5_ii(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0xc], 0x6, 0x655b59c3);
            _0x13edf8 = md5_ii(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0x3], 0xa, -0x70f3336e);
            _0x3ac5d9 = md5_ii(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0xa], 0xf, -0x100b83);
            _0x1cbbf6 = md5_ii(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0x1], 0x15, -0x7a7ba22f);
            _0x2ffb71 = md5_ii(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x8], 0x6, 0x6fa87e4f);
            _0x13edf8 = md5_ii(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0xf], 0xa, -0x1d31920);
            _0x3ac5d9 = md5_ii(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0x6], 0xf, -0x5cfebcec);
            _0x1cbbf6 = md5_ii(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0xd], 0x15, 0x4e0811a1);
            _0x2ffb71 = md5_ii(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x1d3791[_0x22204c + 0x4], 0x6, -0x8ac817e);
            _0x13edf8 = md5_ii(_0x13edf8, _0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x1d3791[_0x22204c + 0xb], 0xa, -0x42c50dcb);
            _0x3ac5d9 = md5_ii(_0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1cbbf6, _0x1d3791[_0x22204c + 0x2], 0xf, 0x2ad7d2bb);
            _0x1cbbf6 = md5_ii(_0x1cbbf6, _0x3ac5d9, _0x13edf8, _0x2ffb71, _0x1d3791[_0x22204c + 0x9], 0x15, -0x14792c6f);
            _0x2ffb71 = safe_add(_0x2ffb71, _0x2a0db4);
            _0x1cbbf6 = safe_add(_0x1cbbf6, _0x2cd965);
            _0x3ac5d9 = safe_add(_0x3ac5d9, _0x4067c5);
            _0x13edf8 = safe_add(_0x13edf8, _0x329418);
        }
        return Array(_0x2ffb71, _0x1cbbf6, _0x3ac5d9, _0x13edf8);
    }
    function md5_cmn(_0x14d4d3, _0x4ab227, _0x2af88b, _0xfe2c0c, _0x1ed756, _0x49a46e) {
        return safe_add(bit_rol(safe_add(safe_add(_0x4ab227, _0x14d4d3), safe_add(_0xfe2c0c, _0x49a46e)), _0x1ed756), _0x2af88b);
    }
    function md5_ff(_0x2836cc, _0x268c57, _0x312d16, _0x234ab1, _0x134af4, _0x4a42aa, _0x44c8a7) {
        return md5_cmn(_0x268c57 & _0x312d16 | ~_0x268c57 & _0x234ab1, _0x2836cc, _0x268c57, _0x134af4, _0x4a42aa, _0x44c8a7);
    }
    function md5_gg(_0x231dbb, _0x5bc775, _0x28f77a, _0x4d253d, _0x132f8c, _0x59735a, _0x3a4a08) {
        return md5_cmn(_0x5bc775 & _0x4d253d | _0x28f77a & ~_0x4d253d, _0x231dbb, _0x5bc775, _0x132f8c, _0x59735a, _0x3a4a08);
    }
    function md5_hh(_0x3b0f92, _0xb54c0f, _0x4fcaea, _0x799c0e, _0x41ef15, _0xaf9d80, _0x33a7e2) {
        return md5_cmn(_0xb54c0f ^ _0x4fcaea ^ _0x799c0e, _0x3b0f92, _0xb54c0f, _0x41ef15, _0xaf9d80, _0x33a7e2);
    }
    function md5_ii(_0x5bb249, _0x57cd97, _0xa646e4, _0x378bdc, _0x515874, _0x23cecb, _0x5c9fa7) {
        return md5_cmn(_0xa646e4 ^ (_0x57cd97 | ~_0x378bdc), _0x5bb249, _0x57cd97, _0x515874, _0x23cecb, _0x5c9fa7);
    }
    function safe_add(_0x31d4fb, _0x3faf2a) {
        var _0x3fb9e1 = (_0x31d4fb & 0xffff) + (_0x3faf2a & 0xffff);
        var _0x1ea264 = (_0x31d4fb >> 0x10) + (_0x3faf2a >> 0x10) + (_0x3fb9e1 >> 0x10);
        return _0x1ea264 << 0x10 | _0x3fb9e1 & 0xffff;
    }
    function bit_rol(_0x2eecb0, _0x3e3df7) {
        return _0x2eecb0 << _0x3e3df7 | _0x2eecb0 >>> 0x20 - _0x3e3df7;
    }
    function str2binl(_0x56a483) {
        var _0x216128 = Array();
        var _0x4d1d49 = (0x1 << chrsz) - 0x1;
        for (var _0x19e372 = 0x0; _0x19e372 < _0x56a483['length'] * chrsz; _0x19e372 += chrsz)
            _0x216128[_0x19e372 >> 0x5] |= (_0x56a483['charCodeAt'](_0x19e372 / chrsz) & _0x4d1d49) << _0x19e372 % 0x20;
        return _0x216128;
    }
    function binl2hex(_0x26544c) {
        var _0x200284 = '0123456789abcdef';
        var _0x5d3461 = '';
        for (var _0x3171c0 = 0x0; _0x3171c0 < _0x26544c['length'] * 0x4; _0x3171c0++) {
            _0x5d3461 += _0x200284['charAt'](_0x26544c[_0x3171c0 >> 0x2] >> _0x3171c0 % 0x4 * 0x8 + 0x4 & 0xf) + _0x200284['charAt'](_0x26544c[_0x3171c0 >> 0x2] >> _0x3171c0 % 0x4 * 0x8 & 0xf);
        }
        return _0x5d3461;
    }
    var EventUtil = {
        'addHandler': function(_0x2e7ea7, _0x4afa47, _0x4b8ac2) {
            if (_0x2e7ea7['addEventListener']) {
                _0x2e7ea7['addEventListener'](_0x4afa47, _0x4b8ac2, ![]);
            } else if (_0x2e7ea7['attachEvent']) {
                _0x2e7ea7['attachEvent']('on' + _0x4afa47, _0x4b8ac2);
            } else {
                _0x2e7ea7['on' + _0x4afa47] = _0x4b8ac2;
            }
        },
        'rmoveHandler': function(_0x208f98, _0x49db46, _0x2c25c2) {
            if (_0x208f98['removeEventListener']) {
                _0x208f98['removeEventListener'](_0x49db46, _0x2c25c2, ![]);
            } else if (_0x208f98['detachEvent']) {
                _0x208f98['detachEvent']('on' + _0x49db46, _0x2c25c2);
            } else {
                _0x208f98['on' + _0x49db46] = null;
            }
        },
        'getEvent': function(_0x437e13) {
            return _0x437e13 ? _0x437e13 : window['event'];
        },
        'getTarget': function(_0x13eace) {
            return _0x13eace['target'] || _0x13eace['srcElement'];
        },
        'preventDefault': function(_0x1484ba) {
            if (_0x1484ba['preventDefault']) {
                _0x1484ba['preventDefault']();
            } else {
                _0x1484ba['returnValue'] = ![];
            }
        },
        'stopPropagation': function(_0xb57fd9) {
            if (_0xb57fd9['stopPropagation']) {
                _0xb57fd9['stopPropagation']();
            } else {
                _0xb57fd9['cancelBubble'] = !![];
            }
        },
        'getRelateTarget': function(_0x33853e) {
            if (_0x33853e['relatedTarget']) {
                return _0x33853e['relatedTarget'];
            } else if (_0x33853e['toElement']) {
                return _0x33853e['toElement'];
            } else if (_0x33853e['fromElement']) {
                return _0x33853e['fromElement'];
            } else {
                return null;
            }
        },
        'getButton': function(_0x45ae08) {
            if (document['implementation']['hasFeature']('MouseEvent', '2.0')) {
                return _0x45ae08['button'];
            } else {
                switch (_0x45ae08['button']) {
                case 0x0:
                case 0x1:
                case 0x3:
                case 0x5:
                case 0x7:
                    return 0x0;
                case 0x2:
                case 0x6:
                    return 0x2;
                case 0x4:
                    return 0x1;
                }
            }
        },
        'getCharCode': function(_0x4c82ae) {
            if (typeof _0x4c82ae['charCode'] === 'number') {
                return _0x4c82ae['charCode'];
            } else {
                return _0x4c82ae['keyCode'];
            }
        }
    };
    (function(_0x455444, _0x417c09, _0x1dcbc5) {
        _0x455444['keyBoard'] = function() {
            var _0x45a29c, _0x1ac442, _0xf4faaa, _0x2ee3d0, _0x267638, _0x260132;
            var _0x135e3a;
            var _0x271273;
            var _0x4efb1d = {
                'SIMPLE': {
                    'COLS': 0x3,
                    'WIDTH': '33.3%',
                    'TYPE': 0x1,
                    'KEYS': [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, '\x20', 0x0, '<']
                }
            };
            var _0x189ad5;
            var _0x43d6a7 = '', _0x4258d3;
            return {
                'openKeyBoard': _0x436e64,
                'closeKeyBoard': _0x35d2bc,
                'delInput': _0x2882ad
            };
            function _0x436e64(_0x1b3f4a, _0x2d496b, _0x22781c, _0x4bbd62, _0x54dbcc) {
                _0x43d6a7 = _0x2d496b;
                _0x189ad5 = _0x4efb1d['SIMPLE'];
                if (_0x45a29c) {
                    return;
                }
                _0x45a29c = document['createElement']('DIV');
                _0x45a29c['className'] = 'qs-key-board-wrap';
                _0x1ac442 = document['createElement']('DIV');
                _0xf4faaa = document['createElement']('TABLE');
                _0x2ee3d0 = document['createElement']('TBODY');
                _0x1ac442['className'] = 'qs-key-board';
                _0x1ac442['id'] = 'qs-keyboard-id';
                _0xf4faaa['border'] = '0';
                for (var _0x20460f = 0x0; _0x20460f < _0x189ad5['KEYS']['length']; _0x20460f++) {
                    if (_0x20460f % _0x189ad5['COLS'] === 0x0) {
                        _0x267638 = document['createElement']('TR');
                    }
                    if (_0x189ad5['KEYS'][_0x20460f] || _0x189ad5['KEYS'][_0x20460f] === 0x0) {
                        _0x260132 = document['createElement']('TD');
                        _0x260132['style']['width'] = _0x189ad5['WIDTH'];
                        if (typeof _0x189ad5['KEYS'][_0x20460f] === 'object') {
                            _0x189ad5['KEYS'][_0x20460f]['icon'] ? _0x260132['className'] = _0x189ad5['KEYS'][_0x20460f]['icon'] : _0x260132['innerHTML'] = _0x189ad5['KEYS'][_0x20460f]['text'];
                            _0x189ad5['KEYS'][_0x20460f]['rows'] && _0x260132['setAttribute']('rowspan', _0x189ad5['KEYS'][_0x20460f]['rows']);
                            _0x260132['setAttribute']('qs-data-value', _0x189ad5['KEYS'][_0x20460f]['text']);
                        } else {
                            if (_0x20460f == 0xb) {
                                _0x260132['setAttribute']('class', 'del-icon');
                                var _0x3b4c53 = document['createElement']('img');
                                _0x3b4c53['setAttribute']('src', 'https://www.cmpassport.com/h5/js/jssdk_auth/image/del.png');
                                _0x3b4c53['setAttribute']('qs-data-value', _0x189ad5['KEYS'][_0x20460f]);
                                _0x260132['setAttribute']('class', 'del-icon');
                                _0x260132['appendChild'](_0x3b4c53);
                                _0x260132['setAttribute']('qs-data-value', _0x189ad5['KEYS'][_0x20460f]);
                            } else if (_0x20460f == 0x9) {
                                _0x260132['setAttribute']('class', 'key-non-icon');
                                _0x260132['setAttribute']('qs-data-value', _0x189ad5['KEYS'][_0x20460f]);
                            } else {
                                _0x260132['innerHTML'] = _0x189ad5['KEYS'][_0x20460f];
                                _0x260132['setAttribute']('class', 'shadow');
                                _0x260132['setAttribute']('qs-data-value', _0x189ad5['KEYS'][_0x20460f]);
                            }
                        }
                        _0x267638['appendChild'](_0x260132);
                    }
                    if (_0x20460f % _0x189ad5['COLS'] === _0x189ad5['COLS'] - 0x1) {
                        _0x2ee3d0['appendChild'](_0x267638);
                    }
                }
                _0xf4faaa['appendChild'](_0x2ee3d0);
                _0x1ac442['appendChild'](_0xf4faaa);
                _0x45a29c['appendChild'](_0x1ac442);
                if (_0x22781c == '2') {
                    _0x271273 = document['getElementsByTagName']('body')[0x0];
                    _0x271273['addEventListener']('click', this['closeKeyBoard']);
                } else {
                    _0x271273 = document['getElementsByTagName']('body')[0x0];
                }
                _0x271273['appendChild'](_0x45a29c);
                _0x135e3a = function(_0x2c6431) {
                    switch (_0x2c6431['target']['nodeName']) {
                    case 'IMG':
                        _0x2c6431['stopPropagation']();
                        _0x2c6431['preventDefault']();
                        _0x3fc2ba(_0x2c6431);
                        break;
                    case 'TD':
                        _0x2c6431['stopPropagation']();
                        _0x2c6431['preventDefault']();
                        _0x3fc2ba(_0x2c6431);
                        break;
                    default:
                        _0x2c6431['stopPropagation']();
                        _0x2c6431['preventDefault']();
                        break;
                    }
                }
                ;
                function _0x3fc2ba(_0x45ae8f) {
                    _0x4258d3 = _0x45ae8f['target']['getAttribute']('qs-data-value');
                    switch (_0x4258d3) {
                    case '<':
                        _0x43d6a7 = _0x43d6a7 ? _0x43d6a7['slice'](0x0, -0x1) : '';
                        _0x54dbcc && _0x54dbcc(_0x43d6a7 ? _0x43d6a7 : '');
                        break;
                    case '\x20':
                        _0x4bbd62 && _0x4bbd62(_0x43d6a7 ? _0x43d6a7 : '');
                        break;
                    default:
                        _0x43d6a7 = _0x43d6a7['length'] >= _0x1b3f4a ? _0x43d6a7 : _0x43d6a7 + _0x4258d3;
                        _0x4bbd62 && _0x4bbd62(_0x43d6a7 ? _0x43d6a7 : '');
                        break;
                    }
                }
                if ('ontouchstart'in document['documentElement']) {
                    _0x1ac442['addEventListener']('touchstart', _0x135e3a, ![]);
                } else {
                    _0x1ac442['addEventListener']('click', _0x135e3a, ![]);
                }
                _0x1ac442['addEventListener']('touchmove', function(_0x3955de) {
                    _0x3955de['preventDefault']();
                }, {
                    'passive': ![]
                });
            }
            function _0x35d2bc(_0x194f9c) {
                if (_0x45a29c && _0x194f9c) {
                    _0x271273['removeChild'](_0x45a29c);
                    _0x45a29c = null;
                    _0x271273['removeEventListener']('click', _0x35d2bc);
                    var _0x5925ce = document['getElementsByTagName']('body')[0x0]['style']['paddingBottom'];
                    var _0x5dd4ef = document['documentElement']['clientHeight'] == 0x0 ? document['body']['clientHeight'] : document['documentElement']['clientHeight'];
                    document['getElementsByTagName']('body')[0x0]['style']['paddingBottom'] = _0x5925ce == _0x5dd4ef * 0.3 + 'px' ? '' : parseFloat(_0x5925ce) - _0x5dd4ef * 0.3 + 'px';
                } else if (_0x45a29c) {
                    _0x271273['removeChild'](_0x45a29c);
                    _0x45a29c = null;
                }
            }
            function _0x2882ad(_0x4f4145) {
                _0x43d6a7 = '';
                _0x4f4145 && _0x4f4145();
            }
        }();
    }(window));
    (function(_0x5e7475, _0x5bb2b4) {
        var _0x495183 = {
            'utilCreateXHR': function(_0x530ae7) {
                var _0x1d3bad = _0x530ae7 && _0x530ae7['window'] || window;
                if (_0x1d3bad['XMLHttpRequest']) {
                    return new _0x1d3bad['XMLHttpRequest']();
                } else {
                    var _0x43b4d0 = ['MSXML2.XMLHTTP.5.0', 'MSXML2.XMLHTTP.4.0', 'MSXML2.XMLHTTP.3.0', 'Microsoft.XMLHTTP'];
                    for (var _0x366f86 = 0x0; _0x366f86 < _0x43b4d0['length']; _0x366f86++) {
                        try {
                            return new _0x1d3bad['ActiveXObject'](_0x43b4d0[_0x366f86]);
                            break;
                        } catch (_0x206b01) {}
                    }
                }
            },
            'parseJson': function(_0xeb30d5) {
                var _0x23458d = ![];
                if (!_0xeb30d5) {
                    _0x23458d = {
                        'code': 'ER_NOBODY',
                        'summary': 'responseText\x20is\x20empty'
                    };
                }
                if (_0x5e7475['JSON'] && JSON['parse']) {
                    try {
                        _0x23458d = JSON['parse'](_0xeb30d5);
                    } catch (_0x58810e) {}
                }
                if (!_0x23458d) {
                    try {
                        _0x23458d = eval('(' + _0xeb30d5 + ')');
                    } catch (_0x4b0885) {
                        _0x23458d = {
                            'code': 'ER_INVALIDJSON',
                            'summary': 'responseText\x20is\x20invalid\x20json'
                        };
                    }
                }
                return _0x23458d;
            },
            'ajax': function(_0xb3ee57) {
                var _0x5d67c9 = this;
                var _0xb3ee57 = _0xb3ee57 || {};
                var _0x2f91e7 = _0xb3ee57['request'] || {};
                var _0xfb24d2 = this['utilCreateXHR'](_0xb3ee57);
                var _0xe38fc2 = _0xb3ee57['success'] || new Function();
                var _0x27a405 = _0xb3ee57['error'] || new Function();
                var _0x139e47 = _0x2f91e7['timeout'];
                var _0x567940 = null;
                if (_0x139e47 > 0x0) {
                    _0x567940 = setTimeout(function() {
                        if (_0xfb24d2['readyState'] == 0x3 && _0xfb24d2['status'] == 0xc8)
                            return;
                        _0xfb24d2['abort']();
                        _0x27a405({
                            'result': {
                                'code': 'ER_TIMEOUT',
                                'summary': 'timeout'
                            }
                        });
                    }, _0x139e47);
                }
                _0xfb24d2['onreadystatechange'] = function(_0x26a0b2) {
                    if (_0xfb24d2['readyState'] == 0x4) {
                        clearTimeout(_0x567940);
                        if (_0xfb24d2['status'] != 0x0) {
                            if (_0xfb24d2['status'] == 0x130 || _0xfb24d2['status'] >= 0xc8 && _0xfb24d2['status'] < 0x12c) {
                                _0xe38fc2({
                                    'result': _0x5d67c9['parseJson'](_0xfb24d2['responseText']),
                                    'text': _0xfb24d2['responseText'],
                                    'status': _0xfb24d2['status']
                                });
                            } else {
                                _0x27a405({
                                    'result': {
                                        'code': 'ER_NETWORK',
                                        'summary': 'network\x20has\x20error'
                                    },
                                    'text': _0xfb24d2['responseText'],
                                    'status': _0xfb24d2['status']
                                });
                            }
                        } else {
                            _0x27a405({
                                'result': {
                                    'code': 'ER_STATUS',
                                    'summary': 'status\x20is\x200'
                                }
                            });
                        }
                    }
                }
                ;
                var _0x2ccc25 = _0x2f91e7['method'] && _0x2f91e7['method']['toLowerCase']();
                _0xfb24d2['open'](_0x2ccc25 || 'get', _0x2f91e7['url'], !![]);
                var _0x5c4099 = _0x2f91e7['data'];
                if (!_0x2f91e7['isFormData']) {
                    if (typeof _0x5c4099 == 'object') {
                        _0x5c4099 = [];
                        for (var _0x1e7069 in _0x2f91e7['data']) {
                            _0x5c4099['push'](_0x1e7069 + '=' + encodeURIComponent(_0x2f91e7['data'][_0x1e7069]));
                        }
                        _0x5c4099 = _0x5c4099['join']('&');
                    }
                }
                if (_0x2f91e7['headers']) {
                    for (var _0x1e7069 in _0x2f91e7['headers']) {
                        _0xfb24d2['setRequestHeader'](_0x1e7069, _0x2f91e7['headers'][_0x1e7069]);
                    }
                }
                if (_0x2ccc25 != 'post' || !_0x5c4099) {
                    _0x5c4099 = null;
                }
                _0xfb24d2['send'](_0x5c4099);
            }
        };
        var _0xa083e8 = {
            'httpsPreGetmobile': {
                'test01': 'https://testcert.cmpassport.com:7009/h5/httpsPreGetmobile',
                'pro': 'https://verify.cmpassport.com/h5/httpsPreGetmobile'
            },
            'getTelecomUrl': {
                'test01': 'https://testcert.cmpassport.com:7002/h5/onekeylogin/getNewTelecomPhonescrip',
                'pro': 'https://www.cmpassport.com/h5/onekeylogin/getNewTelecomPhonescrip'
            },
            'getTelecomToken': {
                'test01': 'https://testcert.cmpassport.com:7002/h5/onekeylogin/CTCallback',
                'pro': 'https://www.cmpassport.com/h5/onekeylogin/CTCallback'
            },
            'getUnicomUrl': {
                'test01': 'https://testcert.cmpassport.com:7002/h5/onekeylogin/getNewUnicomPhonescrip',
                'pro': 'https://www.cmpassport.com/h5/onekeylogin/getNewUnicomPhonescrip'
            },
            'getUnicomToken': {
                'test01': 'https://testcert.cmpassport.com:7002/h5/onekeylogin/CUCallback',
                'pro': 'https://www.cmpassport.com/h5/onekeylogin/CUCallback'
            },
            'logReport': {
                'pro': 'https://log-h5.cmpassport.com:9443/log/logReport'
            },
            'getToken': {
                'test01': 'https://testcert.cmpassport.com:7002/h5/onekeylogin/authGetToken',
                'pro': 'https://www.cmpassport.com//h5/onekeylogin/authGetToken'
            },
            'getPageOpt': {
                'test01': 'https://testcert.cmpassport.com:7002/h5/onekeylogin/getPageOption',
                'pro': 'https://www.cmpassport.com//h5/onekeylogin/getPageOption'
            },
            'optparams': {
                'uuid': '',
                'msgId': '',
                'timestamp': _0x23d191(new Date(), 'yyyyMMddhhmmssSSS'),
                'userInformation': '',
                'isimge': ![],
                'expandParams': '',
                'userInformations': _0x19e155(),
                'traceId': '',
                'businessType': '8',
                'status': ![],
                'loading': !![],
                'sysStatus': '',
                'netStatus': '',
                'maskPhone': '',
                'v': '20211103',
                'resourceHref': 'https://www.cmpassport.com/h5/js/jssdk_auth/image/',
                'ifStopGetToken': ![],
                'ifLoadIframe': !![],
                'ifInitOptions': ![],
                'customerPrivacyConfig': ''
            },
            'authPageOpt': {},
            'jssdkLog': {
                'operType': 'onekeylogin',
                'traceid': '',
                'appScene': '0',
                'appid': '',
                'networkType': '',
                'clientType': '',
                'userInformation': '',
                'costtime_GetOwnerAppValidate': '',
                'CMrequestTime_PreGetmobile': '',
                'CMresponseTime_PreGetmobile': '',
                'CM_resultCode': '',
                'CTrequestTime_PreGetmobile': '',
                'CTresponseTime_PreGetmobile': '',
                'CT_resultCode': '',
                'CUrequestTime_PreGetmobile': '',
                'CUresponseTime_PreGetmobile': '',
                'CU_resultCode': '',
                'polling_PreGetmobile': ''
            }
        };
        function _0x4e452a(_0x8d4ad2, _0x5cd726) {
            var _0x5cdb78 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'['split']('');
            var _0x24a43e = [], _0x54ec99;
            _0x5cd726 = _0x5cd726 || _0x5cdb78['length'];
            if (_0x8d4ad2) {
                for (_0x54ec99 = 0x0; _0x54ec99 < _0x8d4ad2; _0x54ec99++)
                    _0x24a43e[_0x54ec99] = _0x5cdb78[0x0 | Math['random']() * _0x5cd726];
            } else {
                var _0xcf026a;
                _0x24a43e[0x8] = _0x24a43e[0xd] = _0x24a43e[0x12] = _0x24a43e[0x17] = '-';
                _0x24a43e[0xe] = '4';
                for (_0x54ec99 = 0x0; _0x54ec99 < 0x24; _0x54ec99++) {
                    if (!_0x24a43e[_0x54ec99]) {
                        _0xcf026a = 0x0 | Math['random']() * 0x10;
                        _0x24a43e[_0x54ec99] = _0x5cdb78[_0x54ec99 == 0x13 ? _0xcf026a & 0x3 | 0x8 : _0xcf026a];
                    }
                }
            }
            return _0x24a43e['join']('');
        }
        function _0x19e155() {
            return encodeURIComponent(_0x451233(_0x165c24()));
        }
        function _0x23d191(_0x1bd34b, _0x228166) {
            var _0x44ff65 = {
                'M+': _0x1bd34b['getMonth']() + 0x1,
                'd+': _0x1bd34b['getDate'](),
                'h+': _0x1bd34b['getHours'](),
                'm+': _0x1bd34b['getMinutes'](),
                's+': _0x1bd34b['getSeconds'](),
                'q+': Math['floor']((_0x1bd34b['getMonth']() + 0x3) / 0x3),
                'S+': _0x1bd34b['getMilliseconds']()
            };
            if (/(y+)/['test'](_0x228166)) {
                _0x228166 = _0x228166['replace'](RegExp['$1'], (_0x1bd34b['getFullYear']() + '')['substr'](0x4 - RegExp['$1']['length']));
            }
            for (var _0x4dcaef in _0x44ff65) {
                if (new RegExp('(' + _0x4dcaef + ')')['test'](_0x228166)) {
                    _0x228166 = _0x228166['replace'](RegExp['$1'], RegExp['$1']['length'] == 0x1 ? _0x44ff65[_0x4dcaef] : ((RegExp['$1']['length'] == 0x3 && _0x4dcaef == 'S+' ? '000' : '00') + _0x44ff65[_0x4dcaef])['substr'](('' + _0x44ff65[_0x4dcaef])['length']));
                }
            }
            return _0x228166;
        }
        function _0x165c24() {
            var _0x347430 = navigator['userAgent'];
            _0x347430['indexOf']('Android') > -0x1 || _0x347430['indexOf']('Linux') > -0x1;
            var _0x1fa5de = top['navigator']['platform'] + '@@' + top['navigator']['userAgent'] + '@@' + top['navigator']['appVersion'] + '@@' + top['navigator']['cookieEnabled'] + '@@' + top['navigator']['cpuClass'] + '@@' + top['navigator']['hardwareConcurrency'] + '@@' + top['navigator']['language'] + '@@' + top['navigator']['plugins'] + '@@' + top['screen']['availWidth'] + '@@' + top['navigator']['availHeight'] + '@@' + top['screen']['colorDepth'] + '@@' + top['Date']['getTimezoneOffset'];
            var _0x2dd0a1 = top['navigator']['userAgent'];
            if (_0x2dd0a1['length'] > 0x64) {
                _0x2dd0a1 = _0x2dd0a1['substring'](0x0, 0x64);
            }
            var _0x502c38 = top['navigator']['platform'] + '@@' + _0x2dd0a1 + '@@' + hex_md5(_0x1fa5de);
            return _0x502c38;
        }
        function _0x451233(_0x404307) {
            var _0x26b256 = '';
            var _0x21a1d2 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
            var _0x4efd36, _0x209596, _0x2f5325, _0x81e12b, _0x1c04d4, _0x26a2a4, _0x4bfa33;
            var _0x11593f = 0x0;
            _0x404307 = _0x1f4f2c(_0x404307);
            while (_0x11593f < _0x404307['length']) {
                _0x4efd36 = _0x404307['charCodeAt'](_0x11593f++);
                _0x209596 = _0x404307['charCodeAt'](_0x11593f++);
                _0x2f5325 = _0x404307['charCodeAt'](_0x11593f++);
                _0x81e12b = _0x4efd36 >> 0x2;
                _0x1c04d4 = (_0x4efd36 & 0x3) << 0x4 | _0x209596 >> 0x4;
                _0x26a2a4 = (_0x209596 & 0xf) << 0x2 | _0x2f5325 >> 0x6;
                _0x4bfa33 = _0x2f5325 & 0x3f;
                if (isNaN(_0x209596)) {
                    _0x26a2a4 = _0x4bfa33 = 0x40;
                } else if (isNaN(_0x2f5325)) {
                    _0x4bfa33 = 0x40;
                }
                _0x26b256 = _0x26b256 + _0x21a1d2['charAt'](_0x81e12b) + _0x21a1d2['charAt'](_0x1c04d4) + _0x21a1d2['charAt'](_0x26a2a4) + _0x21a1d2['charAt'](_0x4bfa33);
            }
            return _0x26b256;
        }
        function _0x1f4f2c(_0x43b052) {
            _0x43b052 = _0x43b052['replace'](/\r\n/g, '\x0a');
            var _0x44e8a4 = '';
            for (var _0x294f56 = 0x0; _0x294f56 < _0x43b052['length']; _0x294f56++) {
                var _0x2df4f2 = _0x43b052['charCodeAt'](_0x294f56);
                if (_0x2df4f2 < 0x80) {
                    _0x44e8a4 += String['fromCharCode'](_0x2df4f2);
                } else if (_0x2df4f2 > 0x7f && _0x2df4f2 < 0x800) {
                    _0x44e8a4 += String['fromCharCode'](_0x2df4f2 >> 0x6 | 0xc0);
                    _0x44e8a4 += String['fromCharCode'](_0x2df4f2 & 0x3f | 0x80);
                } else {
                    _0x44e8a4 += String['fromCharCode'](_0x2df4f2 >> 0xc | 0xe0);
                    _0x44e8a4 += String['fromCharCode'](_0x2df4f2 >> 0x6 & 0x3f | 0x80);
                    _0x44e8a4 += String['fromCharCode'](_0x2df4f2 & 0x3f | 0x80);
                }
            }
            return _0x44e8a4;
        }
        function _0x1e2667() {
            var _0x46d6cc = navigator['userAgent']
              ;
            var _0x3817b1 = _0x46d6cc['indexOf']('Android') > -0x1 || _0x46d6cc['indexOf']('Linux') > -0x1;
            var _0x42c336 = !!_0x46d6cc['match'](/\(i[^;]+;( U;)? CPU.+Mac OS X/);
            if (_0x3817b1) {
                return '0';
            }
            if (_0x42c336) {
                return '1';
            }
            return '3';
        }
        function _0x318de7(_0x452408, _0x5bdf75, _0x525aa0) {
            var _0x5bdf75 = CryptoJS['enc']['Utf8']['parse'](_0x5bdf75);
            var _0x525aa0 = CryptoJS['enc']['Utf8']['parse'](_0x525aa0);
            var _0xc49959 = '';
            var _0x357b1c = '';
            if (typeof _0x452408 == 'string') {
                _0x357b1c = _0x452408;
            } else if (typeof _0x452408 == 'object') {
                _0x357b1c = CryptoJS['enc']['Utf8']['parse'](_0x452408);
            }
            _0xc49959 = CryptoJS['AES']['encrypt'](_0x357b1c, _0x5bdf75, {
                'iv': _0x525aa0,
                'mode': CryptoJS['mode']['CBC'],
                'padding': CryptoJS['pad']['Pkcs7']
            });
            return _0xc49959['ciphertext']['toString']();
        }
        var _0x2ad624 = function(_0x336093) {
            var _0x4312ed = [];
            for (var _0x4880a9 in _0x336093) {
                _0x4312ed['push'](encodeURIComponent(_0x4880a9) + '=' + encodeURIComponent(_0x336093[_0x4880a9]));
            }
            return _0x4312ed['join']('&');
        };
        var _0x3ff96d = function(_0xc66b34) {
            _0xc66b34 = _0xc66b34 || {};
            if (!_0xc66b34['url'] || !_0xc66b34['callback']) {
                throw new Error('参数不合法');
            }
            var _0x1c9e4f = document['getElementsByTagName']('head')[0x0];
            var _0x46f0a5 = '';
            if (_0xc66b34['data']) {
                _0xc66b34['data'][_0xc66b34['callback']] = _0xc66b34['callback'];
                _0x46f0a5 += _0x2ad624(_0xc66b34['data']);
            } else {
                _0x46f0a5 += _0xc66b34['callback'] + '=' + _0xc66b34['callback'];
            }
            var _0x4b351d = document['createElement']('script');
            _0x1c9e4f['appendChild'](_0x4b351d);
            window[_0xc66b34['callback']] = function(_0x3fed64) {
                _0x1c9e4f['removeChild'](_0x4b351d);
                clearTimeout(_0x4b351d['timer']);
                window[_0xc66b34['callback']] = null;
                _0xc66b34['success'] && _0xc66b34['success'](_0x3fed64);
            }
            ;
            if (_0xc66b34['oSscrType'] === 0x1) {
                var _0x1b24f6 = _0xc66b34['url']['indexOf']('?') < 0x0 ? '?' : '&';
                _0x4b351d['src'] = _0xc66b34['url'] + _0x1b24f6 + _0x46f0a5;
            } else {
                _0x4b351d['src'] = _0xc66b34['url'];
            }
            if (_0xc66b34['time']) {
                _0x4b351d['timer'] = setTimeout(function() {
                    window[_0xc66b34['callback']] = null;
                    _0x1c9e4f['removeChild'](_0x4b351d);
                    _0xc66b34['fail'] && _0xc66b34['fail']({
                        'message': '超时'
                    });
                }, _0xc66b34['time']);
            }
        };
        function _0x530764(_0x404e56) {
            if (typeof _0x404e56 == 'string') {
                try {
                    var _0x1ea2ce = JSON['parse'](_0x404e56);
                    if (typeof _0x1ea2ce == 'object' && _0x1ea2ce) {
                        return !![];
                    } else {
                        return ![];
                    }
                } catch (_0x10eae8) {
                    return ![];
                }
            }
        }
        function _0x65a829() {
            var _0x3e3022, _0xf2b7df, _0x19fa8c, _0x5e4d49;
            if (document['documentElement'] && document['documentElement']['scrollTop']) {
                _0x3e3022 = document['documentElement']['scrollTop'];
                _0xf2b7df = document['documentElement']['scrollLeft'];
                _0x19fa8c = document['documentElement']['scrollWidth'];
                _0x5e4d49 = document['documentElement']['scrollHeight'];
            } else if (document['body']) {
                _0x3e3022 = document['body']['scrollTop'];
                _0xf2b7df = document['body']['scrollLeft'];
                _0x19fa8c = document['body']['scrollWidth'];
                _0x5e4d49 = document['body']['scrollHeight'];
            }
            return {
                'top': _0x3e3022,
                'left': _0xf2b7df,
                'width': _0x19fa8c,
                'height': _0x5e4d49
            };
        }
        var _0x24f766, _0x4538fc, _0x5c5d35;
        var _0x56edeb = {
            'getConnection': function(_0xd73d64) {
                if (_0xa083e8['optparams']['msgId'] == '') {
                    _0xa083e8['optparams']['msgId'] = _0x4e452a(0x20, 0x20);
                }
                var _0x4b1559 = navigator['connection'] || navigator['mozConnection'] || navigator['webkitConnection'] || {
                    'type': 'unknown'
                };
                var _0x24cd7e = '2.0';
                var _0x2701a8 = _0x24cd7e + _0xd73d64 + _0xa083e8['optparams']['timestamp'] + _0xa083e8['optparams']['msgId'] + '@Fdiwmxy7CBDDQNUI';
                var _0x2b1183 = hex_md5(_0x2701a8);
                var _0x11d61c = {
                    'appid': _0xd73d64,
                    'msgid': _0xa083e8['optparams']['msgId'],
                    'netType': _0x4b1559['type'] == 'none' ? 'unknown' : _0x4b1559['type'] || 'unknown'
                };
                var _0x38da66 = {
                    'header': {
                        'sign': _0x2b1183,
                        'msgid': _0xa083e8['optparams']['msgId'],
                        'version': _0x24cd7e,
                        'appid': _0xd73d64,
                        'systemtime': _0xa083e8['optparams']['timestamp']
                    },
                    'body': {
                        'log': {
                            'UA': navigator['userAgent'],
                            'appId': _0xd73d64,
                            'msgid': _0xa083e8['optparams']['msgId'],
                            'netType': _0x11d61c['netType']
                        }
                    }
                };
                var _0x47926e = _0xa083e8['logReport']['pro'];
                var _0x28b32c;
                if (window['XMLHttpRequest']) {
                    _0x28b32c = new XMLHttpRequest();
                } else {
                    _0x28b32c = new ActiveXObject('Microsoft.XMLHTTP');
                }
    _0x28b32c['open']('post', _0x47926e, !![]);
                _0x28b32c['send'](JSON['stringify'](_0x38da66));
                return _0x11d61c;
            },
            'init': function(_0x1c474f) {
                var _0x2f1500 = this;
                if (event['data']['UC_MSG_Method'] || !(event['origin'] == 'https://www.cmpassport.com' || event['origin'] == 'https://testcert.cmpassport.com:7002' || event['origin'] == 'http://120.197.235.102')) {
                    return;
                }
                var _0x40876e = document['getElementById']('auth');
                try {
                    _0x40876e['contentWindow']['document']['write']('');
                    _0x40876e['contentWindow']['document']['clear']();
                } catch (_0x2e7ab8) {}
                if (_0x40876e && (event['data']['msgId'] || event['data']['code'])) {
                    _0x40876e['parentNode']['removeChild'](_0x40876e);
                    _0xa083e8['optparams']['loading'] = !![];
                    if (event['data']['code'] === '103000' && _0xa083e8['optparams']['status'] == ![]) {
                        _0xa083e8['optparams']['success'](event['data']);
                        _0x5e7475['removeEventListener']('message', _0x2f1500['init'], ![]);
                        _0xa083e8['optparams']['status'] = !![];
                    } else if (_0xa083e8['optparams']['status'] == ![]) {
                        _0xa083e8['optparams']['error'](event['data']);
                        _0x5e7475['removeEventListener']('message', _0x2f1500['init'], ![]);
                        _0xa083e8['optparams']['status'] = !![];
                    }
                }
            },
            'getTokenInfo': function(_0x261120) {
                if (!_0xa083e8['optparams']['loading']) {
                    return;
                }
                for (var _0x413462 in _0xa083e8['jssdkLog']) {
                    _0xa083e8['jssdkLog'][_0x413462] = '';
                }
                _0xa083e8['optparams']['status'] = ![];
                _0xa083e8['optparams']['msgId'] = _0x261120['data']['traceId'];
                _0xa083e8['optparams']['traceId'] = _0x261120['data']['traceId'];
                _0xa083e8['optparams']['maskLength'] = 0x0;
                _0xa083e8['optparams']['success'] = 'undefined' === typeof _0x261120['success'] ? function() {}
                : _0x261120['success'];
                _0xa083e8['optparams']['error'] = 'undefined' === typeof _0x261120['error'] ? function() {}
                : _0x261120['error'];
                _0xa083e8['optparams']['layerCallback'] = 'undefined' === typeof _0x261120['layerCallback'] ? function() {}
                : _0x261120['layerCallback'];
                _0xa083e8['optparams']['authPageType'] = _0x261120['data']['authPageType'] ? _0x261120['data']['authPageType'] : '0';
                _0x5e7475['removeEventListener']('message', _0x56edeb['init'], ![]);
                _0x5e7475['addEventListener']('message', _0x56edeb['init'], ![]);
                _0xa083e8['optparams']['sysStatus'] = _0x1e2667();
                _0xa083e8['optparams']['netStatus'] = _0x56edeb['getConnection'](_0x261120['data']['appId'])['netType'];
                var _0x27ee53 = {
                    'version': _0x261120['data']['version'],
                    'openType': _0x261120['data']['openType'],
                    'timestamp': _0x261120['data']['timestamp'],
                    'appId': _0x261120['data']['appId'],
                    'traceId': _0x261120['data']['traceId'],
                    'msgId': _0x261120['data']['traceId'],
                    'sign': _0x261120['data']['sign'],
                    'expandParams': _0x261120['data']['expandParams'],
                    'isTest': _0x261120['data']['isTest'],
                    'error': 'undefined' === typeof _0x261120['error'] ? function() {}
                    : _0x261120['error'],
                    'success': 'undefined' === typeof _0x261120['success'] ? function() {}
                    : _0x261120['success'],
                    'authPageType': _0x261120['data']['authPageType'] ? _0x261120['data']['authPageType'] : '0',
                    'userInformation': _0xa083e8['optparams']['userInformations'],
                    'businessType': _0xa083e8['optparams']['businessType'],
                    'YDData': {
                        'code': '',
                        'message': ''
                    },
                    'CTData': {
                        'code': '',
                        'message': ''
                    },
                    'CUData': {
                        'code': '',
                        'message': ''
                    }
                };
                _0xa083e8['jssdkLog']['traceid'] = _0x27ee53['traceId'];
                _0xa083e8['jssdkLog']['appid'] = _0x27ee53['appId'];
                _0xa083e8['jssdkLog']['appScene'] = '0';
                _0xa083e8['jssdkLog']['userInformation'] = _0x27ee53['userInformation'];
                _0xa083e8['jssdkLog']['clientType'] = _0xa083e8['optparams']['sysStatus'] == '0' ? 'android' : _0xa083e8['optparams']['sysStatus'] == '1' ? 'iOS' : 'other';
                _0xa083e8['optparams']['netStatus'] = 'unknown';
                if (_0xa083e8['optparams']['netStatus'] == 'unknown' || _0xa083e8['optparams']['netStatus'] == 'cellular') {
                    _0xa083e8['jssdkLog']['networkType'] = _0xa083e8['optparams']['netStatus'];
                    if (_0x27ee53['authPageType'] == '1' || _0x27ee53['authPageType'] == '2') {
                        _0xa083e8['optparams']['ifLoadIframe'] = ![];
                    } else {
                        _0xa083e8['optparams']['ifLoadIframe'] = !![];
                        _0x24f766 = document['createElement']('iframe');
                        _0x24f766['setAttribute']('id', 'auth');
                        _0x24f766['style']['display'] = 'none';
                        document['body']['appendChild'](_0x24f766);
                    }
                    if (_0xa083e8['optparams']['ifStopGetToken']) {
                        _0x56edeb['getYDPhoneNumber'](_0x27ee53);
                    } else {
                        _0x56edeb['endGetToken'](_0x27ee53);
                    }
                } else {
                    _0xa083e8['jssdkLog']['networkType'] = 'wifi';
                    _0x28fa04['getLog']();
                    var _0x2b0e04 = {
                        'code': '504',
                        'message': '网络环境不支持取号',
                        'msgId': _0xa083e8['optparams']['msgId']
                    };
                    _0x5e7475['removeEventListener']('message', _0x56edeb['init'], ![]);
                    _0x261120['error'](_0x2b0e04);
                    _0xa083e8['optparams']['loading'] = !![];
                    return;
                }
            },
            'getYDPhoneNumber': function(_0x274d24) {
                var _0x168605 = this;
                var _0x43f832 = {
                    'version': _0x274d24['version'],
                    'timestamp': _0x274d24['timestamp'],
                    'appId': _0x274d24['appId'],
                    'businessType': _0x274d24['businessType'],
                    'traceId': _0x274d24['traceId'],
                    'msgId': _0x274d24['traceId'],
                    'sign': _0x274d24['sign'],
                    'authPageType': _0xa083e8['optparams']['authPageType'],
                    'userInformation': _0x274d24['userInformation'],
                    'expandParams': _0x274d24['expandParams']
                };
                var _0x1ca621 = _0x274d24['isTest'] === '0' ? _0xa083e8['httpsPreGetmobile']['test01'] : _0xa083e8['httpsPreGetmobile']['pro'];
                try {
                    if (_0xa083e8['optparams']['loading']) {
                        _0xa083e8['optparams']['loading'] = ![];
                        _0xa083e8['jssdkLog']['CMrequestTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                        _0x495183['ajax']({
                            'request': {
                                'url': _0x1ca621,
                                'method': 'post',
                                'data': JSON['stringify'](_0x43f832)
                            },
                            'success': function(_0x56308d) {
                                var _0x169531 = _0x56308d['result']['body'];
                                _0xa083e8['jssdkLog']['CMresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                                _0xa083e8['jssdkLog']['CM_resultCode'] = _0x169531['resultCode'];
                                if (_0x169531['resultCode'] === '103000') {
                                    var _0x529949 = {
                                        'traceId': _0x274d24['traceId'],
                                        'accessToken': _0x169531['accessToken'],
                                        'maskPhone': _0x169531['maskPhone'],
                                        'authPageUrl': _0x169531['authPageUrl'],
                                        'authLevel': _0x169531['authLevel'],
                                        'authName': _0x169531['appName'],
                                        'userInformation': _0xa083e8['optparams']['userInformations'],
                                        'appId': _0x274d24['appId'],
                                        'expandParams': _0x274d24['expandParams'],
                                        'isTest': _0x274d24['isTest'],
                                        'customerPrivacyConfig': _0x169531['customerPrivacyConfig'] || '',
                                        'oper': 'CM'
                                    };
                                    _0x168605['getAuthentication'](_0x529949, _0x274d24);
                                } else {
                                    _0x274d24['YDData'] = {
                                        'code': _0x169531['resultCode'],
                                        'message': _0x169531['resultDesc']
                                    };
                                    if (_0xa083e8['optparams']['ifStopGetToken']) {
                                        _0x168605['getTelecomPhone'](_0x274d24);
                                    } else {
                                        _0x56edeb['endGetToken'](_0x274d24);
                                    }
                                }
                            },
                            'error': function(_0x181f03) {
                                _0x274d24['YDData'] = {
                                    'code': '500',
                                    'message': '网络异常，请检查网络设置'
                                };
                                if (_0xa083e8['optparams']['ifStopGetToken']) {
                                    _0x168605['getTelecomPhone'](_0x274d24);
                                } else {
                                    _0x56edeb['endGetToken'](_0x274d24);
                                }
                            }
                        });
                    }
                } catch (_0x2d9399) {
                    throw new Error(_0x2d9399);
                }
            },
            'getTelecomPhone': function(_0x3fc9b6) {
                var _0x369481 = this;
                var _0x459d3a = _0x4e452a(0x10, 0x10);
                var _0x419882 = hex_md5(_0x459d3a)['substr'](0x8, 0x10)['toUpperCase']();
                var _0x59e42b = _0x1e2667();
                var _0x4799b8 = hex_md5(_0x3fc9b6['appId'] + _0x3fc9b6['version'] + _0x3fc9b6['msgId'] + _0x3fc9b6['timestamp'])['toLowerCase']();
                var _0x31be4d = {
                    'ver': '1.0',
                    'appId': _0x3fc9b6['appId'],
                    'interfaceVersion': _0x3fc9b6['version'],
                    'expandParams': '',
                    'msgId': _0x3fc9b6['msgId'],
                    'timestamp': _0x3fc9b6['timestamp'],
                    'mobilesystem': _0x59e42b,
                    'sign': _0x4799b8
                };
                _0x31be4d = JSON['stringify'](_0x31be4d);
                _0x31be4d = _0x318de7(_0x31be4d, _0x419882, '0000000000000000');
                var _0x4abedc = {
                    'header': {
                        'appId': _0x3fc9b6['appId'],
                        'interfaceVersion': _0x3fc9b6['version'],
                        'traceId': _0x3fc9b6['traceId']
                    },
                    'body': {
                        'encrypted': _0x459d3a,
                        'reqdata': _0x31be4d,
                        'businessType': _0x3fc9b6['businessType']
                    }
                };
                var _0x5250cf = _0x3fc9b6['isTest'] === '0' ? _0xa083e8['getTelecomUrl']['test01'] : _0xa083e8['getTelecomUrl']['pro'];
                try {
                    _0xa083e8['jssdkLog']['CTrequestTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                    _0x495183['ajax']({
                        'request': {
                            'headers': _0x4abedc['header'],
                            'url': _0x5250cf,
                            'method': 'post',
                            'data': JSON['stringify'](_0x4abedc['body'])
                        },
                        'success': function(_0xe236c4) {
                            var _0x34b473 = _0xe236c4['result'];
                            if (_0x34b473['resultCode'] == '103000') {
                                _0x3ff96d({
                                    'url': _0x34b473['data'],
                                    'callback': 'getTelecomPhone',
                                    'time': 0x1f40,
                                    'oSscrType': 0x0,
                                    'success': function(_0x2cea8d) {
                                        if (_0x2cea8d['result'] == '0') {
                                            if (_0xa083e8['optparams']['ifStopGetToken']) {
                                                _0x369481['getNewTelecomPhoneNumber'](_0x3fc9b6, _0x2cea8d['data']);
                                            } else {
                                                _0x56edeb['endGetToken'](_0x3fc9b6);
                                            }
                                        } else {
                                            _0xa083e8['jssdkLog']['CTresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                                            _0xa083e8['jssdkLog']['CT_resultCode'] = _0x2cea8d['result']['toString']();
                                            _0x3fc9b6['CTData'] = {
                                                'code': _0x2cea8d['result']['toString'](),
                                                'message': _0x2cea8d['data']
                                            };
                                            if (_0xa083e8['optparams']['ifStopGetToken']) {
                                                _0x369481['getUnicomPhone'](_0x3fc9b6);
                                            } else {
                                                _0x56edeb['endGetToken'](_0x3fc9b6);
                                            }
                                        }
                                    },
                                    'fail': function() {
                                        _0xa083e8['jssdkLog']['CTresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                                        _0xa083e8['jssdkLog']['CT_resultCode'] = '500';
                                        _0x3fc9b6['CTData'] = {
                                            'code': '500',
                                            'message': '网络异常，请检查网络设置'
                                        };
                                        if (_0xa083e8['optparams']['ifStopGetToken']) {
                                            _0x369481['getUnicomPhone'](_0x3fc9b6);
                                        } else {
                                            _0x56edeb['endGetToken'](_0x3fc9b6);
                                        }
                                    }
                                });
                            } else {
                                _0xa083e8['jssdkLog']['CTresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                                _0xa083e8['jssdkLog']['CT_resultCode'] = _0x34b473['resultCode'];
                                _0x3fc9b6['CTData'] = {
                                    'code': _0x34b473['resultCode'],
                                    'message': _0x34b473['desc']
                                };
                                if (_0xa083e8['optparams']['ifStopGetToken']) {
                                    _0x369481['getUnicomPhone'](_0x3fc9b6);
                                } else {
                                    _0x56edeb['endGetToken'](_0x3fc9b6);
                                }
                            }
                        },
                        'error': function(_0x39aaa6) {
                            _0xa083e8['jssdkLog']['CTresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                            _0xa083e8['jssdkLog']['CT_resultCode'] = '500';
                            _0x3fc9b6['CTData'] = {
                                'code': '500',
                                'message': '网络异常，请检查网络设置'
                            };
                            _0x369481['getUnicomPhone'](_0x3fc9b6);
                        }
                    });
                } catch (_0x5a557a) {
                    throw new Error(_0x5a557a);
                }
            },
            'getNewTelecomPhoneNumber': function(_0x25d014, _0xf4436f) {
                var _0x4a0e6c = this;
                var _0x17cd8f = {
                    'header': {
                        'appId': _0x25d014['appId'],
                        'interfaceVersion': _0x25d014['version'],
                        'traceId': _0x25d014['traceId'],
                        'businessType': _0x25d014['businessType'],
                        'timestamp': _0x25d014['timestamp'],
                        'authPageType': _0xa083e8['optparams']['authPageType']
                    },
                    'body': {
                        'data': _0xf4436f,
                        'ver': '1.0',
                        'userInformation': _0x25d014['userInformation']
                    }
                };
                var _0x15cd95 = _0x25d014['isTest'] === '0' ? _0xa083e8['getTelecomToken']['test01'] : _0xa083e8['getTelecomToken']['pro'];
                try {
                    _0x495183['ajax']({
                        'request': {
                            'headers': _0x17cd8f['header'],
                            'url': _0x15cd95,
                            'method': 'post',
                            'data': JSON['stringify'](_0x17cd8f['body'])
                        },
                        'success': function(_0x56fbe1) {
                            var _0x4cfcdd = _0x56fbe1['result'];
                            _0xa083e8['jssdkLog']['CTresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                            _0xa083e8['jssdkLog']['CT_resultCode'] = _0x4cfcdd['resultCode'];
                            if (_0x4cfcdd['resultCode'] == '103000' && _0x4cfcdd['accessToken'] != '') {
                                var _0x46c780 = {
                                    'traceId': _0x25d014['traceId'],
                                    'accessToken': _0x4cfcdd['accessToken'],
                                    'maskPhone': _0x4cfcdd['maskPhone'],
                                    'authPageUrl': _0x4cfcdd['authPageUrl'],
                                    'authLevel': _0x4cfcdd['authLevel'],
                                    'authName': _0x4cfcdd['appName'],
                                    'userInformation': _0x25d014['userInformation'],
                                    'appId': _0x25d014['appId'],
                                    'expandParams': _0x25d014['expandParams'],
                                    'isTest': _0x25d014['isTest'],
                                    'oper': 'CT',
                                    'customerPrivacyConfig': _0x4cfcdd['customerPrivacyConfig'] || ''
                                };
                                _0x4a0e6c['getAuthentication'](_0x46c780, _0x25d014);
                            } else {
                                _0x25d014['CTData'] = {
                                    'code': '',
                                    'message': ''
                                };
                                _0x25d014['CTData']['code'] = _0x4cfcdd['resultCode'] == '103000' ? '502' : _0x4cfcdd['resultCode'];
                                _0x25d014['CTData']['message'] = _0x4cfcdd['resultCode'] == '103000' ? '电信取号能力关闭' : _0x4cfcdd['desc'];
                                var _0x1881b0 = {
                                    'msgId': _0xa083e8['optparams']['msgId'],
                                    'CUData': {},
                                    'CTData': _0x25d014['CTData'],
                                    'YDData': _0x25d014['YDData']
                                };
                                _0x28fa04['getLog']();
                                if (_0xa083e8['optparams']['ifLoadIframe']) {
                                    _0x24f766['parentNode']['removeChild'](_0x24f766);
                                }
                                _0x5e7475['removeEventListener']('message', _0x4a0e6c['init'], ![]);
                                _0x25d014['error'](_0x1881b0);
                                _0xa083e8['optparams']['loading'] = !![];
                            }
                        },
                        'error': function(_0x78c284) {
                            _0xa083e8['jssdkLog']['CTresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                            _0xa083e8['jssdkLog']['CT_resultCode'] = '500';
                            _0x25d014['CTData'] = {
                                'code': '500',
                                'message': '网络异常，请检查网络设置'
                            };
                            var _0x461bab = {
                                'msgId': _0x25d014['msgId'],
                                'CUData': {},
                                'CTData': _0x25d014['CTData'],
                                'YDData': _0x25d014['YDData']
                            };
                            _0x28fa04['getLog']();
                            if (_0xa083e8['optparams']['ifLoadIframe']) {
                                _0x24f766['parentNode']['removeChild'](_0x24f766);
                            }
                            _0x5e7475['removeEventListener']('message', _0x4a0e6c['init'], ![]);
                            _0x25d014['error'](_0x461bab);
                            _0xa083e8['optparams']['loading'] = !![];
                        }
                    });
                } catch (_0x106c82) {
                    throw new Error(_0x106c82);
                }
            },
            'getUnicomPhone': function(_0x14d690) {
                var _0x2c08df = this;
                var _0x3fc25c = _0x4e452a(0x10, 0x10);
                var _0x39e419 = hex_md5(_0x3fc25c)['substr'](0x8, 0x10)['toUpperCase']();
                var _0x5502dd = _0x1e2667();
                var _0x2a792f = hex_md5(_0x14d690['appId'] + _0x14d690['version'] + _0x14d690['msgId'] + _0x14d690['timestamp'])['toLowerCase']();
                var _0x430be6 = {
                    'ver': '1.0',
                    'appId': _0x14d690['appId'],
                    'interfaceVersion': _0x14d690['version'],
                    'expandParams': '',
                    'msgId': _0x14d690['msgId'],
                    'timestamp': _0x14d690['timestamp'],
                    'mobilesystem': _0x5502dd,
                    'sign': _0x2a792f
                };
                _0x430be6 = JSON['stringify'](_0x430be6);
                _0x430be6 = _0x318de7(_0x430be6, _0x39e419, '0000000000000000');
                var _0xad1e62 = {
                    'header': {
                        'appId': _0x14d690['appId'],
                        'interfaceVersion': _0x14d690['version'],
                        'traceId': _0x14d690['traceId']
                    },
                    'body': {
                        'encrypted': _0x3fc25c,
                        'reqdata': _0x430be6,
                        'businessType': _0x14d690['businessType']
                    }
                };
                var _0x51ef27 = _0x14d690['isTest'] === '0' ? _0xa083e8['getUnicomUrl']['test01'] : _0xa083e8['getUnicomUrl']['pro'];
                try {
                    _0xa083e8['jssdkLog']['CUrequestTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                    _0x495183['ajax']({
                        'request': {
                            'headers': _0xad1e62['header'],
                            'url': _0x51ef27,
                            'method': 'post',
                            'data': JSON['stringify'](_0xad1e62['body'])
                        },
                        'success': function(_0x4bfdc0) {
                            var _0x4fd2a5 = _0x4bfdc0['result'];
                            if (_0x4fd2a5['resultCode'] == '103000') {
                                _0x3ff96d({
                                    'url': _0x4fd2a5['data'],
                                    'callback': 'getNewUnicomPhone',
                                    'time': 0x1f40,
                                    'oSscrType': 0x0,
                                    'success': function(_0x535731) {
                                        if (_0x535731['result'] == '0') {
                                            _0x2c08df['getNewUnicomPhoneNumber'](_0x14d690, _0x535731['data']);
                                        } else {
                                            _0xa083e8['jssdkLog']['CUresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                                            _0xa083e8['jssdkLog']['CU_resultCode'] = _0x535731['code'];
                                            _0x14d690['CUData'] = {
                                                'code': _0x535731['code'],
                                                'message': _0x535731['msg'],
                                                'result': _0x535731['result']
                                            };
                                            var _0x1fe958 = {
                                                'msgId': _0xa083e8['optparams']['msgId'],
                                                'CUData': _0x14d690['CUData'],
                                                'CTData': _0x14d690['CTData'],
                                                'YDData': _0x14d690['YDData']
                                            };
                                            _0x28fa04['getLog']();
                                            if (_0xa083e8['optparams']['ifLoadIframe']) {
                                                _0x24f766['parentNode']['removeChild'](_0x24f766);
                                            }
                                            _0x5e7475['removeEventListener']('message', _0x2c08df['init'], ![]);
                                            _0x14d690['error'](_0x1fe958);
                                            _0xa083e8['optparams']['loading'] = !![];
                                        }
                                    },
                                    'fail': function() {
                                        _0xa083e8['jssdkLog']['CUresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                                        _0xa083e8['jssdkLog']['CU_resultCode'] = '500';
                                        _0x14d690['CUData'] = {
                                            'code': '500',
                                            'message': '网络异常，请检查网络设置'
                                        };
                                        var _0x4fcb2c = {
                                            'msgId': _0xa083e8['optparams']['msgId'],
                                            'CUData': _0x14d690['CUData'],
                                            'CTData': _0x14d690['CTData'],
                                            'YDData': _0x14d690['YDData']
                                        };
                                        _0x28fa04['getLog']();
                                        if (_0xa083e8['optparams']['ifLoadIframe']) {
                                            _0x24f766['parentNode']['removeChild'](_0x24f766);
                                        }
                                        _0x5e7475['removeEventListener']('message', _0x2c08df['init'], ![]);
                                        _0x14d690['error'](_0x4fcb2c);
                                        _0xa083e8['optparams']['loading'] = !![];
                                    }
                                });
                            } else {
                                _0xa083e8['jssdkLog']['CUresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                                _0xa083e8['jssdkLog']['CU_resultCode'] = _0x4fd2a5['resultCode'];
                                _0x14d690['CUData'] = {
                                    'code': _0x4fd2a5['resultCode'],
                                    'message': _0x4fd2a5['desc']
                                };
                                var _0x49c6de = {
                                    'msgId': _0xa083e8['optparams']['msgId'],
                                    'CUData': _0x14d690['CUData'],
                                    'CTData': _0x14d690['CTData'],
                                    'YDData': _0x14d690['YDData']
                                };
                                _0x28fa04['getLog']();
                                if (_0xa083e8['optparams']['ifLoadIframe']) {
                                    _0x24f766['parentNode']['removeChild'](_0x24f766);
                                }
                                _0x5e7475['removeEventListener']('message', _0x2c08df['init'], ![]);
                                _0x14d690['error'](_0x49c6de);
                                _0xa083e8['optparams']['loading'] = !![];
                            }
                        },
                        'error': function(_0x2f52ee) {
                            _0xa083e8['jssdkLog']['CUresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                            _0xa083e8['jssdkLog']['CU_resultCode'] = '500';
                            _0x14d690['CUData'] = {
                                'code': '500',
                                'message': '网络异常，请检查网络设置'
                            };
                            var _0x405cc8 = {
                                'msgId': _0xa083e8['optparams']['msgId'],
                                'CUData': _0x14d690['CUData'],
                                'CTData': _0x14d690['CTData'],
                                'YDData': _0x14d690['YDData']
                            };
                            _0x28fa04['getLog']();
                            if (_0xa083e8['optparams']['ifLoadIframe']) {
                                _0x24f766['parentNode']['removeChild'](_0x24f766);
                            }
                            _0x5e7475['removeEventListener']('message', _0x2c08df['init'], ![]);
                            _0x14d690['error'](_0x405cc8);
                            _0xa083e8['optparams']['loading'] = !![];
                        }
                    });
                } catch (_0x18f8f6) {
                    throw new Error(_0x18f8f6);
                }
            },
            'getNewUnicomPhoneNumber': function(_0x4057db, _0x3d2aa1) {
                var _0x34f4c3 = this;
                var _0xc521d5 = {
                    'header': {
                        'appId': _0x4057db['appId'],
                        'interfaceVersion': _0x4057db['version'],
                        'traceId': _0x4057db['traceId'],
                        'businessType': '8',
                        'timestamp': _0x4057db['timestamp'],
                        'authPageType': _0xa083e8['optparams']['authPageType']
                    },
                    'body': {
                        'data': _0x3d2aa1,
                        'ver': '1.0',
                        'userInformation': _0xa083e8['userInformation']
                    }
                };
                var _0x507cea = _0x4057db['isTest'] === '0' ? _0xa083e8['getUnicomToken']['test01'] : _0xa083e8['getUnicomToken']['pro'];
                try {
                    _0x495183['ajax']({
                        'request': {
                            'headers': _0xc521d5['header'],
                            'url': _0x507cea,
                            'method': 'post',
                            'data': JSON['stringify'](_0xc521d5['body'])
                        },
                        'success': function(_0x2922a4) {
                            var _0x445eb5 = _0x2922a4['result'];
                            _0xa083e8['jssdkLog']['CUresponseTime_PreGetmobile'] = _0x23d191(new Date(), 'yyyyMMddhhmmssSSS');
                            _0xa083e8['jssdkLog']['CU_resultCode'] = _0x445eb5['resultCode'];
                            if (_0x445eb5['resultCode'] == '103000' && _0x445eb5['accessToken'] != '') {
                                var _0x2185a9 = {
                                    'traceId': _0x4057db['traceId'],
                                    'accessToken': _0x445eb5['accessToken'],
                                    'maskPhone': _0x445eb5['maskPhone'],
                                    'authPageUrl': _0x445eb5['authPageUrl'],
                                    'authLevel': _0x445eb5['authLevel'],
                                    'authName': _0x445eb5['appName'],
                                    'userInformation': _0x4057db['userInformation'],
                                    'appId': _0x4057db['appId'],
                                    'expandParams': _0x4057db['expandParams'],
                                    'isTest': _0x4057db['isTest'],
                                    'oper': 'CU',
                                    'customerPrivacyConfig': _0x445eb5['customerPrivacyConfig'] || ''
                                };
                                _0x34f4c3['getAuthentication'](_0x2185a9, _0x4057db);
                            } else {
                                _0x4057db['CUData'] = {
                                    'code': '',
                                    'message': ''
                                };
                                _0x4057db['CUData']['code'] = _0x445eb5['resultCode'] == '103000' ? '502' : _0x445eb5['resultCode'];
                                _0x4057db['CUData']['message'] = _0x445eb5['resultCode'] == '103000' ? '联通取号能力关闭' : _0x445eb5['desc'];
                                var _0xbbf54 = {
                                    'msgId': _0xa083e8['optparams']['msgId'],
                                    'CUData': _0x4057db['CUData'],
                                    'CTData': _0x4057db['CTData'],
                                    'YDData': _0x4057db['YDData']
                                };
                                _0x28fa04['getLog']();
                                if (_0xa083e8['optparams']['ifLoadIframe']) {
                                    _0x24f766['parentNode']['removeChild'](_0x24f766);
                                }
                                _0x5e7475['removeEventListener']('message', _0x34f4c3['init'], ![]);
                                _0x4057db['error'](_0xbbf54);
                                _0xa083e8['optparams']['loading'] = !![];
                            }
                        },
                        'error': function(_0x48fd83) {
                            _0x4057db['CUData'] = {
                                'code': '500',
                                'message': '网络异常，请检查网络设置'
                            };
                            var _0x249036 = {
                                'msgId': _0xa083e8['optparams']['msgId'],
                                'CUData': _0x4057db['CUData'],
                                'CTData': _0x4057db['CTData'],
                                'YDData': _0x4057db['YDData']
                            };
                            _0x28fa04['getLog']();
                            if (_0xa083e8['optparams']['ifLoadIframe']) {
                                _0x24f766['parentNode']['removeChild'](_0x24f766);
                            }
                            _0x5e7475['removeEventListener']('message', _0x34f4c3['init'], ![]);
                            _0x4057db['error'](_0x249036);
                            _0xa083e8['optparams']['loading'] = !![];
                        }
                    });
                } catch (_0x102926) {
                    throw new Error(_0x102926);
                }
            },
            'getAuthentication': function(_0x3ee47a, _0x13f718) {
                _0xa083e8['optparams']['authLevel'] = _0x3ee47a['authLevel'];
                _0xa083e8['optparams']['authPageType'] = _0x13f718['authPageType'];
                _0xa083e8['optparams']['customerPrivacyConfig'] = _0x3ee47a['customerPrivacyConfig'];
                if (_0x13f718['authPageType'] == '1' && _0x3ee47a['authLevel'] != '5') {
                    _0x13f718['accessToken'] = _0x3ee47a['accessToken'];
                    _0x13f718['authLevel'] = _0x3ee47a['authLevel'];
                    _0x13f718['maskPhone'] = _0x3ee47a['maskPhone'];
                    _0x13f718['oper'] = _0x3ee47a['oper'];
                    _0x4bfcd0['getPageConf'](_0x13f718);
                    return;
                }
                if (_0x13f718['authPageType'] == '2' && _0x3ee47a['authLevel'] != '5') {
                    _0x13f718['accessToken'] = _0x3ee47a['accessToken'];
                    _0x13f718['authLevel'] = _0x3ee47a['authLevel'];
                    _0x13f718['maskPhone'] = _0x3ee47a['maskPhone'];
                    _0x13f718['oper'] = _0x3ee47a['oper'];
                    _0x3aa33a['getPageConf'](_0x13f718);
                    return;
                }
                var _0x17cccd = this;
                _0x28fa04['getLog']();
                if (!!_0x3ee47a['authPageUrl'] && !!_0x3ee47a['authLevel'] && !!_0x3ee47a['accessToken'] && _0x3ee47a['authLevel'] != '5') {
                    _0x24f766['style']['cssText'] = 'width:\x20100%;height:\x20100%;border:0;position:\x20fixed;top:0;left:0;right:0;bottom:0;z-index:\x20999999999999;background:\x20#fff;';
                    var _0x22ba7f = _0x3ee47a['authPageUrl'];
                    var _0x1accc7 = {
                        'traceId': _0x3ee47a['traceId'],
                        'accessToken': _0x3ee47a['accessToken'],
                        'maskPhone': _0x3ee47a['maskPhone'],
                        'authLevel': _0x3ee47a['authLevel'],
                        'authName': _0x3ee47a['authName'],
                        'userInformation': _0x3ee47a['userInformation'],
                        'appId': _0x3ee47a['appId'],
                        'expandParams': _0x3ee47a['expandParams'],
                        'isTest': _0x3ee47a['isTest'],
                        'oper': _0x3ee47a['oper']
                    };
                    var _0xe08a98 = _0x22ba7f + '?traceId=' + _0x3ee47a['traceId'] + '&accessToken=' + _0x3ee47a['accessToken'] + '&maskPhone=' + _0x3ee47a['maskPhone'] + '&authLevel=' + _0x3ee47a['authLevel'] + '&authName=' + _0x3ee47a['authName'] + '&userInformation=' + _0x3ee47a['userInformation'] + '&appId=' + _0x3ee47a['appId'] + '&expandParams=' + _0x3ee47a['expandParams'] + '&isTest=' + _0x3ee47a['isTest'] + '&oper=' + _0x3ee47a['oper'] + '&from=' + window['location']['origin'] + '&authPageType=' + _0x13f718['authPageType'] + '&v=' + _0xa083e8['optparams']['v'];
                    _0x24f766['src'] = _0xe08a98;
                    if (_0x530764(_0x3ee47a['customerPrivacyConfig']) && _0x13f718['authPageType'] != '3') {
                        _0x24f766['onload'] = function() {
                            _0x24f766['contentWindow']['postMessage'](_0x3ee47a['customerPrivacyConfig'], _0x22ba7f);
                        }
                        ;
                    } else if (_0x13f718['authPageType'] == '3') {
                        _0x24f766['onload'] = function() {
                            _0x24f766['contentWindow']['postMessage'](_0xa083e8['authPageOpt'], _0x22ba7f);
                        }
                        ;
                    }
                } else if (!!_0x3ee47a['authLevel'] && !!_0x3ee47a['accessToken'] && _0x3ee47a['authLevel'] == '5') {
                    if (_0xa083e8['optparams']['ifLoadIframe']) {
                        _0x24f766['parentNode']['removeChild'](_0x24f766);
                    }
                    _0xa083e8['optparams']['maskPhone'] = _0x3ee47a['maskPhone'];
                    var _0x1accc7 = {
                        'code': '103000',
                        'message': '获取AccessToken成功',
                        'msgId': _0xa083e8['optparams']['msgId'],
                        'accessToken': _0x3ee47a['accessToken'],
                        'maskPhone': _0x3ee47a['maskPhone'],
                        'oper': _0x3ee47a['oper']
                    };
                    _0x5e7475['removeEventListener']('message', _0x17cccd['init'], ![]);
                    _0x13f718['success'](_0x1accc7);
                    _0xa083e8['optparams']['loading'] = !![];
                } else {
                    var _0x14817e = {
                        'code': '503',
                        'message': '参数缺失',
                        'msgId': _0xa083e8['optparams']['msgId']
                    };
                    if (_0xa083e8['optparams']['ifLoadIframe']) {
                        _0x24f766['parentNode']['removeChild'](_0x24f766);
                    }
                    _0x5e7475['removeEventListener']('message', _0x17cccd['init'], ![]);
                    _0x13f718['error'](_0x14817e);
                    _0xa083e8['optparams']['loading'] = !![];
                }
            },
            'authGetToken': function(_0x3e35e5) {
                var _0xd6e2ec = this;
                var _0x4a5b7e = _0x3e35e5['data']['maskPhone'] ? _0x3e35e5['data']['maskPhone'] : _0xa083e8['optparams']['maskPhone'];
                var _0x342dc0 = _0x4a5b7e['replace'](/\*+/g, _0x3e35e5['data']['maskVal']);
                var _0x170fc3 = hex_md5(_0x342dc0);
                var _0x589a09 = 'undefined' === typeof _0x3e35e5['success'] ? function() {}
                : _0x3e35e5['success'];
                var _0x2a341d = 'undefined' === typeof _0x3e35e5['error'] ? function() {}
                : _0x3e35e5['error'];
                var _0xda7911 = {
                    'header': {
                        'interfaceVersion': _0x3e35e5['data']['version'],
                        'timestamp': _0x23d191(new Date(), 'yyyyMMddhhmmssSSS'),
                        'appId': _0x3e35e5['data']['appId'],
                        'businessType': _0xa083e8['optparams']['businessType'],
                        'traceId': _0x3e35e5['data']['traceId'],
                        'Content-Type': 'application/json'
                    },
                    'body': {
                        'accessToken': _0x3e35e5['data']['accessToken'],
                        'phone': _0x170fc3,
                        'userInformation': _0xa083e8['optparams']['userInformations'],
                        'expandParams': _0x3e35e5['data']['expandParams']
                    }
                };
                var _0x3f1967 = _0x3e35e5['data']['isTest'] === '0' ? _0xa083e8['getToken']['test01'] : _0xa083e8['getToken']['pro'];
                try {
                    _0x495183['ajax']({
                        'request': {
                            'headers': _0xda7911['header'],
                            'url': _0x3f1967,
                            'method': 'post',
                            'data': JSON['stringify'](_0xda7911['body'])
                        },
                        'success': function(_0x193602) {
                            if (_0x4538fc) {
                                _0x4538fc['parentNode']['removeChild'](_0x4538fc);
                                _0x4538fc = null;
                            }
                            var _0x7f48a2 = _0x193602['result'];
                            if (_0x3e35e5['data']['authPageType'] && (_0x3e35e5['data']['authPageType'] == '1' || _0x3e35e5['data']['authPageType'] == '2') && _0x7f48a2['resultCode'] != '104012') {
                                _0x5c5d35['parentNode']['removeChild'](_0x5c5d35);
                                keyBoard['closeKeyBoard']();
                            }
                            if (_0x7f48a2['resultCode'] === '103000') {
                                var _0x30499d = {
                                    'code': _0x7f48a2['resultCode'],
                                    'token': _0x7f48a2['data']['token'],
                                    'userInformation': _0xa083e8['optparams']['userInformations'],
                                    'msgId': _0x3e35e5['data']['traceId'],
                                    'message': _0x7f48a2['desc']
                                };
                                _0x589a09(_0x30499d);
                                _0x5e7475['removeEventListener']('message', _0xd6e2ec['init'], ![]);
                                _0xa083e8['optparams']['loading'] = !![];
                            } else if (_0x3e35e5['data']['authPageType'] && _0x7f48a2['resultCode'] === '104012' && _0xa083e8['optparams']['authLevel'] != '1' && _0xa083e8['optparams']['authLevel'] != '5') {
                                if (_0xa083e8['optparams']['authPageType'] == '1') {
                                    _0x4bfcd0['showErrorTips']('号码有误，请重新填写');
                                } else {
                                    _0x3aa33a['showErrorTips']('号码有误，请重新填写');
                                }
                            } else {
                                var _0x30499d = {
                                    'code': _0x7f48a2['resultCode'],
                                    'message': _0x7f48a2['desc'],
                                    'msgId': _0x3e35e5['data']['traceId']
                                };
                                _0x2a341d(_0x30499d);
                                _0x5e7475['removeEventListener']('message', _0xd6e2ec['init'], ![]);
                                _0xa083e8['optparams']['loading'] = !![];
                            }
                        },
                        'error': function(_0x472be1) {
                            if (_0x3e35e5['data']['authPageType'] && (_0x3e35e5['data']['authPageType'] == '1' || _0x3e35e5['data']['authPageType'] == '2')) {
                                if (_0x4538fc) {
                                    _0x4538fc['parentNode']['removeChild'](_0x4538fc);
                                    _0x4538fc = null;
                                }
                                _0x5c5d35['parentNode']['removeChild'](_0x5c5d35);
                                keyBoard['closeKeyBoard']();
                            }
                            var _0x4ec9ca = {
                                'code': '103005',
                                'message': 'inner\x20error',
                                'msgId': _0x3e35e5['data']['traceId']
                            };
                            _0x2a341d(_0x4ec9ca);
                            _0x5e7475['removeEventListener']('message', _0xd6e2ec['init'], ![]);
                            _0xa083e8['optparams']['loading'] = !![];
                        }
                    });
                } catch (_0x5d8a9f) {
                    throw new Error(_0x5d8a9f);
                }
            },
            'endGetToken': function(_0x5cfb3b) {
                var _0x6ae72c = this;
                var _0x1e2113 = {
                    'code': '503',
                    'message': '获取token结束',
                    'msgId': _0xa083e8['optparams']['msgId']
                };
                if (_0xa083e8['optparams']['ifLoadIframe']) {
                    _0x24f766['parentNode']['removeChild'](_0x24f766);
                }
                _0x5e7475['removeEventListener']('message', _0x6ae72c['init'], ![]);
                _0x5cfb3b['error'](_0x1e2113);
                _0xa083e8['optparams']['loading'] = !![];
            }
        };
        var _0x4bfcd0 = {
            'showMark': function(_0x128471, _0x2fd701) {
                if (_0x2fd701) {
                    var _0x64a68c = !!_0x2fd701['agreeTextColour'] ? _0x2fd701['agreeTextColour'] : '#1B82EB'
                      , _0x3549f2 = !!_0x2fd701['configBusinessName'] ? _0x2fd701['configBusinessName'] : ''
                      , _0x5d4a90 = !!_0x2fd701['agreeButtonColour'] ? _0x2fd701['agreeButtonColour'] : '#1B82EB'
                      , _0x4d0c2c = !!_0x2fd701['agreeButtonText'] ? _0x2fd701['agreeButtonText'] : '本机号码登录'
                      , _0x1005bf = !!_0x2fd701['pageTitle'] ? _0x2fd701['pageTitle'] : '本机号码登录';
                    if (!!_0x2fd701['agreeCheckPic']) {
                        var _0x5a1bf6 = 'input[type=checkbox]:checked{outline:\x20none;appearance:\x20none;-webkit-appearance:\x20none;margin-right:\x206px;width:\x2012px;height:\x2012px;border:\x200;background:\x20url(' + _0x2fd701['agreeCheckPic'] + ')\x20no-repeat\x20center\x20top;background-size:\x20100%\x20100%;}'
                          , _0x4b8299 = document['getElementsByTagName']('head')[0x0]
                          , _0x51df60 = document['createElement']('style');
                        _0x51df60['type'] = 'text/css';
                        if (_0x51df60['styleSheet']) {
                            _0x51df60['styleSheet']['cssText'] = _0x5a1bf6;
                        } else {
                            _0x51df60['appendChild'](document['createTextNode'](_0x5a1bf6));
                        }
                        _0x4b8299['appendChild'](_0x51df60);
                    } else {
                        var _0x5a1bf6 = '.ydrz-layer-mark-wrap\x20.ydrz-layer-wrap\x20.ydrz-p\x20.ydrz-choose:checked::after{content:\x20\x22\x22;position:\x20absolute;left:\x200;top:\x201px;height:\x204px;width:\x208px;transform:\x20rotate(-45deg);border:\x201px\x20solid\x20' + _0x64a68c + ';border-top:\x20none;border-right:\x20none;}' + '.ydrz-layer-mark-wrap\x20.ydrz-layer-wrap\x20.ydrz-p\x20.ydrz-choose-level4:checked::after{content:\x20\x22\x22;position:\x20absolute;left:\x200;top:\x201px;height:\x204px;width:\x208px;transform:\x20rotate(-45deg);border:\x201px\x20solid\x20' + _0x64a68c + ';border-top:\x20none;border-right:\x20none;}'
                          , _0x4b8299 = document['getElementsByTagName']('head')[0x0]
                          , _0x51df60 = document['createElement']('style');
                        _0x51df60['type'] = 'text/css';
                        if (_0x51df60['styleSheet']) {
                            _0x51df60['styleSheet']['cssText'] = _0x5a1bf6;
                        } else {
                            _0x51df60['appendChild'](document['createTextNode'](_0x5a1bf6));
                        }
                        _0x4b8299['appendChild'](_0x51df60);
                    }
                }
                var _0xbbc4bd = this
                  ;
                _0x5c5d35 = document['createElement']('div');
                _0x5c5d35['classList']['add']('ydrz-layer-mark-wrap');
                _0x5c5d35['id'] = 'YDRZLayer';
                var _0x36dbf4 = [];
                if ('CT' == _0x128471['oper']) {
                    var _0x569974 = {
                        'agreeTxt': '《中国电信天翼账号服务条款》',
                        'agreeUrl': 'https://e.189.cn/sdk/agreement/detail.do?hidetop=true'
                    };
                    _0x36dbf4['push'](_0x569974);
                } else if ('CU' == _0x128471['oper']) {
                    var _0x569974 = {
                        'agreeTxt': '《中国联通认证服务协议》',
                        'agreeUrl': 'https://opencloud.wostore.cn/authz/resource/html/disclaimer.html?fromsdk=true'
                    };
                    _0x36dbf4['push'](_0x569974);
                } else {
                    var _0x569974 = {
                        'agreeTxt': '《中国移动认证服务协议》',
                        'agreeUrl': 'https://wap.cmpassport.com/resources/html/contract.html'
                    };
                    _0x36dbf4['push'](_0x569974);
                }
                if (_0x530764(_0xa083e8['optparams']['customerPrivacyConfig'])) {
                    _0x2fd701['customerPrivacyConfig'] = _0xa083e8['optparams']['customerPrivacyConfig'];
                    if (_0x2fd701 && _0x2fd701['customerPrivacyConfig'] && JSON['parse'](_0x2fd701['customerPrivacyConfig'])['length'] != 0x0) {
                        _0x2fd701['customerPrivacyConfig'] = JSON['parse'](_0x2fd701['customerPrivacyConfig']);
                        for (var _0x409c68 in _0x2fd701['customerPrivacyConfig']) {
                            var _0x569974 = {
                                'agreeTxt': _0x409c68,
                                'agreeUrl': _0x2fd701['customerPrivacyConfig'][_0x409c68]
                            };
                            _0x36dbf4['push'](_0x569974);
                        }
                    }
                }
                var _0x4e578f = '';
                for (var _0x38abf9 = 0x0; _0x38abf9 < _0x36dbf4['length']; _0x38abf9++) {
                    var _0x5623da = _0x36dbf4[_0x38abf9];
                    _0x4e578f += '<a\x20target=\x27_blank\x27\x20href=\x27' + _0x5623da['agreeUrl'] + '\x27\x20style=\x27' + _0x64a68c + '\x27>' + _0x5623da['agreeTxt'] + '</a>';
                }
                var _0x36b985 = {
                    '1': '<p\x20class=\x27ydrz-maskphone\x27>' + _0x128471['maskPhone'] + '</p>' + '<input\x20type=\x27submit\x27\x20\x20id=\x27YDRZ_Submitbtn\x27\x20class=\x27ydrz-submit-btn\x20ydrz-disabled\x27\x20style=\x27background:' + _0x5d4a90 + '\x27\x20value=\x27' + _0x4d0c2c + '\x27\x20/>' + '<p\x20class=\x27ydrz-p\x27><input\x20type=\x27checkbox\x27\x20id=\x27YDRZ_Checkbox_l1\x27\x20\x20name=\x27YDRZ_Choose\x27\x20class=\x27ydrz-choose\x27>我已阅读同意' + _0x4e578f + '并授权' + _0x3549f2 + '使用此号码</p>',
                    '4': '<p\x20class=\x27ydrz-auth-phone\x27>' + this['createMaskPhone'](_0x128471['maskPhone']) + '</p>' + '<p\x20class=\x27ydrz-p\x27><input\x20type=\x27checkbox\x27\x20id=\x27YDRZ_Checkbox_l4\x27\x20\x20name=\x27YDRZ_Choose\x27\x20class=\x27ydrz-choose-level4\x27>请补充完整号码同意' + _0x4e578f + '并授权' + _0x3549f2 + '使用此号码</p>'
                };
                var _0x3aaafb = _0xa083e8['optparams']['maskLength'];
                _0x5c5d35['innerHTML'] = '<div\x20id=\x27YDRZ_Modal\x27\x20class=\x27ydrz-layer-wrap\x27>' + '<div\x20class=\x27ydrz-close-btn\x27\x20id=\x27YDRZ_Closebtn\x27>' + '<img\x20src=\x27' + _0xa083e8['optparams']['resourceHref'] + 'closeIcon.png\x27\x20width=\x27100%\x27>' + '</div>' + '<p\x20class=\x27ydrz-title\x27>' + _0x1005bf + '</p>' + _0x36b985[_0x128471['authLevel']] + '<div\x20class=\x27ydrz-defined\x27></div>' + '</div>' + '</div>' + '<div\x20class=\x27ydrz-layer-mark\x27></div>';
                document['body']['appendChild'](_0x5c5d35);
                if ('ontouchmove'in document['documentElement']) {
                    document['getElementById']('YDRZLayer')['addEventListener']('touchmove', function(_0x581fc6) {
                        _0x581fc6['preventDefault']();
                    }, {
                        'passive': ![]
                    });
                }
                if (_0x2fd701 && _0x2fd701['customControlsConf'] && JSON['parse'](_0x2fd701['customControlsConf'])['length'] != 0x0) {
                    _0x2fd701['customControlsConf'] = JSON['parse'](_0x2fd701['customControlsConf']);
                    for (var _0x38abf9 = 0x0; _0x38abf9 < _0x2fd701['customControlsConf']['length']; _0x38abf9++) {
                        this['generateInput']('button', 'customInput' + _0x38abf9, 'customInput' + _0x38abf9, _0x2fd701['customControlsConf'][_0x38abf9]);
                    }
                }
                if (_0x128471['authLevel'] != '1') {
                    var _0x51d0db = '';
                    keyBoard['openKeyBoard'](_0x128471['authLevel'], '', '1', function(_0x5a4779) {
                        _0x51d0db = _0x5a4779['toString']();
                        if (_0x51d0db['length'] == _0x3aaafb) {
                            if (_0x128471['_USER_Checked']) {
                                _0xbbc4bd['showLoading'](_0x128471, _0x51d0db);
                            } else {
                                _0xbbc4bd['showToast']('请阅读服务协议', 0x5dc);
                            }
                        }
                        if (_0x51d0db['length'] <= _0x3aaafb) {
                            if (_0x51d0db['length'] === 0x0) {
                                document['getElementById']('inputVal1')['innerHTML'] = '';
                            } else {
                                document['getElementById']('inputVal' + _0x51d0db['length'])['innerHTML'] = _0x51d0db[_0x51d0db['length'] - 0x1];
                            }
                        }
                    }, function(_0x21364f) {
                        _0x51d0db = _0x21364f['toString']();
                        if (_0x51d0db['length'] < _0x3aaafb) {
                            document['getElementById']('inputVal' + (_0x51d0db['length'] + 0x1))['innerHTML'] = '';
                        }
                    });
                    var _0x37b5b2 = document['getElementById']('YDRZ_Checkbox_l4');
                    EventUtil['addHandler'](_0x37b5b2, 'click', function(_0x330b8c) {
                        _0x128471['_USER_Checked'] = _0x37b5b2['checked'];
                        if (_0x37b5b2['checked']) {
                            _0xbbc4bd['showLoading'](_0x128471, _0x51d0db);
                        }
                    });
                } else {
                    var _0x50d0a0 = document['getElementById']('YDRZ_Submitbtn')
                      , _0x37b5b2 = document['getElementById']('YDRZ_Checkbox_l1');
                    EventUtil['addHandler'](_0x50d0a0, 'click', function(_0x39219e) {
                        if (_0x37b5b2['checked']) {
                            _0xbbc4bd['showLoading'](_0x128471, maskVal);
                        }
                    });
                    EventUtil['addHandler'](_0x37b5b2, 'click', function(_0x1056ed) {
                        _0x128471['_USER_Checked'] = _0x37b5b2['checked'];
                        if (_0x37b5b2['checked']) {
                            _0x50d0a0['classList']['remove']('ydrz-disabled');
                        } else {
                            _0x50d0a0['classList']['add']('ydrz-disabled');
                        }
                    });
                }
                var _0x82fefb = document['getElementById']('YDRZ_Closebtn');
                EventUtil['addHandler'](_0x82fefb, 'click', function(_0x1b1c70) {
                    _0xbbc4bd['closeMark'](_0x5c5d35);
                    var _0x38ffb5 = {
                        'code': '501',
                        'msgId': _0xa083e8['optparams']['msgId'],
                        'message': '用户取消授权'
                    };
                    _0x128471['error'](_0x38ffb5);
                    _0xa083e8['optparams']['loading'] = !![];
                });
            },
            'closeMark': function(_0x3e83ba) {
                document['body']['removeChild'](_0x3e83ba);
                keyBoard['closeKeyBoard']();
            },
            'showLoading': function(_0x3fd3c6, _0x4462e0) {
                if (_0x3fd3c6['authLevel'] != '1' && !(_0x4462e0['length'] == 0x4 && _0x3fd3c6['_USER_Checked'])) {
                    return;
                }
                _0x4538fc = document['createElement']('div');
                _0x4538fc['classList']['add']('ydrz-loading-wrap');
                _0x4538fc['id'] = 'YDRZLoad';
                _0x4538fc['innerHTML'] = '<div\x20class=\x27ydrz-loading-div\x27>' + '<div\x20class=\x27ydrz-loader\x27></div>' + '<p\x20class=\x27ydrz-loading-p\x27>请稍候...</p>' + '</div>';
                document['body']['appendChild'](_0x4538fc);
                _0x56edeb['authGetToken']({
                    'data': {
                        'version': _0x3fd3c6['version'],
                        'maskPhone': _0x3fd3c6['maskPhone'],
                        'maskVal': _0x4462e0,
                        'appId': _0x3fd3c6['appId'],
                        'traceId': _0x3fd3c6['traceId'],
                        'accessToken': _0x3fd3c6['accessToken'],
                        'expandParams': _0x3fd3c6['expandParams'],
                        'isTest': _0x3fd3c6['isTest'],
                        'authPageType': '1'
                    },
                    'success': _0x3fd3c6['success'],
                    'error': _0x3fd3c6['error']
                });
            },
            'createMaskPhone': function(_0x50fd04) {
                var _0x240a1c = ''
                  , _0x504813 = 0x1;
    for (var _0x35b0ca = 0x0; _0x35b0ca < _0x50fd04['length']; _0x35b0ca++) {
                    if (_0x50fd04[_0x35b0ca] === '*') {
                        _0xa083e8['optparams']['maskLength']++;
                        var _0x224bc7 = '<span\x20class=\x27ydrz-input-val\x27\x20id=\x27inputVal' + _0x504813++ + '\x27></span>';
                        _0x240a1c += _0x224bc7;
                    } else {
                        _0x240a1c += _0x50fd04[_0x35b0ca];
                    }
                }
                return _0x240a1c;
            },
            'getPageConf': function(_0x14af3d) {
                var _0x6a8e8a = this;
                var _0x3ca370 = {};
                var _0x57e863 = {
                    'interfaceVersion': '1.0',
                    'traceId': _0xa083e8['optparams']['msgId'],
                    'appId': _0x14af3d['appId'],
                    'timestamp': _0x23d191(new Date(), 'yyyyMMddhhmmssSSS'),
                    'businessType': _0xa083e8['optparams']['businessType']
                };
                var _0x3b041f = _0x14af3d['isTest'] === '0' ? _0xa083e8['getPageOpt']['test01'] : _0xa083e8['getPageOpt']['pro'];
                try {
                    _0x495183['ajax']({
                        'request': {
                            'headers': _0x57e863,
                            'url': _0x3b041f,
                            'method': 'get',
                            'data': ''
                        },
                        'success': function(_0x521151) {
                            var _0x1d2919 = _0x521151['result'];
                            if (_0x1d2919['resultCode'] == '103000' && !!_0x1d2919['data']['pageOption']) {
                                _0x3ca370 = _0x1d2919['data']['pageOption'];
                                _0x6a8e8a['showMark'](_0x14af3d, _0x3ca370);
                            } else {
                                _0x6a8e8a['showMark'](_0x14af3d, _0x3ca370);
                            }
                        },
                        'error': function(_0x129627) {
                            _0x6a8e8a['showMark'](_0x14af3d, _0x3ca370);
                        }
                    });
                } catch (_0x2ddb4b) {
                    _0x6a8e8a['showMark'](_0x14af3d, _0x3ca370);
                }
            },
            'generateInput': function(_0x1a7848, _0x277f8a, _0x167519, _0x63ab2a) {
                var _0x141a82;
                if (document['all']) {
                    if (_0x167519 != null && _0x167519 != '') {
                        _0x141a82 = document['createElement']('<input\x20name=\x22' + _0x167519 + '\x22>');
                    } else {
                        _0x141a82 = document['createElement']('<input');
                    }
                } else {
                    _0x141a82 = document['createElement']('input');
                    if (_0x167519 != null && _0x167519 != '') {
                        _0x141a82['name'] = _0x167519;
                    }
                }
                if (_0x1a7848 == null || _0x1a7848 == '') {
                    _0x1a7848 = 'button';
                } else {
                    _0x141a82['type'] = _0x1a7848;
                }
                if (_0x277f8a != null && _0x277f8a != '') {
                    _0x141a82['id'] = _0x277f8a;
                }
                _0x141a82['value'] = _0x63ab2a['name'];
                if (_0x63ab2a['width'] && _0x63ab2a['width']['indexOf']('%') != -0x1) {
                    _0x141a82['style']['width'] = _0x63ab2a['width'];
                } else {
                    _0x141a82['style']['width'] = parseFloat(_0x63ab2a['width']) + 'px';
                }
                if (_0x63ab2a['height'] && _0x63ab2a['height']['indexOf']('%') != -0x1) {
                    _0x141a82['style']['height'] = _0x63ab2a['height'];
                    _0x141a82['style']['lineHeight'] = _0x63ab2a['height'];
                } else {
                    _0x141a82['style']['height'] = parseFloat(_0x63ab2a['height']) + 'px';
                    _0x141a82['style']['lineHeight'] = parseFloat(_0x63ab2a['height']) + 'px';
                }
                _0x141a82['style']['position'] = 'absolute';
                if (_0x63ab2a['high'] && _0x63ab2a['high']['indexOf']('%') != -0x1) {
                    _0x141a82['style']['top'] = _0x63ab2a['high'];
                } else if (_0x63ab2a['high'] && _0x63ab2a['high'] == 'center') {
                    _0x141a82['style']['top'] = '50%';
                    _0x141a82['style']['transform'] = 'translateY(-50%)';
                } else {
                    _0x141a82['style']['top'] = parseFloat(_0x63ab2a['high']) + 'px';
                }
                if (_0x63ab2a['left'] && _0x63ab2a['left']['indexOf']('%') != -0x1) {
                    _0x141a82['style']['left'] = _0x63ab2a['left'];
                } else if (_0x63ab2a['left'] && _0x63ab2a['left'] == 'center') {
                    _0x141a82['style']['left'] = '50%';
                    _0x141a82['style']['transform'] = _0x63ab2a['high'] && _0x63ab2a['high'] == 'center' ? 'translate(-50%,-50%)' : 'translateX(-50%)';
                } else {
                    _0x141a82['style']['left'] = parseFloat(_0x63ab2a['left']) + 'px';
                }
                _0x141a82['style']['fontSize'] = parseFloat(_0x63ab2a['font-size']) + 'px';
                _0x141a82['style']['backgroundColor'] = _0x63ab2a['background-color'] || 'transparent';
                _0x141a82['style']['borderRadius'] = parseFloat(_0x63ab2a['border-radius']) + 'px';
                _0x141a82['style']['color'] = _0x63ab2a['color'] || 'transparent';
                _0x141a82['style']['border'] = _0x63ab2a['border'] || '0';
                _0x141a82['style']['textDecoration'] = _0x63ab2a['text-decoration'];
                _0x141a82['style']['textAlign'] = _0x63ab2a['text-align'];
                if (_0x141a82['attachEvent']) {
                    _0x141a82['attachEvent']('onclick', function() {
                        window['parent']['location']['href'] = _0x63ab2a['url'];
                    });
                } else {
                    _0x141a82['addEventListener']('click', function() {
                        window['parent']['location']['href'] = _0x63ab2a['url'];
                    });
                }
                document['getElementsByClassName']('ydrz-defined')[0x0]['appendChild'](_0x141a82);
            },
            'showToast': function(_0x5a4f40, _0x40e6e6) {
                var _0x1fc8be = _0x40e6e6 || 0x7d0;
                var _0x5877c9 = document['createElement']('div');
                _0x5877c9['classList']['add']('ydrz-toast-wrap');
                _0x5877c9['id'] = 'YDRZToast';
                _0x5877c9['innerHTML'] = '<div\x20class=\x27ydrz-toast-div\x27>' + '<p\x20class=\x27ydrz-toast-p\x27>' + _0x5a4f40 + '</p>' + '</div>';
                document['body']['appendChild'](_0x5877c9);
                var _0x3f9cf5 = setTimeout(function() {
                    document['body']['removeChild'](_0x5877c9);
                    clearTimeout(_0x3f9cf5);
                }, _0x1fc8be);
            },
            'showErrorTips': function(_0x1676f6) {
                keyBoard['delInput'](function() {
                    var _0x342d16 = document['getElementsByClassName']('ydrz-input-val');
                    if (_0x342d16) {
                        for (var _0x44e620 = 0x0; _0x44e620 < _0x342d16['length']; _0x44e620++) {
                            _0x342d16[_0x44e620]['innerHTML'] = '';
                        }
                    }
                });
                if (document['getElementById']('YDRZErrorTips')) {
                    return;
                }
                var _0x28d4f8 = document['createElement']('div');
                _0x28d4f8['classList']['add']('ydrz-error-tip-wrap');
                _0x28d4f8['id'] = 'YDRZErrorTips';
                _0x28d4f8['innerHTML'] = '<p\x20class=\x27ydrz-error-tip\x27>' + _0x1676f6 + '</p>';
                var _0x2b16da = document['getElementsByClassName']('ydrz-auth-phone')[0x0];
                _0x2b16da['parentNode']['insertBefore'](_0x28d4f8, _0x2b16da['nextSibling']);
            }
        };
        var _0x3aa33a = {
            'initLayer': function(_0x46da13, _0x2be711) {
                var _0x5e5ddc = _0x2be711 && _0x2be711['layerStyle'] || {}
                  , _0x2622af = _0x2be711 && _0x2be711['maskStyle'] || {}
                  , _0x25892c = _0x2be711 && _0x2be711['phoneStyle'] || {}
                  , _0x5b40ae = _0x2be711 && _0x2be711['agreeStyle'] || {}
                  , _0x637a41 = _0x2be711 && _0x2be711['closeBtnStyle'] || {}
                  , _0x45133e = _0x2be711 && _0x2be711['errTipStyle'] || {}
                  , _0x58f647 = _0x2be711 && _0x2be711['customControlStyle'] || {}
                  , _0x3d00ac = _0x2be711 && _0x2be711['submitBtnStyle'] || {};
                this['_layer_style'] = {};
                this['_mask_style'] = {};
                this['_phone_style'] = {};
                this['_agree_style'] = {};
                this['_closebtn_style'] = {};
                this['_customControl_style'] = {};
                this['_submitbtn_style'] = {};
                this['_errtip_style'] = {};
                this['_token_data'] = {};
                this['_MASKVAL'] = '';
                this['agreementArr'] = [];
                var _0x3d6c0b = {
                    'agreeTxt': '《中国移动认证服务协议》',
                    'agreeUrl': 'https://wap.cmpassport.com/resources/html/contract.html'
                };
                this['agreementArr']['push'](_0x3d6c0b);
                this['_divElem'] = _0x46da13;
                this['_layer_style']['width'] = _0x5e5ddc['width'] || '80%';
                this['_layer_style']['height'] = _0x5e5ddc['height'] || '240px';
                this['_layer_style']['bgColor'] = _0x5e5ddc['bgColor'] || '#FFFFFF';
                this['_layer_style']['borderRadius'] = _0x5e5ddc['borderRadius'] || '8px';
                this['_layer_style']['cssStyle'] = 'width:' + this['_layer_style']['width'] + ';height:' + this['_layer_style']['height'] + ';background-color:' + this['_layer_style']['bgColor'] + ';border-radius:' + this['_layer_style']['borderRadius'];
                this['_mask_style']['ifShowMask'] = _0x2622af['ifShowMask'] || ![];
                this['_mask_style']['bgColor'] = _0x2622af['bgColor'] || '#000000';
                this['_mask_style']['opacity'] = _0x2622af['opacity'] || '0.6';
                this['_mask_style']['cssStyle'] = this['_mask_style']['ifShowMask'] ? 'background-color:' + this['_mask_style']['bgColor'] + ';opacity:' + this['_mask_style']['opacity'] : 'display:none;';
                this['_phone_style']['fontSize'] = _0x25892c['fontSize'] || '22px';
                this['_phone_style']['fontColor'] = _0x25892c['fontColor'] && _0x25892c['fontColor'] !== this['_layer_style']['bgColor'] ? _0x25892c['fontColor'] : '#333333';
                this['_phone_style']['high'] = _0x25892c['high'] && parseFloat(_0x25892c['high']) > 0x0 ? _0x25892c['high'] : '86px';
                this['_phone_style']['left'] = _0x25892c['left'] && parseFloat(_0x25892c['left']) > 0x0 ? _0x25892c['left'] : 'center';
                this['_phone_style']['bottom'] = _0x25892c['bottom'] || '27px';
                this['_phone_style']['cssStyle'] = 'font-size:' + this['_phone_style']['fontSize'] + ';color:' + this['_phone_style']['fontColor'] + ';left:' + this['_phone_style']['left'];
                this['_agree_style']['width'] = _0x5b40ae['width'] || '90%';
                this['_agree_style']['fontSize'] = _0x5b40ae['fontSize'] || '12px';
                this['_agree_style']['checkedImage'] = _0x5b40ae['checkedImage'] || '';
                this['_agree_style']['textalign'] = _0x5b40ae['textalign'] || 'center';
                this['_agree_style']['fontColor'] = _0x5b40ae['fontColor'] || '#999';
                this['_agree_style']['hrefColor'] = _0x5b40ae['hrefColor'] || '#1B82EB';
                this['_agree_style']['agreeArr'] = _0x5b40ae['agreeArr'] || [];
                this['_agree_style']['high'] = _0x5b40ae['high'] && parseFloat(_0x5b40ae['high']) > 0x0 ? _0x5b40ae['high'] : '';
                this['_agree_style']['left'] = _0x5b40ae['left'] && parseFloat(_0x5b40ae['left']) > 0x0 ? _0x5b40ae['left'] : 'center';
                this['_agree_style']['cssStyle_p'] = 'width:' + this['_agree_style']['width'] + ';font-size:' + this['_agree_style']['fontSize'] + ';text-align:' + this['_agree_style']['textalign'] + ';color:' + this['_agree_style']['fontColor'];
                this['_agree_style']['cssStyle_a'] = 'color:' + this['_agree_style']['hrefColor'];
                for (var _0x1799c3 = 0x0; _0x1799c3 < this['_agree_style']['agreeArr']['length']; _0x1799c3++) {
                    var _0x3d6c0b = {
                        'agreeTxt': this['_agree_style']['agreeArr'][_0x1799c3]['name'],
                        'agreeUrl': this['_agree_style']['agreeArr'][_0x1799c3]['url']
                    };
                    this['agreementArr']['push'](_0x3d6c0b);
                }
                this['_closebtn_style']['ifShowBtn'] = _0x637a41['ifShowBtn'] === ![] ? ![] : !![];
                this['_closebtn_style']['btnImage'] = _0x637a41['btnImage'] || 'https://www.cmpassport.com/h5/js/jssdk_auth/image/closeIcon.png';
                this['_closebtn_style']['top'] = _0x637a41['top'] || '12px';
                this['_closebtn_style']['right'] = _0x637a41['right'] || '12px';
                this['_closebtn_style']['width'] = _0x637a41['width'] || '16px';
                this['_closebtn_style']['height'] = _0x637a41['height'] || '16px';
                this['_closebtn_style']['cssStyle'] = this['_closebtn_style']['ifShowBtn'] ? 'position:absolute' + ';top:' + this['_closebtn_style']['top'] + ';right:' + this['_closebtn_style']['right'] + ';width:' + this['_closebtn_style']['width'] + ';height:' + this['_closebtn_style']['height'] : 'display:none;';
                this['_customControl_style']['ifShow'] = _0x58f647['ifShow'] || ![];
                this['_customControl_style'] = _0x58f647;
                this['_submitbtn_style']['name'] = _0x3d00ac['name'] || '确认授权登录';
                this['_submitbtn_style']['fontColor'] = _0x3d00ac['fontColor'] || '#FFFFFF';
                this['_submitbtn_style']['fontSize'] = _0x3d00ac['fontSize'] || '14px';
                this['_submitbtn_style']['textAlign'] = _0x3d00ac['textAlign'] || 'center';
                this['_submitbtn_style']['bgColor'] = _0x3d00ac['bgColor'] || '#1B82EB';
                this['_submitbtn_style']['width'] = _0x3d00ac['width'] || '90%';
                this['_submitbtn_style']['height'] = _0x3d00ac['height'] || '46px';
                this['_submitbtn_style']['high'] = _0x3d00ac['high'] || '120px';
                this['_submitbtn_style']['left'] = _0x3d00ac['left'] || 'center';
                this['_submitbtn_style']['borderRadius'] = _0x3d00ac['borderRadius'] || '8px';
                this['_submitbtn_style']['cssStyle'] = 'width:' + this['_submitbtn_style']['width'] + ';height:' + this['_submitbtn_style']['height'] + ';line-height:' + this['_submitbtn_style']['height'] + ';color:' + this['_submitbtn_style']['fontColor'] + ';font-size:' + this['_submitbtn_style']['fontSize'] + ';background-color:' + this['_submitbtn_style']['bgColor'] + ';text-align:' + this['_submitbtn_style']['textAlign'] + ';border-radius:' + this['_submitbtn_style']['borderRadius'] + ';top:' + this['_submitbtn_style']['high'];
                this['_errtip_style']['high'] = _0x45133e['high'] || 'center';
                this['_errtip_style']['left'] = _0x45133e['left'] || 'center';
                this['_errtip_style']['cssStyleTop'] = this['_errtip_style']['high'] == 'center' ? 'top:0;bottom:0;' : 'top:' + this['_errtip_style']['high'];
                this['_errtip_style']['cssStyleLeft'] = this['_errtip_style']['left'] == 'center' ? 'left:0;right:0;' : 'left:' + this['_errtip_style']['left'];
                this['_errtip_style']['cssStyle'] = this['_errtip_style']['cssStyleTop'] + ';' + this['_errtip_style']['cssStyleLeft'];
                _0xa083e8['optparams']['ifInitOptions'] = !![];
            },
            'initTokenData': function(_0x5d366a) {
                var _0x35292b = {
                    'version': _0x5d366a['version'],
                    'maskPhone': _0x5d366a['maskPhone'],
                    'maskVal': '',
                    'appId': _0x5d366a['appId'],
                    'traceId': _0x5d366a['traceId'],
                    'accessToken': _0x5d366a['accessToken'],
                    'expandParams': _0x5d366a['expandParams'],
                    'isTest': _0x5d366a['isTest'],
                    'authPageType': '1',
                    '_USER_Checked': ![],
                    'authLevel': _0x5d366a['authLevel']
                };
                this['_token_data'] = _0x35292b;
            },
            'showMarkTypeOne': function(_0x43b83f, _0x19fc48) {
                var _0x772364 = _0x19fc48 && _0x19fc48['configBusinessName'] ? _0x19fc48['configBusinessName'] : '';
                this['initTokenData'](_0x43b83f);
                if (!!this['_agree_style']['checkedImage']) {
                    var _0x26141f = '.ydrz-layer-mark-two-wrap\x20.ydrz-layer-wrap\x20.ydrz-p\x20.ydrz-choose-level1.imgCheck:checked{border:\x200!important;border-radius:0!important;outline:\x20none;appearance:\x20none;-webkit-appearance:\x20none;margin-right:\x206px;width:\x2012px;height:\x2012px;border:\x200;background:\x20url(' + this['_agree_style']['checkedImage'] + ')\x20no-repeat\x20center\x20top;background-size:\x20100%\x20100%;}' + '.ydrz-layer-mark-two-wrap\x20.ydrz-layer-wrap\x20.ydrz-p\x20.ydrz-choose-level4.imgCheck:checked{border:\x200!important;border-radius:0!important;outline:\x20none;appearance:\x20none;-webkit-appearance:\x20none;margin-right:\x206px;width:\x2012px;height:\x2012px;border:\x200;background:\x20url(' + this['_agree_style']['checkedImage'] + ')\x20no-repeat\x20center\x20top;background-size:\x20100%\x20100%;}'
                      , _0x5b649c = document['getElementsByTagName']('head')[0x0]
                      , _0x23a197 = document['createElement']('style');
                    _0x23a197['type'] = 'text/css';
                    if (_0x23a197['styleSheet']) {
                        _0x23a197['styleSheet']['cssText'] = _0x26141f;
                    } else {
                        _0x23a197['appendChild'](document['createTextNode'](_0x26141f));
                    }
                    _0x5b649c['appendChild'](_0x23a197);
                } else {
                    var _0x26141f = '.ydrz-layer-mark-two-wrap\x20.ydrz-layer-wrap\x20.ydrz-p\x20.ydrz-choose-level1:checked::after{content:\x20\x22\x22;position:\x20absolute;left:\x200;top:\x201px;height:\x204px;width:\x208px;transform:\x20rotate(-45deg);border:\x201px\x20solid\x20' + this['_agree_style']['hrefColor'] + ';border-top:\x20none;border-right:\x20none;}' + '.ydrz-layer-mark-two-wrap\x20.ydrz-layer-wrap\x20.ydrz-p\x20.ydrz-choose-level4:checked::after{content:\x20\x22\x22;position:\x20absolute;left:\x200;top:\x201px;height:\x204px;width:\x208px;transform:\x20rotate(-45deg);border:\x201px\x20solid\x20' + this['_agree_style']['hrefColor'] + ';border-top:\x20none;border-right:\x20none;}'
                      , _0x5b649c = document['getElementsByTagName']('head')[0x0]
                      , _0x23a197 = document['createElement']('style');
                    _0x23a197['type'] = 'text/css';
                    if (_0x23a197['styleSheet']) {
                        _0x23a197['styleSheet']['cssText'] = _0x26141f;
                    } else {
                        _0x23a197['appendChild'](document['createTextNode'](_0x26141f));
                    }
                    _0x5b649c['appendChild'](_0x23a197);
                }
                var _0x35e907 = this
                  ;
                _0x5c5d35 = document['createElement']('div');
                _0x5c5d35['classList']['add']('ydrz-layer-mark-two-wrap');
                _0x5c5d35['id'] = 'YDRZLayerTwo';
                if ('CT' == _0x43b83f['oper']) {
                    var _0x106c02 = {
                        'agreeTxt': '《中国电信天翼账号服务条款》',
                        'agreeUrl': 'https://e.189.cn/sdk/agreement/detail.do?hidetop=true'
                    };
                    this['agreementArr']['splice'](0x1, 0x0, _0x106c02);
                } else if ('CU' == _0x43b83f['oper']) {
                    var _0x106c02 = {
                        'agreeTxt': '《中国联通认证服务协议》',
                        'agreeUrl': 'https://opencloud.wostore.cn/authz/resource/html/disclaimer.html?fromsdk=true'
                    };
                    this['agreementArr']['splice'](0x1, 0x0, _0x106c02);
                }
                var _0x2b58d1 = '';
                for (var _0x3bd706 = 0x0; _0x3bd706 < this['agreementArr']['length']; _0x3bd706++) {
                    var _0x5afc45 = this['agreementArr'][_0x3bd706];
                    _0x2b58d1 += '<a\x20target=\x27_blank\x27\x20href=\x27' + _0x5afc45['agreeUrl'] + '\x27\x20style=\x27' + this['_agree_style']['cssStyle_a'] + '\x27>' + _0x5afc45['agreeTxt'] + '</a>';
                }
                var _0xe16489 = this['_agree_style']['checkedImage'] ? 'imgCheck' : '';
                var _0x58c509 = {
                    '1': '<p\x20class=\x27ydrz-maskphone\x27\x20id=\x27YDRZ_InputPhone_two\x27\x20style=\x27' + this['_phone_style']['cssStyle'] + '\x27>' + _0x43b83f['maskPhone'] + '</p>' + '<p\x20class=\x27ydrz-p\x27\x20id=\x27YDRZ_Agreement\x27\x20style=\x27' + this['_agree_style']['cssStyle_p'] + '\x27><input\x20type=\x27checkbox\x27\x20id=\x27YDRZ_Checkbox_l1_two\x27\x20\x20name=\x27YDRZ_Choose\x27\x20class=\x27ydrz-choose-level1\x20' + _0xe16489 + '\x27>我已阅读同意' + _0x2b58d1 + '并授权' + _0x772364 + '使用此号码</p>',
                    '4': '<p\x20class=\x27ydrz-auth-phone\x27\x20id=\x27YDRZ_InputPhone_two\x27\x20style=\x27' + this['_phone_style']['cssStyle'] + '\x27>' + this['createMaskPhone'](_0x43b83f['maskPhone']) + '</p>' + '<p\x20class=\x27ydrz-p\x27\x20id=\x27YDRZ_Agreement\x27\x20style=\x27' + this['_agree_style']['cssStyle_p'] + '\x27><input\x20type=\x27checkbox\x27\x20id=\x27YDRZ_Checkbox_l4_two\x27\x20\x20name=\x27YDRZ_Choose\x27\x20class=\x27ydrz-choose-level4\x20' + _0xe16489 + '\x27>请补充完整号码同意' + _0x2b58d1 + '并授权' + _0x772364 + '使用此号码</p>'
                };
                var _0x32c855 = _0xa083e8['optparams']['maskLength'];
                _0x5c5d35['innerHTML'] = '<div\x20id=\x27YDRZ_Modal_two\x27\x20class=\x27ydrz-layer-wrap\x27\x20style=\x27' + this['_layer_style']['cssStyle'] + '\x27>' + '<div\x20class=\x27ydrz-close-btn\x27\x20id=\x27YDRZ_Closebtn_two\x27\x20style=\x27' + this['_closebtn_style']['cssStyle'] + '\x27>' + '<img\x20src=\x27' + this['_closebtn_style']['btnImage'] + '\x27\x20width=\x27100%\x27>' + '</div>' + _0x58c509[_0x43b83f['authLevel']] + '<div\x20class=\x27ydrz-defined\x27></div>' + '</div>' + '</div>' + '<div\x20class=\x27ydrz-layer-mark\x27\x20style=\x27' + this['_mask_style']['cssStyle'] + '\x27></div>';
                document['getElementById'](this['_divElem'])['appendChild'](_0x5c5d35);
                if (document['getElementById'](_0x5c5d35['id'])) {
                    var _0x106c02 = {
                        'code': '103000',
                        'msgId': _0xa083e8['optparams']['msgId'],
                        'message': '弹窗加载成功'
                    };
                    _0x43b83f['success'](_0x106c02);
                    _0xa083e8['optparams']['loading'] = !![];
                } else {
                    var _0x106c02 = {
                        'code': '506',
                        'msgId': _0xa083e8['optparams']['msgId'],
                        'message': '弹窗加载失败',
                        'err': e['stack']
                    };
                    _0x43b83f['error'](_0x106c02);
                    _0xa083e8['optparams']['loading'] = !![];
                    return;
                }
                var _0x12df9c = document['getElementById']('YDRZ_Modal_two');
                var _0x33cf6d = document['getElementById']('YDRZ_Agreement');
                if (_0x33cf6d['offsetTop'] + _0x33cf6d['offsetHeight'] > _0x12df9c['offsetHeight']) {
                    _0x33cf6d['style']['top'] = _0x43b83f['authLevel'] == '4' ? '146px' : '168px';
                } else {
                    _0x33cf6d['style']['top'] = this['_agree_style']['high'] ? this['_agree_style']['high'] : _0x43b83f['authLevel'] == '4' ? '146px' : '168px';
                }
                if (_0x33cf6d['offsetLeft'] + _0x33cf6d['offsetWidth'] > _0x12df9c['offsetWidth']) {
                    this['_agree_style']['left'] = 'center';
                }
                if (this['_agree_style']['left'] == 'center') ; else {
                    _0x33cf6d['style']['left'] = this['_agree_style']['left'];
                }
                var _0x48b555 = document['getElementById']('YDRZ_InputPhone_two');
                if (_0x48b555['offsetTop'] + _0x48b555['offsetHeight'] > _0x12df9c['offsetHeight']) {
                    _0x48b555['style']['top'] = _0x43b83f['authLevel'] == '4' ? '86px' : '81px';
                } else {
                    _0x48b555['style']['top'] = this['_phone_style']['high'];
                }
                if (_0x48b555['offsetLeft'] + _0x48b555['offsetWidth'] > _0x12df9c['offsetWidth']) {
                    this['_phone_style']['left'] = 'center';
                }
                if (this['_phone_style']['left'] == 'center') {
                    _0x48b555['style']['left'] = (_0x12df9c['offsetWidth'] - _0x48b555['offsetWidth']) / 0x2 + 'px';
                } else {
                    _0x48b555['style']['left'] = this['_phone_style']['left'];
                }
                if ('ontouchmove'in document['documentElement']) {
                    document['getElementById']('YDRZLayerTwo')['addEventListener']('touchmove', function(_0x2290bc) {
                        _0x2290bc['preventDefault']();
                    }, {
                        'passive': ![]
                    });
                }
                if (this['_customControl_style']['ifShow']) {
                    var _0x3bd706 = 0x0;
                    this['generateInput']('button', 'customInput' + _0x3bd706, 'customInput' + _0x3bd706, this['_customControl_style']);
                }
                if (_0x43b83f['authLevel'] != '1') {
                    _0x35e907['_MASKVAL'] = '';
                    var _0x39ab44 = document['getElementById']('YDRZ_InputPhone_two');
                    EventUtil['addHandler'](_0x39ab44, 'click', function(_0x4ab5e3) {
                        _0x4ab5e3['stopPropagation']();
                        var _0x4c1f48 = document['documentElement']['clientHeight'] == 0x0 ? document['body']['clientHeight'] : document['documentElement']['clientHeight']
                          , _0x39d2da = _0x4ab5e3['clientY']
                          , _0x37c812 = _0x4c1f48 - _0x39d2da - 0x70;
                        var _0x272b46 = _0x65a829();
                        if (_0x37c812 < _0x4c1f48 * 0.3) {
                            window['scrollTo'](0x0, _0x272b46['top'] + _0x4c1f48 * 0.3 + 0x70);
                        }
                        var _0x11706e = document['getElementsByClassName']('qs-key-board-wrap')[0x0];
                        if (_0x11706e) ; else {
                            var _0x1cdbb2 = document['getElementsByTagName']('body')[0x0]['style']['paddingBottom'];
                            document['getElementsByTagName']('body')[0x0]['style']['paddingBottom'] = _0x1cdbb2 == '' ? _0x4c1f48 * 0.3 + 'px' : parseFloat(_0x1cdbb2) + _0x4c1f48 * 0.3 + 'px';
                        }
                        keyBoard['openKeyBoard'](_0x43b83f['authLevel'], _0x35e907['_MASKVAL'], _0x43b83f['authPageType'], function(_0x33ec3c) {
                            _0x35e907['_MASKVAL'] = _0x33ec3c['toString']();
                            if (_0x35e907['_MASKVAL']['length'] == _0x32c855) {
                                if (_0x35e907['_token_data']['_USER_Checked']) {
                                    var _0x3b4efc = {
                                        'code': '103000',
                                        'msgId': _0xa083e8['optparams']['msgId'],
                                        'message': '用户已输入中间四位号码并勾选协议'
                                    };
                                    _0xa083e8['optparams']['layerCallback'](_0x3b4efc);
                                } else {
                                    _0x35e907['showToast']('请阅读服务协议', 0x5dc);
                                }
                                _0x35e907['_token_data']['maskVal'] = _0x35e907['_MASKVAL'];
                            }
                            if (_0x35e907['_MASKVAL']['length'] <= _0x32c855) {
                                if (_0x35e907['_MASKVAL']['length'] === 0x0) {
                                    document['getElementById']('inputVal1')['innerHTML'] = '';
                                } else {
                                    document['getElementById']('inputVal' + _0x35e907['_MASKVAL']['length'])['innerHTML'] = _0x35e907['_MASKVAL'][_0x35e907['_MASKVAL']['length'] - 0x1];
                                }
                            }
                        }, function(_0x3ea554) {
                            _0x35e907['_MASKVAL'] = _0x3ea554['toString']();
                            _0x35e907['_token_data']['maskVal'] = _0x35e907['_MASKVAL'];
                            if (_0x35e907['_MASKVAL']['length'] < _0x32c855) {
                                document['getElementById']('inputVal' + (_0x35e907['_MASKVAL']['length'] + 0x1))['innerHTML'] = '';
                            }
                        });
                    });
                    var _0x903079 = document['getElementById']('YDRZ_Checkbox_l4_two');
                    EventUtil['addHandler'](_0x903079, 'click', function(_0x298269) {
                        _0x35e907['_token_data']['_USER_Checked'] = _0x903079['checked'];
                        if (_0x35e907['_token_data']['_USER_Checked'] && _0x35e907['_MASKVAL']['length'] == _0x32c855) {
                            var _0x3aa8b1 = {
                                'code': '103000',
                                'msgId': _0xa083e8['optparams']['msgId'],
                                'message': '用户已输入中间四位号码并勾选协议'
                            };
                            _0xa083e8['optparams']['layerCallback'](_0x3aa8b1);
                        }
                    });
                } else {
                    var _0x903079 = document['getElementById']('YDRZ_Checkbox_l1_two');
                    EventUtil['addHandler'](_0x903079, 'click', function(_0x69cc05) {
                        _0x35e907['_token_data']['_USER_Checked'] = _0x903079['checked'];
                    });
                }
                var _0x4cbda5 = document['getElementById']('YDRZ_Closebtn_two');
                EventUtil['addHandler'](_0x4cbda5, 'click', function(_0x4ed934) {
                    _0x35e907['closeMark'](_0x35e907['_divElem'], _0x5c5d35);
                    var _0x301252 = {
                        'code': '501',
                        'msgId': _0xa083e8['optparams']['msgId'],
                        'message': '用户取消授权'
                    };
                    _0x43b83f['error'](_0x301252);
                    _0xa083e8['optparams']['loading'] = !![];
                });
            },
            'showMarkTypeTwo': function(_0x3dd4c1, _0x2b6d1b) {
                var _0x36fabc = _0x2b6d1b && _0x2b6d1b['configBusinessName'] ? _0x2b6d1b['configBusinessName'] : '';
                if (!!this['_agree_style']['checkedImage']) {
                    var _0x2072e8 = '.ydrz-layer-mark-two-wrap\x20.ydrz-layer-wrap\x20.ydrz-p\x20.ydrz-choose-level1.imgCheck:checked{border:\x200!important;border-radius:0!important;outline:\x20none;appearance:\x20none;-webkit-appearance:\x20none;margin-right:\x206px;width:\x2012px;height:\x2012px;border:\x200;background:\x20url(' + this['_agree_style']['checkedImage'] + ')\x20no-repeat\x20center\x20top;background-size:\x20100%\x20100%;}' + '.ydrz-layer-mark-two-wrap\x20.ydrz-layer-wrap\x20.ydrz-p\x20.ydrz-choose-level4.imgCheck:checked{border:\x200!important;border-radius:0!important;outline:\x20none;appearance:\x20none;-webkit-appearance:\x20none;margin-right:\x206px;width:\x2012px;height:\x2012px;border:\x200;background:\x20url(' + this['_agree_style']['checkedImage'] + ')\x20no-repeat\x20center\x20top;background-size:\x20100%\x20100%;}'
                      , _0x3449b5 = document['getElementsByTagName']('head')[0x0]
                      , _0x285564 = document['createElement']('style');
                    _0x285564['type'] = 'text/css';
                    if (_0x285564['styleSheet']) {
                        _0x285564['styleSheet']['cssText'] = _0x2072e8;
                    } else {
                        _0x285564['appendChild'](document['createTextNode'](_0x2072e8));
                    }
                    _0x3449b5['appendChild'](_0x285564);
                } else {
                    var _0x2072e8 = '.ydrz-layer-mark-two-wrap\x20.ydrz-layer-wrap\x20.ydrz-p\x20.ydrz-choose-level1:checked::after{content:\x20\x22\x22;position:\x20absolute;left:\x200;top:\x201px;height:\x204px;width:\x208px;transform:\x20rotate(-45deg);border:\x201px\x20solid\x20' + this['_agree_style']['hrefColor'] + ';border-top:\x20none;border-right:\x20none;}' + '.ydrz-layer-mark-two-wrap\x20.ydrz-layer-wrap\x20.ydrz-p\x20.ydrz-choose-level4:checked::after{content:\x20\x22\x22;position:\x20absolute;left:\x200;top:\x201px;height:\x204px;width:\x208px;transform:\x20rotate(-45deg);border:\x201px\x20solid\x20' + this['_agree_style']['hrefColor'] + ';border-top:\x20none;border-right:\x20none;}'
                      , _0x3449b5 = document['getElementsByTagName']('head')[0x0]
                      , _0x285564 = document['createElement']('style');
                    _0x285564['type'] = 'text/css';
                    if (_0x285564['styleSheet']) {
                        _0x285564['styleSheet']['cssText'] = _0x2072e8;
                    } else {
                        _0x285564['appendChild'](document['createTextNode'](_0x2072e8));
                    }
                    _0x3449b5['appendChild'](_0x285564);
                }
                var _0x556865 = this
                  ;
                _0x5c5d35 = document['createElement']('div');
                _0x5c5d35['classList']['add']('ydrz-layer-mark-two-wrap');
                _0x5c5d35['classList']['add']('ydrz-extra-css');
                _0x5c5d35['id'] = 'YDRZLayerTwo';
                if ('CT' == _0x3dd4c1['oper']) {
                    var _0x1cb024 = {
                        'agreeTxt': '《中国电信天翼账号服务条款》',
                        'agreeUrl': 'https://e.189.cn/sdk/agreement/detail.do?hidetop=true'
                    };
                    this['agreementArr']['splice'](0x1, 0x0, _0x1cb024);
                } else if ('CU' == _0x3dd4c1['oper']) {
                    var _0x1cb024 = {
                        'agreeTxt': '《中国联通认证服务协议》',
                        'agreeUrl': 'https://opencloud.wostore.cn/authz/resource/html/disclaimer.html?fromsdk=true'
                    };
                    this['agreementArr']['splice'](0x1, 0x0, _0x1cb024);
                }
                var _0x1c6830 = '';
                for (var _0x2e0a10 = 0x0; _0x2e0a10 < this['agreementArr']['length']; _0x2e0a10++) {
                    var _0x47f032 = this['agreementArr'][_0x2e0a10];
                    _0x1c6830 += '<a\x20target=\x27_blank\x27\x20href=\x27' + _0x47f032['agreeUrl'] + '\x27\x20style=\x27' + this['_agree_style']['cssStyle_a'] + '\x27>' + _0x47f032['agreeTxt'] + '</a>';
                }
                var _0x44b75b = this['_agree_style']['checkedImage'] ? 'imgCheck' : '';
                var _0x4850dc = {
                    '1': '<p\x20class=\x27ydrz-maskphone\x27\x20id=\x27YDRZ_InputPhone_two\x27\x20style=\x27' + this['_phone_style']['cssStyle'] + '\x27>' + _0x3dd4c1['maskPhone'] + '</p>' + '<input\x20type=\x27submit\x27\x20\x20id=\x27YDRZ_Submitbtn_two\x27\x20class=\x27ydrz-submit-btn\x20ydrz-disabled\x27\x20style=\x27' + this['_submitbtn_style']['cssStyle'] + '\x27\x20value=\x27' + this['_submitbtn_style']['name'] + '\x27\x20/>' + '<p\x20class=\x27ydrz-p\x27\x20id=\x27YDRZ_Agreement\x27\x20style=\x27' + this['_agree_style']['cssStyle_p'] + '\x27><input\x20type=\x27checkbox\x27\x20id=\x27YDRZ_Checkbox_l1_two\x27\x20\x20name=\x27YDRZ_Choose\x27\x20class=\x27ydrz-choose-level1\x20' + _0x44b75b + '\x27>我已阅读同意' + _0x1c6830 + '并授权' + _0x36fabc + '使用此号码</p>',
                    '4': '<p\x20class=\x27ydrz-auth-phone\x27\x20id=\x27YDRZ_InputPhone_two\x27\x20style=\x27' + this['_phone_style']['cssStyle'] + '\x27>' + this['createMaskPhone'](_0x3dd4c1['maskPhone']) + '</p>' + '<p\x20class=\x27ydrz-p\x27\x20id=\x27YDRZ_Agreement\x27\x20style=\x27' + this['_agree_style']['cssStyle_p'] + '\x27><input\x20type=\x27checkbox\x27\x20id=\x27YDRZ_Checkbox_l4_two\x27\x20\x20name=\x27YDRZ_Choose\x27\x20class=\x27ydrz-choose-level4\x20' + _0x44b75b + '\x27>请补充完整号码同意' + _0x1c6830 + '并授权' + _0x36fabc + '使用此号码</p>'
                };
                var _0x3b5529 = _0xa083e8['optparams']['maskLength'];
                _0x5c5d35['innerHTML'] = '<div\x20id=\x27YDRZ_Modal_two\x27\x20class=\x27ydrz-layer-wrap\x27\x20style=\x27' + this['_layer_style']['cssStyle'] + '\x27>' + '<div\x20class=\x27ydrz-close-btn\x27\x20id=\x27YDRZ_Closebtn_two\x27\x20style=\x27' + this['_closebtn_style']['cssStyle'] + '\x27>' + '<img\x20src=\x27' + this['_closebtn_style']['btnImage'] + '\x27\x20width=\x27100%\x27>' + '</div>' + _0x4850dc[_0x3dd4c1['authLevel']] + '<div\x20class=\x27ydrz-defined\x27></div>' + '</div>' + '</div>' + '<div\x20class=\x27ydrz-layer-mark\x27\x20style=\x27' + this['_mask_style']['cssStyle'] + '\x27></div>';
                document['body']['appendChild'](_0x5c5d35);
                var _0x168dab = document['getElementById']('YDRZ_Modal_two');
                var _0x26eac5 = document['getElementById']('YDRZ_Agreement');
                if (_0x26eac5['offsetTop'] + _0x26eac5['offsetHeight'] > _0x168dab['offsetHeight']) {
                    _0x26eac5['style']['top'] = _0x3dd4c1['authLevel'] == '4' ? '146px' : '168px';
                } else {
                    _0x26eac5['style']['top'] = this['_agree_style']['high'] ? this['_agree_style']['high'] : _0x3dd4c1['authLevel'] == '4' ? '146px' : '168px';
                }
                if (_0x26eac5['offsetLeft'] + _0x26eac5['offsetWidth'] > _0x168dab['offsetWidth']) {
                    this['_agree_style']['left'] = 'center';
                }
                if (this['_agree_style']['left'] == 'center') ; else {
                    _0x26eac5['style']['left'] = this['_agree_style']['left'];
                }
                var _0x5e9d4e = document['getElementById']('YDRZ_InputPhone_two');
                if (_0x5e9d4e['offsetTop'] + _0x5e9d4e['offsetHeight'] > _0x168dab['offsetHeight']) {
                    _0x5e9d4e['style']['top'] = _0x3dd4c1['authLevel'] == '4' ? '86px' : '81px';
                } else {
                    _0x5e9d4e['style']['top'] = this['_phone_style']['high'];
                }
                if (_0x5e9d4e['offsetLeft'] + _0x5e9d4e['offsetWidth'] > _0x168dab['offsetWidth']) {
                    this['_phone_style']['left'] = 'center';
                }
                if (this['_phone_style']['left'] == 'center') {
                    _0x5e9d4e['style']['left'] = (_0x168dab['offsetWidth'] - _0x5e9d4e['offsetWidth']) / 0x2 + 'px';
                } else {
                    _0x5e9d4e['style']['left'] = this['_phone_style']['left'];
                }
                if ('ontouchmove'in document['documentElement']) {
                    document['getElementById']('YDRZLayerTwo')['addEventListener']('touchmove', function(_0x217284) {
                        _0x217284['preventDefault']();
                    }, {
                        'passive': ![]
                    });
                }
                if (this['_customControl_style']['ifShow']) {
                    var _0x2e0a10 = 0x0;
                    this['generateInput']('button', 'customInput' + _0x2e0a10, 'customInput' + _0x2e0a10, this['_customControl_style']);
                }
                if (_0x3dd4c1['authLevel'] != '1') {
                    var _0x5c29b5 = '';
                    keyBoard['openKeyBoard'](_0x3dd4c1['authLevel'], '', '1', function(_0x157071) {
                        _0x5c29b5 = _0x157071['toString']();
                        if (_0x5c29b5['length'] == _0x3b5529) {
                            if (_0x3dd4c1['_USER_Checked']) {
                                _0x4bfcd0['showLoading'](_0x3dd4c1, _0x5c29b5);
                            } else {
                                _0x556865['showToast']('请阅读服务协议', 0x5dc);
                            }
                        }
                        if (_0x5c29b5['length'] <= _0x3b5529) {
                            if (_0x5c29b5['length'] === 0x0) {
                                document['getElementById']('inputVal1')['innerHTML'] = '';
                            } else {
                                document['getElementById']('inputVal' + _0x5c29b5['length'])['innerHTML'] = _0x5c29b5[_0x5c29b5['length'] - 0x1];
                            }
                        }
                    }, function(_0x5388c1) {
                        _0x5c29b5 = _0x5388c1['toString']();
                        if (_0x5c29b5['length'] < _0x3b5529) {
                            document['getElementById']('inputVal' + (_0x5c29b5['length'] + 0x1))['innerHTML'] = '';
                        }
                    });
                    var _0x104a06 = document['getElementById']('YDRZ_Checkbox_l4_two');
                    EventUtil['addHandler'](_0x104a06, 'click', function(_0x1daa8b) {
                        _0x3dd4c1['_USER_Checked'] = _0x104a06['checked'];
                        if (_0x104a06['checked']) {
                            _0x4bfcd0['showLoading'](_0x3dd4c1, _0x5c29b5);
                        }
                    });
                } else {
                    var _0x53dae3 = document['getElementById']('YDRZ_Submitbtn_two')
                      , _0x104a06 = document['getElementById']('YDRZ_Checkbox_l1_two');
                    if (_0x53dae3['offsetTop'] + _0x53dae3['offsetHeight'] > _0x168dab['offsetHeight']) {
                        _0x53dae3['style']['top'] = '120px';
                    }
                    if (_0x53dae3['offsetLeft'] + _0x53dae3['offsetWidth'] > _0x168dab['offsetWidth']) {
                        this['_submitbtn_style']['left'] = 'center';
                    }
                    if (this['_submitbtn_style']['left'] == 'center') {
                        _0x53dae3['style']['left'] = '50%';
                        _0x53dae3['style']['transform'] = 'translate(-50%,0)';
                    } else {
                        _0x53dae3['style']['left'] = this['_submitbtn_style']['left'];
                    }
                    EventUtil['addHandler'](_0x53dae3, 'click', function(_0x4d9513) {
                        if (_0x104a06['checked']) {
                            _0x4bfcd0['showLoading'](_0x3dd4c1, maskVal);
                        }
                    });
                    EventUtil['addHandler'](_0x104a06, 'click', function(_0x5d4f4c) {
                        _0x3dd4c1['_USER_Checked'] = _0x104a06['checked'];
                        if (_0x104a06['checked']) {
                            _0x53dae3['classList']['remove']('ydrz-disabled');
                        } else {
                            _0x53dae3['classList']['add']('ydrz-disabled');
                        }
                    });
                }
                var _0xcf256f = document['getElementById']('YDRZ_Closebtn_two');
                EventUtil['addHandler'](_0xcf256f, 'click', function(_0x409982) {
                    _0x4bfcd0['closeMark'](_0x5c5d35);
                    keyBoard['closeKeyBoard']();
                    var _0x2d5f30 = {
                        'code': '501',
                        'msgId': _0xa083e8['optparams']['msgId'],
                        'message': '用户取消授权'
                    };
                    _0x3dd4c1['error'](_0x2d5f30);
                    _0xa083e8['optparams']['loading'] = !![];
                });
            },
            'closeMark': function(_0x20ac4b, _0x5a5f1e) {
                document['getElementById'](_0x20ac4b)['removeChild'](_0x5a5f1e);
            },
            'showLoading': function(_0x57b6b3, _0x292424) {
                var _0x10a660 = this;
                _0x57b6b3 = 'undefined' === typeof _0x57b6b3 ? function() {}
                : _0x57b6b3;
                _0x292424 = 'undefined' === typeof _0x292424 ? function() {}
                : _0x292424;
                if (this['_token_data']['authLevel'] != '1' && !(this['_token_data']['maskVal'] && this['_token_data']['maskVal']['length'] == 0x4)) {
                    this['showToast']('未补齐4位号码', 0x5dc);
                    var _0x40ad93 = {
                        'code': '507',
                        'msgId': _0xa083e8['optparams']['msgId'],
                        'message': '用户未补齐4位号码'
                    };
                    _0x292424(_0x40ad93);
                    return;
                }
                if (!this['_token_data']['_USER_Checked']) {
                    this['showToast']('未勾选协议', 0x5dc);
                    var _0x40ad93 = {
                        'code': '508',
                        'msgId': _0xa083e8['optparams']['msgId'],
                        'message': '用户未勾选协议'
                    };
                    _0x292424(_0x40ad93);
                    return;
                }
                _0x56edeb['authGetToken']({
                    'data': {
                        'version': _0x10a660['_token_data']['version'],
                        'maskPhone': _0x10a660['_token_data']['maskPhone'],
                        'maskVal': _0x10a660['_token_data']['maskVal'],
                        'appId': _0x10a660['_token_data']['appId'],
                        'traceId': _0x10a660['_token_data']['traceId'],
                        'accessToken': _0x10a660['_token_data']['accessToken'],
                        'expandParams': _0x10a660['_token_data']['expandParams'],
                        'isTest': _0x10a660['_token_data']['isTest'],
                        'authPageType': '2'
                    },
                    'success': _0x57b6b3,
                    'error': _0x292424
                });
            },
            'createMaskPhone': function(_0x413083) {
                var _0x2a566e = ''
                  , _0x351ffe = 0x1;
    for (var _0x599722 = 0x0; _0x599722 < _0x413083['length']; _0x599722++) {
                    if (_0x413083[_0x599722] === '*') {
                        _0xa083e8['optparams']['maskLength']++;
                        var _0xf38bb1 = '<span\x20class=\x27ydrz-input-val\x27\x20id=\x27inputVal' + _0x351ffe++ + '\x27></span>';
                        _0x2a566e += _0xf38bb1;
                    } else {
                        _0x2a566e += _0x413083[_0x599722];
                    }
                }
                return _0x2a566e;
            },
            'getPageConf': function(_0x4605f7) {
                var _0xb5d9da = document['getElementById']('ydrzCustomControls');
                if (!_0xb5d9da && !this['_mask_style']['ifShowMask']) {
                    var _0x3c53a7 = {
                        'code': '506',
                        'msgId': _0xa083e8['optparams']['msgId'],
                        'message': '弹窗加载失败'
                    };
                    _0x4605f7['error'](_0x3c53a7);
                    _0xa083e8['optparams']['loading'] = !![];
                    return;
                }
                if (_0xb5d9da && _0xb5d9da['childNodes']['length'] > 0x0) {
                    return;
                }
                if (!_0xa083e8['optparams']['ifInitOptions']) {
                    var _0x3c53a7 = {
                        'code': '505',
                        'msgId': _0xa083e8['optparams']['msgId'],
                        'message': '未初始化弹窗配置项'
                    };
                    _0x4605f7['error'](_0x3c53a7);
                    _0xa083e8['optparams']['loading'] = !![];
                    return;
                }
                var _0xf3a23e = this;
                var _0x2fe3be = {};
                var _0x49122b = {
                    'interfaceVersion': '1.0',
                    'traceId': _0xa083e8['optparams']['msgId'],
                    'appId': _0x4605f7['appId'],
                    'timestamp': _0x23d191(new Date(), 'yyyyMMddhhmmssSSS'),
                    'businessType': _0xa083e8['optparams']['businessType']
                };
                var _0x27c32a = _0x4605f7['isTest'] === '0' ? _0xa083e8['getPageOpt']['test01'] : _0xa083e8['getPageOpt']['pro'];
                try {
                    _0x495183['ajax']({
                        'request': {
                            'headers': _0x49122b,
                            'url': _0x27c32a,
                            'method': 'get',
                            'data': ''
                        },
                        'success': function(_0x456195) {
                            var _0xc58a2d = _0x456195['result'];
                            if (_0xc58a2d['resultCode'] == '103000' && !!_0xc58a2d['data']['pageOption']) {
                                _0x2fe3be = _0xc58a2d['data']['pageOption'];
                                try {
                                    if (_0xf3a23e['_mask_style']['ifShowMask']) {
                                        _0xf3a23e['showMarkTypeTwo'](_0x4605f7, _0x2fe3be);
                                    } else {
                                        _0xf3a23e['showMarkTypeOne'](_0x4605f7, _0x2fe3be);
                                    }
                                } catch (_0x7afa0d) {
                                    var _0x51b384 = {
                                        'code': '506',
                                        'msgId': _0xa083e8['optparams']['msgId'],
                                        'message': '弹窗加载失败',
                                        'err': _0x7afa0d['stack']
                                    };
                                    _0x4605f7['error'](_0x51b384);
                                    _0xa083e8['optparams']['loading'] = !![];
                                    return;
                                }
                            } else {
                                try {
                                    if (_0xf3a23e['_mask_style']['ifShowMask']) {
                                        _0xf3a23e['showMarkTypeTwo'](_0x4605f7, _0x2fe3be);
                                    } else {
                                        _0xf3a23e['showMarkTypeOne'](_0x4605f7, _0x2fe3be);
                                    }
                                } catch (_0x11d26b) {
                                    var _0x51b384 = {
                                        'code': '506',
                                        'msgId': _0xa083e8['optparams']['msgId'],
                                        'message': '弹窗加载失败',
                                        'err': _0x11d26b['stack']
                                    };
                                    _0x4605f7['error'](_0x51b384);
                                    _0xa083e8['optparams']['loading'] = !![];
                                    return;
                                }
                            }
                        },
                        'error': function(_0x525291) {
                            try {
                                if (_0xf3a23e['_mask_style']['ifShowMask']) {
                                    _0xf3a23e['showMarkTypeTwo'](_0x4605f7, _0x2fe3be);
                                } else {
                                    _0xf3a23e['showMarkTypeOne'](_0x4605f7, _0x2fe3be);
                                }
                            } catch (_0x4dba3e) {
                                console['log'](_0x4dba3e);
                                var _0x9347e = {
                                    'code': '506',
                                    'msgId': _0xa083e8['optparams']['msgId'],
                                    'message': '弹窗加载失败',
                                    'err': _0x4dba3e['stack']
                                };
                                _0x4605f7['error'](_0x9347e);
                                _0xa083e8['optparams']['loading'] = !![];
                                return;
                            }
                        }
                    });
                } catch (_0x25bebf) {
                    try {
                        if (_0xf3a23e['_mask_style']['ifShowMask']) {
                            _0xf3a23e['showMarkTypeTwo'](_0x4605f7, _0x2fe3be);
                        } else {
                            _0xf3a23e['showMarkTypeOne'](_0x4605f7, _0x2fe3be);
                        }
                    } catch (_0xd7f51c) {
                        var _0x3c53a7 = {
                            'code': '506',
                            'msgId': _0xa083e8['optparams']['msgId'],
                            'message': '弹窗加载失败',
                            'err': _0xd7f51c['stack']
                        };
                        _0x4605f7['error'](_0x3c53a7);
                        _0xa083e8['optparams']['loading'] = !![];
                        return;
                    }
                }
            },
            'generateInput': function(_0x152f64, _0x320b59, _0x4610e0, _0xc53859) {
                var _0x3b6dc8;
                if (document['all']) {
                    if (_0x4610e0 != null && _0x4610e0 != '') {
                        _0x3b6dc8 = document['createElement']('<input\x20name=\x22' + _0x4610e0 + '\x22>');
                    } else {
                        _0x3b6dc8 = document['createElement']('<input');
                    }
                } else {
                    _0x3b6dc8 = document['createElement']('input');
                    if (_0x4610e0 != null && _0x4610e0 != '') {
                        _0x3b6dc8['name'] = _0x4610e0;
                    }
                }
                if (_0x152f64 == null || _0x152f64 == '') {
                    _0x152f64 = 'button';
                } else {
                    _0x3b6dc8['type'] = _0x152f64;
                }
                if (_0x320b59 != null && _0x320b59 != '') {
                    _0x3b6dc8['id'] = _0x320b59;
                }
                _0x3b6dc8['value'] = _0xc53859['name'];
                if (_0xc53859['width'] && _0xc53859['width']['indexOf']('%') != -0x1) {
                    _0x3b6dc8['style']['width'] = _0xc53859['width'];
                } else {
                    _0x3b6dc8['style']['width'] = parseFloat(_0xc53859['width']) + 'px';
                }
                if (_0xc53859['height'] && _0xc53859['height']['indexOf']('%') != -0x1) {
                    _0x3b6dc8['style']['height'] = _0xc53859['height'];
                    _0x3b6dc8['style']['lineHeight'] = _0xc53859['height'];
                } else {
                    _0x3b6dc8['style']['height'] = parseFloat(_0xc53859['height']) + 'px';
                    _0x3b6dc8['style']['lineHeight'] = parseFloat(_0xc53859['height']) + 'px';
                }
                _0x3b6dc8['style']['position'] = 'absolute';
                if (_0xc53859['high'] && _0xc53859['high']['indexOf']('%') != -0x1) {
                    _0x3b6dc8['style']['top'] = _0xc53859['high'];
                } else if (_0xc53859['high'] && _0xc53859['high'] == 'center') {
                    _0x3b6dc8['style']['top'] = '50%';
                    _0x3b6dc8['style']['transform'] = 'translateY(-50%)';
                } else {
                    _0x3b6dc8['style']['top'] = parseFloat(_0xc53859['high']) + 'px';
                }
                if (_0xc53859['left'] && _0xc53859['left']['indexOf']('%') != -0x1) {
                    _0x3b6dc8['style']['left'] = _0xc53859['left'];
                } else if (_0xc53859['left'] && _0xc53859['left'] == 'center') {
                    _0x3b6dc8['style']['left'] = '50%';
                    _0x3b6dc8['style']['transform'] = _0xc53859['high'] && _0xc53859['high'] == 'center' ? 'translate(-50%,-50%)' : 'translateX(-50%)';
                } else {
                    _0x3b6dc8['style']['left'] = parseFloat(_0xc53859['left']) + 'px';
                }
                _0x3b6dc8['style']['fontSize'] = parseFloat(_0xc53859['fontSize']) + 'px';
                _0x3b6dc8['style']['backgroundColor'] = _0xc53859['bgColor'] || 'transparent';
                _0x3b6dc8['style']['borderRadius'] = parseFloat(_0xc53859['borderRadius']) + 'px';
                _0x3b6dc8['style']['border'] = _0xc53859['border'];
                _0x3b6dc8['style']['color'] = _0xc53859['fontColor'] || 'transparent';
                _0x3b6dc8['style']['textDecoration'] = _0xc53859['textDecoration'];
                _0x3b6dc8['style']['textAlign'] = _0xc53859['textAlign'];
                if (_0x3b6dc8['attachEvent']) {
                    _0x3b6dc8['attachEvent']('onclick', function() {
                        window['parent']['location']['href'] = _0xc53859['url'];
                    });
                } else {
                    _0x3b6dc8['addEventListener']('click', function() {
                        window['parent']['location']['href'] = _0xc53859['url'];
                    });
                }
                document['getElementsByClassName']('ydrz-defined')[0x0]['appendChild'](_0x3b6dc8);
            },
            'showToast': function(_0x4aebc9, _0x1d292a) {
                var _0x3aca5e = _0x1d292a || 0x7d0;
                var _0x4d3bd4 = document['createElement']('div');
                _0x4d3bd4['classList']['add']('ydrz-toast-wrap');
                _0x4d3bd4['id'] = 'YDRZToast';
                _0x4d3bd4['innerHTML'] = '<div\x20class=\x27ydrz-toast-div\x27>' + '<p\x20class=\x27ydrz-toast-p\x27>' + _0x4aebc9 + '</p>' + '</div>';
                document['body']['appendChild'](_0x4d3bd4);
                var _0xee647b = setTimeout(function() {
                    document['body']['removeChild'](_0x4d3bd4);
                    clearTimeout(_0xee647b);
                }, _0x3aca5e);
            },
            'closeKeyBoard': function() {
                keyBoard['closeKeyBoard'](!![]);
            },
            'showErrorTips': function(_0x58c0e6, _0x53c1fa) {
                var _0x432823 = _0x53c1fa || 0x7d0
                  , _0x2df1c9 = this;
                keyBoard['delInput'](function() {
                    var _0x51bc70 = document['getElementsByClassName']('ydrz-input-val');
                    if (_0x51bc70) {
                        for (var _0x8f34c2 = 0x0; _0x8f34c2 < _0x51bc70['length']; _0x8f34c2++) {
                            _0x51bc70[_0x8f34c2]['innerHTML'] = '';
                        }
                    }
                    _0x2df1c9['_MASKVAL'] = '';
                });
                if (document['getElementById']('YDRZErrorTips')) {
                    return;
                }
                var _0x1fad2f = document['createElement']('div');
                _0x1fad2f['classList']['add']('ydrz-error-tip2-wrap');
                _0x1fad2f['id'] = 'YDRZErrorTips';
                _0x1fad2f['innerHTML'] = '<div\x20class=\x27ydrz-toast-div2\x27>' + '<p\x20class=\x27ydrz-toast-p\x27\x20style=\x27' + this['_errtip_style']['cssStyle'] + '\x27>' + _0x58c0e6 + '</p>' + '</div>';
                document['body']['appendChild'](_0x1fad2f);
                var _0x58b11f = setTimeout(function() {
                    document['body']['removeChild'](_0x1fad2f);
                    clearTimeout(_0x58b11f);
                }, _0x432823);
            }
        };
        var _0x28fa04 = {
            'getLog': function() {
                var _0x23a541 = '2.0';
                var _0x3c3ea2 = _0xa083e8['jssdkLog']['appid'];
                _0xa083e8['jssdkLog']['operType'] = 'onekeylogin';
                _0xa083e8['jssdkLog']['version'] = '2';
                var _0x6a2a09 = _0x23a541 + _0x3c3ea2 + _0xa083e8['optparams']['timestamp'] + _0xa083e8['optparams']['msgId'] + '@Fdiwmxy7CBDDQNUI';
                var _0x336b40 = hex_md5(_0x6a2a09);
                var _0x29114e = {
                    'header': {
                        'sign': _0x336b40,
                        'msgid': _0xa083e8['optparams']['msgId'],
                        'version': _0x23a541,
                        'appid': _0x3c3ea2,
                        'systemtime': _0xa083e8['optparams']['timestamp'],
                        'operType': 'onekeylogin'
                    },
                    'body': {
                        'log': _0xa083e8['jssdkLog']
                    }
                };
                var _0x524fa6 = _0xa083e8['logReport']['pro'];
                var _0x3f4888;
                if (window['XMLHttpRequest']) {
                    _0x3f4888 = new XMLHttpRequest();
                } else {
                    _0x3f4888 = new ActiveXObject('Microsoft.XMLHTTP');
                }
    _0x3f4888['open']('post', _0x524fa6, !![]);
                _0x3f4888['send'](JSON['stringify'](_0x29114e));
            }
        };
        _0x5e7475['YDRZAuthLogin'] = {
            'getConnection': function(_0x50a5ad) {
                var _0xde40b5 = _0x56edeb['getConnection'](_0x50a5ad);
                return _0xde40b5;
            },
            'getTokenInfo': function(_0x59394d) {
                _0xa083e8['optparams']['ifStopGetToken'] = !![];
                _0x56edeb['getTokenInfo'](_0x59394d);
            },
            'authGetToken': function(_0x6233e3) {
                _0x56edeb['authGetToken'](_0x6233e3);
            },
            'endGetToken': function() {
                _0xa083e8['optparams']['ifStopGetToken'] = ![];
            },
            'CustomControlsInit': function(_0x464e4e, _0x364b84) {
                _0x3aa33a['initLayer'](_0x464e4e, _0x364b84);
            },
            'authGetTokenByLayer': function(_0x1441f4, _0x2c90de) {
                _0x3aa33a['showLoading'](_0x1441f4, _0x2c90de);
            },
            'authPageInit': function(_0x118a9a) {
                _0xa083e8['authPageOpt'] = _0x118a9a;
            }
        };
    }(window));

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
        appId: '300012093093',
        appKey: 'CC763B9A69570AA467F572F09B1B09A4',
        version: '2.0',
        timestamp: dateFormat(new Date(), 'yyyyMMddhhmmssSSS'),
        traceId: '@shumei',
        businessType: 8,
        openType: '1',
    };
    ({
        appId: '300012093093',
        appKey: 'CC763B9A69570AA467F572F09B1B09A4',
        version: '1.0',
        timestamp: dateFormat(new Date(), 'yyyyMMddhhmmssSSS'),
        traceId: '@shumei',
        businessType: '5',
        openType: '1',
    });

    var WIN$1 = window;
    var getTokenInfo = function (params) {
        var str = authConfig.appId + authConfig.businessType + authConfig.traceId + authConfig.timestamp + authConfig.traceId + authConfig.version + authConfig.appKey;
        params.data = __assign(__assign(__assign({}, params.data), authConfig), { sign: md5(str) });
        console.log('params :>> ', params);
        return WIN$1.YDRZAuthLogin.getTokenInfo(params);
    };
    var getConnection = function (params) {
        return WIN$1.YDRZAuthLogin.getConnection(params);
    };
    var authPageInit = function (params) {
        console.log('params: ', params);
        return WIN$1.YDRZAuthLogin.authPageInit(params);
    };

    var WIN = window;
    var SMRZ = (function () {
        function SMRZ() {
        }
        SMRZ.prototype.getTokenInfo = function (params) {
            return getTokenInfo(params);
        };
        SMRZ.prototype.getConnection = function (params) {
            return getConnection(params);
        };
        SMRZ.prototype.authPageInit = function (options) {
            console.log('options: ', options);
            return authPageInit(options);
        };
        return SMRZ;
    }());
    WIN.SMAuthLogin = new SMRZ();

}));

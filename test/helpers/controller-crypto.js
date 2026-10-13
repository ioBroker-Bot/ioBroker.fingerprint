'use strict';

/**
 * Copy of `encrypt` / `decrypt` (and the legacy XOR variants) of the js-controller, 1:1 from
 * `@iobroker/js-controller-common-db` 7.2.2, `build/cjs/lib/common/tools.js`. The original
 * module cannot be loaded in unit tests (it needs an installed js-controller), and the tests of
 * `lib/secrets.js` must run against exactly the behaviour of the controller.
 */

const crypto = require('node:crypto');

function encryptLegacy(key, value) {
    let result = '';
    for (let i = 0; i < value.length; i++) {
        result += String.fromCharCode(key[i % key.length].charCodeAt(0) ^ value.charCodeAt(i));
    }
    return result;
}

function decryptLegacy(key, value) {
    let result = '';
    for (let i = 0; i < value.length; i++) {
        result += String.fromCharCode(key[i % key.length].charCodeAt(0) ^ value.charCodeAt(i));
    }
    return result;
}

function encrypt(key, value) {
    if (!/^[0-9a-f]{48}$/.test(key)) {
        return encryptLegacy(key, value);
    }
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-192-cbc', Buffer.from(key, 'hex'), iv);
    const encrypted = Buffer.concat([cipher.update(value), cipher.final()]);
    return `$/aes-192-cbc:${iv.toString('hex')}:${encrypted.toString('hex')}`;
}

function decrypt(key, value) {
    if (!value.startsWith(`$/aes-192-cbc:`) || !/^[0-9a-f]{48}$/.test(key)) {
        return decryptLegacy(key, value);
    }
    const textParts = value.split(':', 3);
    const iv = Buffer.from(textParts[1], 'hex');
    const encryptedText = Buffer.from(textParts[2], 'hex');
    const decipher = crypto.createDecipheriv('aes-192-cbc', Buffer.from(key, 'hex'), iv);
    const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    return decrypted.toString();
}

module.exports = { encrypt, decrypt };

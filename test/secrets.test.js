'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
    normalizeSecrets,
    migrateSecrets,
    needsMigration,
    isBrokenSecret,
    AES_PREFIX,
    SECRET_ATTRS,
} = require('../lib/secrets');
const controller = require('./helpers/controller-crypto');

/**
 * Run `normalizeSecrets` with a collecting logger
 *
 * @param {object} config - native configuration (modified in place)
 * @param {(attr: string) => Promise<string>} [decrypt] - optional decrypt implementation
 * @returns {Promise<object>} config and collected log entries
 */
async function normalize(config, decrypt) {
    const logs = { info: [], warn: [], error: [] };
    const logger = {
        info: msg => logs.info.push(msg),
        warn: msg => logs.warn.push(msg),
        error: msg => logs.error.push(msg),
    };
    await normalizeSecrets(config, logger, decrypt);
    return { config, logs };
}

const XOR_GARBAGE = '7\u001e6\u001eT_\t\u0016\u0004KD\u001d%=)';

describe('lib/secrets', () => {
    describe('isBrokenSecret', () => {
        it('accepts printable secrets', () => {
            assert.equal(isBrokenSecret('abc123:/+='), false);
        });

        it('detects control characters', () => {
            assert.equal(isBrokenSecret(XOR_GARBAGE), true);
            assert.equal(isBrokenSecret('abc\u0000def'), true);
        });
    });

    describe('normalizeSecrets', () => {
        it('keeps plain text values untouched', async () => {
            const { config, logs } = await normalize({ adminPassword: 'secret', webhookToken: 'abcdef0123456789' });
            assert.equal(config.adminPassword, 'secret');
            assert.equal(config.webhookToken, 'abcdef0123456789');
            assert.equal(logs.info.length + logs.warn.length + logs.error.length, 0);
        });

        it('ignores missing and empty values', async () => {
            const { config, logs } = await normalize({ adminPassword: '', webhookToken: undefined });
            assert.equal(config.adminPassword, '');
            assert.equal(config.webhookToken, undefined);
            assert.equal(logs.warn.length, 0);
        });

        it('decrypts values stored in the $/aes-192-cbc: format', async () => {
            const { config, logs } = await normalize(
                { webhookToken: '$/aes-192-cbc:abcd:1234' },
                async () => 'plainToken',
            );
            assert.equal(config.webhookToken, 'plainToken');
            assert.equal(logs.info.length, 1);
            assert.match(logs.info[0], /decrypted webhookToken/);
        });

        it('keeps an encrypted value when no decrypt function is available', async () => {
            const { config } = await normalize({ webhookToken: '$/aes-192-cbc:abcd:1234' });
            assert.equal(config.webhookToken, '$/aes-192-cbc:abcd:1234');
        });

        it('clears a value when decryption fails', async () => {
            const { config, logs } = await normalize({ adminPassword: '$/aes-192-cbc:abcd:1234' }, async () => {
                throw new Error('bad secret');
            });
            assert.equal(config.adminPassword, '');
            assert.equal(logs.warn.length, 1);
            assert.match(logs.warn[0], /Could not decrypt the stored adminPassword/);
        });

        it('regenerates a broken webhook token', async () => {
            const { config, logs } = await normalize({ webhookToken: XOR_GARBAGE });
            assert.equal(config.webhookToken, '');
            assert.equal(logs.warn.length, 1);
            assert.match(logs.warn[0], /webhook token was unreadable/);
        });

        it('reports a broken password', async () => {
            const { config, logs } = await normalize({ adminPassword: XOR_GARBAGE });
            assert.equal(config.adminPassword, '');
            assert.equal(logs.error.length, 1);
            assert.match(logs.error[0], /stored adminPassword is unreadable/);
        });
    });

    describe('migrateSecrets', () => {
        const MODERN_SECRET = crypto.randomBytes(24).toString('hex');
        const LEGACY_SECRET = 'Zgfr56gFe87jJOM';
        const TOKEN = 'a3f09c1e7b2d4c5f8e6a9b0c1d2e3f405162738495a6b7c8';

        /**
         * What the js-controller does before the adapter starts: every `encryptedNative`
         * attribute is run through `decrypt()`.
         *
         * @param {object} native - stored native config
         * @param {string} secret - system secret
         * @returns {object} config as the adapter sees it
         */
        function controllerConfig(native, secret) {
            const config = { ...native };
            for (const attr of SECRET_ATTRS) {
                if (typeof config[attr] === 'string' && config[attr] !== '') {
                    config[attr] = controller.decrypt(secret, config[attr]);
                }
            }
            return config;
        }

        /**
         * Fake adapter that stores the instance object in memory
         *
         * @param {object} native - stored native config
         * @param {string} secret - system secret
         * @param {object} [opts] - failure switches
         * @param {boolean} [opts.failRead] - getForeignObjectAsync throws
         * @param {boolean} [opts.failWrite] - extendForeignObjectAsync throws
         * @returns {object} fake adapter with `store`, `writes` and `logs`
         */
        function fakeAdapter(native, secret, opts = {}) {
            const store = { ...native };
            const logs = { info: [], warn: [], error: [] };
            const writes = [];
            return {
                namespace: 'fingerprint.0',
                config: controllerConfig(store, secret),
                store,
                writes,
                logs,
                log: {
                    info: msg => logs.info.push(msg),
                    warn: msg => logs.warn.push(msg),
                    error: msg => logs.error.push(msg),
                },
                encrypt: value => controller.encrypt(secret, value),
                getForeignObjectAsync: async id => {
                    if (opts.failRead) {
                        throw new Error('db down');
                    }
                    assert.equal(id, 'system.adapter.fingerprint.0');
                    return { native: { ...store } };
                },
                extendForeignObjectAsync: async (id, obj) => {
                    if (opts.failWrite) {
                        throw new Error('db down');
                    }
                    writes.push(obj);
                    Object.assign(store, obj.native);
                },
            };
        }

        it('needsMigration never encrypts a value that is already garbage', () => {
            assert.equal(needsMigration('x', XOR_GARBAGE, true), false);
            assert.equal(needsMigration(XOR_GARBAGE, XOR_GARBAGE, false), false);
        });

        it('modern secret: encrypts plain text values (also short passwords) in one write', async () => {
            const adapter = fakeAdapter({ adminPassword: 'pw1', webhookToken: TOKEN }, MODERN_SECRET);
            assert.notEqual(adapter.config.adminPassword, 'pw1', 'precondition: controller damaged the value');

            const migrated = await migrateSecrets(adapter);

            assert.deepEqual(migrated, ['adminPassword', 'webhookToken']);
            assert.equal(adapter.config.adminPassword, 'pw1');
            assert.equal(adapter.config.webhookToken, TOKEN);
            assert.equal(adapter.writes.length, 1);
            assert.ok(adapter.store.adminPassword.startsWith(AES_PREFIX));
            assert.ok(adapter.store.webhookToken.startsWith(AES_PREFIX));
            assert.equal(adapter.logs.info.length, 1);

            // next start: the controller decrypts correctly, nothing is migrated again
            const next = fakeAdapter(adapter.store, MODERN_SECRET);
            assert.equal(next.config.adminPassword, 'pw1');
            assert.equal(next.config.webhookToken, TOKEN);
            assert.deepEqual(await migrateSecrets(next), []);
            assert.equal(next.writes.length, 0);
        });

        it('legacy secret: encrypts a plain text value that the controller damaged', async () => {
            const adapter = fakeAdapter({ webhookToken: TOKEN }, LEGACY_SECRET);
            assert.ok(isBrokenSecret(adapter.config.webhookToken), 'precondition: controller damaged the value');

            assert.deepEqual(await migrateSecrets(adapter), ['webhookToken']);
            assert.equal(adapter.config.webhookToken, TOKEN);
            assert.equal(adapter.store.webhookToken.startsWith(AES_PREFIX), false);

            // next start: no prefix with a legacy secret, but no migration (no flip-flop)
            const next = fakeAdapter(adapter.store, LEGACY_SECRET);
            assert.equal(next.config.webhookToken, TOKEN);
            assert.deepEqual(await migrateSecrets(next), []);
        });

        it('leaves values alone that Admin already stored encrypted', async () => {
            for (const secret of [MODERN_SECRET, LEGACY_SECRET]) {
                const stored = { adminPassword: controller.encrypt(secret, 'admin-password') };
                const adapter = fakeAdapter(stored, secret);
                assert.deepEqual(await migrateSecrets(adapter), []);
                assert.equal(adapter.config.adminPassword, 'admin-password');
                assert.equal(adapter.writes.length, 0);
            }
        });

        it('ignores missing and empty values', async () => {
            const adapter = fakeAdapter({ adminPassword: '' }, MODERN_SECRET);
            assert.deepEqual(await migrateSecrets(adapter), []);
            assert.equal(adapter.writes.length, 0);
        });

        it('keeps running when the instance object cannot be read', async () => {
            const adapter = fakeAdapter({ webhookToken: TOKEN }, MODERN_SECRET, { failRead: true });
            assert.deepEqual(await migrateSecrets(adapter), []);
            assert.match(adapter.logs.warn[0], /Could not check the stored secrets/);
        });

        it('uses the plain text for this run when the encrypted value cannot be written', async () => {
            const adapter = fakeAdapter({ webhookToken: TOKEN }, MODERN_SECRET, { failWrite: true });
            assert.deepEqual(await migrateSecrets(adapter), ['webhookToken']);
            assert.equal(adapter.config.webhookToken, TOKEN);
            assert.match(adapter.logs.warn[0], /Could not store webhookToken encrypted/);
        });
    });
});

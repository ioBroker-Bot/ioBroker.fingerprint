'use strict';

const path = require('node:path');
const assert = require('node:assert/strict');
const { tests } = require('@iobroker/testing');
const { AES_PREFIX } = require('../lib/secrets');
const controller = require('./helpers/controller-crypto');

const INSTANCE = 'system.adapter.fingerprint.0';
const PASSWORD = 'pw1';
const TOKEN = 'a3f09c1e7b2d4c5f8e6a9b0c1d2e3f405162738495a6b7c8';

// Run integration tests
tests.integration(path.join(__dirname, '..'), {
    defineAdditionalTests({ suite }) {
        suite('Secrets stored as plain text (before encryptedNative)', getHarness => {
            let harness;
            before(() => {
                harness = getHarness();
            });

            it('are encrypted on start and decrypt to the original values', async function () {
                this.timeout(60000);
                // changeAdapterConfig() would encrypt encryptedNative fields itself, so the plain
                // text values of an older release are written into the instance object directly
                const obj = await harness.objects.getObjectAsync(INSTANCE);
                obj.native.adminPassword = PASSWORD;
                obj.native.webhookToken = TOKEN;
                obj.native.espIp = '';
                obj.native.webhookPort = 18095;
                await harness.objects.setObjectAsync(INSTANCE, obj);

                await harness.startAdapterAndWait();

                let stored;
                for (let i = 0; i < 40; i++) {
                    stored = (await harness.objects.getObjectAsync(INSTANCE)).native;
                    if (stored.adminPassword !== PASSWORD && stored.webhookToken !== TOKEN) {
                        break;
                    }
                    await new Promise(resolve => setTimeout(resolve, 500));
                }
                const secret = (await harness.objects.getObjectAsync('system.config')).native.secret;

                assert.notEqual(stored.adminPassword, PASSWORD, 'adminPassword is still plain text');
                assert.notEqual(stored.webhookToken, TOKEN, 'webhookToken is still plain text');
                if (/^[0-9a-f]{48}$/.test(secret)) {
                    assert.ok(stored.adminPassword.startsWith(AES_PREFIX));
                    assert.ok(stored.webhookToken.startsWith(AES_PREFIX));
                }
                assert.equal(controller.decrypt(secret, stored.adminPassword), PASSWORD);
                assert.equal(controller.decrypt(secret, stored.webhookToken), TOKEN);
            });
        });

        suite('Webhook token of a new instance', getHarness => {
            let harness;
            before(() => {
                harness = getHarness();
            });

            it('stores a newly generated webhook token encrypted', async function () {
                this.timeout(60000);
                const obj = await harness.objects.getObjectAsync(INSTANCE);
                obj.native.adminPassword = '';
                obj.native.webhookToken = '';
                obj.native.espIp = '';
                obj.native.webhookPort = 18095;
                await harness.objects.setObjectAsync(INSTANCE, obj);

                await harness.startAdapterAndWait();

                let stored = '';
                for (let i = 0; i < 40 && !stored; i++) {
                    stored = (await harness.objects.getObjectAsync(INSTANCE)).native.webhookToken;
                    if (!stored) {
                        await new Promise(resolve => setTimeout(resolve, 500));
                    }
                }
                const secret = (await harness.objects.getObjectAsync('system.config')).native.secret;

                assert.ok(stored, 'no webhook token was generated');
                assert.match(controller.decrypt(secret, stored), /^[0-9a-f]{48}$/);
            });
        });
    },
});

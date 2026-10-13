'use strict';

/**
 * Helpers for the secret attributes (`adminPassword`, `webhookToken`) of the adapter config.
 *
 * History:
 *  - v0.7.5 declared these attributes as `encryptedNative` without a migration. The js-controller
 *    "decrypts" every stored value before the adapter starts; a value stored as plain text goes
 *    through `decryptLegacy()` (a plain XOR with the system secret, no check) and reaches
 *    `this.config` as garbage. Device login and provisioning failed.
 *  - v0.7.6 removed `encryptedNative` again and added the repair in `normalizeSecrets()`.
 *  - v0.7.13 declares `encryptedNative` again — this time together with `migrateSecrets()`, which
 *    runs before the secrets are used. Only the copy in `this.config` is damaged: the raw value in
 *    the instance object `system.adapter.<namespace>` is still the plain text, so it is read from
 *    there, used for this run and written back encrypted (the instance restarts once).
 */

const AES_PREFIX = '$/aes-192-cbc:';
const SECRET_ATTRS = ['adminPassword', 'webhookToken'];

/**
 * Check whether a value contains control characters and therefore cannot be a real secret
 *
 * @param {string} value - value to check
 * @returns {boolean} true if the value is unusable
 */
function isBrokenSecret(value) {
    // eslint-disable-next-line no-control-regex
    return /[\u0000-\u001f\u007f]/.test(value);
}

/**
 * Decide whether a stored secret is still plain text and has to be encrypted.
 *
 * - Modern system secret (48 hex digits): every encrypted value carries the `$/aes-192-cbc:`
 *   prefix, so a raw value without it is plain text — exact, also for short passwords.
 * - Legacy system secret: an encrypted value has no prefix either (XOR). Migrate only when the
 *   value the controller handed over is damaged (control characters) and the raw value is clean.
 *
 * @param {unknown} configValue - value in `this.config` (already "decrypted" by the controller)
 * @param {unknown} rawValue - value stored in the instance object
 * @param {boolean} modernSecret - true if the system secret produces `$/aes-192-cbc:` values
 * @returns {boolean} true if the raw value has to be encrypted
 */
function needsMigration(configValue, rawValue, modernSecret) {
    if (typeof rawValue !== 'string' || rawValue === '' || rawValue.startsWith(AES_PREFIX)) {
        return false;
    }
    if (isBrokenSecret(rawValue)) {
        // never encrypt garbage; with a legacy secret this is an already encrypted value
        return false;
    }
    if (modernSecret) {
        return true;
    }
    return typeof configValue === 'string' && isBrokenSecret(configValue);
}

/**
 * Encrypt secrets that are still stored as plain text (one-time migration to `encryptedNative`).
 * Modifies `adapter.config` so that this run already uses the correct plain text values. All
 * migrated attributes are written in one call, so the instance restarts only once.
 *
 * @param {object} adapter - adapter instance (`namespace`, `config`, `log`, `encrypt`,
 *     `getForeignObjectAsync`, `extendForeignObjectAsync`)
 * @param {string[]} [attrs] - secret attributes to check
 * @returns {Promise<string[]>} names of the migrated attributes
 */
async function migrateSecrets(adapter, attrs = SECRET_ATTRS) {
    const id = `system.adapter.${adapter.namespace}`;
    let native;
    let modernSecret;
    try {
        const obj = await adapter.getForeignObjectAsync(id);
        native = (obj && obj.native) || {};
        modernSecret = adapter.encrypt('probe').startsWith(AES_PREFIX);
    } catch (err) {
        adapter.log.warn(`Could not check the stored secrets: ${err.message}`);
        return [];
    }

    const update = {};
    const migrated = [];
    for (const attr of attrs) {
        const raw = native[attr];
        if (needsMigration(adapter.config[attr], raw, modernSecret)) {
            adapter.config[attr] = raw;
            update[attr] = adapter.encrypt(raw);
            migrated.push(attr);
        }
    }
    if (migrated.length === 0) {
        return [];
    }

    try {
        await adapter.extendForeignObjectAsync(id, { native: update });
        adapter.log.info(
            `${migrated.join(', ')} is now stored encrypted (one-time migration). The instance restarts once.`,
        );
    } catch (err) {
        adapter.log.warn(`Could not store ${migrated.join(', ')} encrypted: ${err.message}`);
    }
    return migrated;
}

/**
 * Make the stored secrets usable again (modifies `config` in place). Runs after
 * `migrateSecrets()` and catches values that are still damaged: values that an earlier release
 * stored in a form the controller cannot decrypt are dropped, so the webhook token is
 * regenerated and the user is asked to re-enter the password.
 *
 * @param {object} config - native configuration of the adapter
 * @param {object} logger - logger with `info`, `warn` and `error` methods
 * @param {(attr: string) => Promise<string>} [decrypt] - decrypts an encrypted config attribute
 * @returns {Promise<void>} resolves when the secrets have been checked
 */
async function normalizeSecrets(config, logger, decrypt) {
    for (const attr of SECRET_ATTRS) {
        let value = config[attr];
        if (typeof value !== 'string' || value === '') {
            continue;
        }

        if (value.startsWith(AES_PREFIX) && typeof decrypt === 'function') {
            try {
                value = await decrypt(attr);
                logger.info(`Using the decrypted ${attr} from the instance configuration.`);
            } catch (err) {
                logger.warn(`Could not decrypt the stored ${attr}: ${err.message}`);
                value = '';
            }
        }

        if (typeof value === 'string' && isBrokenSecret(value)) {
            if (attr === 'webhookToken') {
                logger.warn('The stored webhook token was unreadable — a new one will be generated.');
            } else {
                logger.error(
                    `The stored ${attr} is unreadable. Please open the adapter settings and enter the value again.`,
                );
            }
            value = '';
        }

        config[attr] = value;
    }
}

module.exports = { normalizeSecrets, migrateSecrets, needsMigration, isBrokenSecret, AES_PREFIX, SECRET_ATTRS };

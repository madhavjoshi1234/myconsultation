import crypto from 'crypto';
import os from 'os';
import path from 'path';
import { writeLog } from './utils.mjs';

export function decrypt(text, key) {
    if (!isLikelyEncrypted(text)) {
        return text;
    }
    const bData = Buffer.from(text, 'base64');
    // Extract salt and IV from OpenSSL-compatible encrypted string
    const salt = bData.slice(8, 16); // after "Salted__"
    const data = bData.slice(16);

    // Key and IV derivation (OpenSSL-style)
    const keyIv = crypto.pbkdf2Sync(key, salt, 10000, 32 + 16, 'sha256');
    const aesKey = keyIv.slice(0, 32);
    const iv = keyIv.slice(32);

    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    let decrypted = decipher.update(data, undefined, 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

export function encrypt(text, key) {
    // Generate a random salt
    const salt = crypto.randomBytes(8);

    // Key and IV derivation (OpenSSL-style)
    const keyIv = crypto.pbkdf2Sync(key, salt, 10000, 32 + 16, 'sha256');
    const aesKey = keyIv.slice(0, 32);
    const iv = keyIv.slice(32);

    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encrypted = cipher.update(text, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    // Format as OpenSSL-compatible encrypted string ("Salted__<salt><encrypted_data>")
    const result = Buffer.concat([Buffer.from("Salted__"), salt, encrypted]);
    return result.toString('base64');
}

export function getDefaultKey(force = false) {
    // Only return the home directory name if not in production mode.
    if (force === false && process.env.NODE_ENV === 'production') {
        return null;
    }
    return path.basename(os.homedir());
}

/**
 * Checks if a value is likely already encrypted by our encrypt function.
 * It looks for a Base64 string that decodes to something starting with "Salted__".
 * @param {string} value The value to check.
 * @returns {boolean} True if the value appears to be encrypted, false otherwise.
 */
export function isLikelyEncrypted(value) {
    if (!value || typeof value !== 'string') {
        return false;
    }
    try {
        const bData = Buffer.from(value, 'base64');
        // "Salted__" is 8 bytes. Salt is 8 bytes. Minimum 16 bytes for prefix + salt.
        if (bData.length < 16) return false;
        const prefix = bData.slice(0, 8).toString('utf8');
        return prefix === 'Salted__';
    } catch (e) {
        // Not a valid base64 string or other error
        return false;
    }
}

// The following functions were referenced in the test code but not defined in the original file.
// Implement minimal stubs for encryptWithDefaultKey and decryptWithDefaultKey for completeness:
export function encryptWithDefaultKey(text) {
    const key = getDefaultKey(true);
    if (!key) throw new Error('Default key is not available');
    return encrypt(text, key);
}
export function decryptWithDefaultKey(text) {
    const key = getDefaultKey(true);
    if (!key) throw new Error('Default key is not available');
    return decrypt(text, key);
}

if (import.meta.url === process.argv[1] || import.meta.url === `file://${process.argv[1]}`) {
    const testText = "This is a secret message!";
    const testKey = "mySuperSecretKey123";
    const homeDirKey = getDefaultKey();

    writeLog("Original Text:", testText);

    const encryptedText = encrypt(testText, testKey);
    writeLog("Encrypted Text:", encryptedText);

    const decryptedText = decrypt(encryptedText, testKey);
    writeLog("Decrypted Text:", decryptedText);

    if (testText === decryptedText) {
        writeLog("SUCCESS: Encryption and decryption successful. Original and decrypted texts match.");
    } else {
        writeLog("FAILURE: Encryption and decryption failed. Texts do not match.");
    }

    writeLog("\n--- Testing with default key (home directory name) ---");
    writeLog("Using default key:", homeDirKey);

    const encryptedTextDefault = encryptWithDefaultKey(testText);
    writeLog("Encrypted Text (default key):", encryptedTextDefault);

    const decryptedTextDefault = decryptWithDefaultKey(encryptedTextDefault);
    writeLog("Decrypted Text (default key):", decryptedTextDefault);

    if (testText === decryptedTextDefault) {
        writeLog("SUCCESS: Default key encryption and decryption successful.");
    } else {
        writeLog("FAILURE: Default key encryption and decryption failed.");
    }
}


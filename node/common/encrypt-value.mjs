import { decrypt, decryptWithDefaultKey, encrypt, getDefaultKey } from "./decrypt.mjs";
import dotenv from 'dotenv';
dotenv.config();

let args = process.argv.slice(2);
let value = args.filter(v => !v.startsWith('--'))[0];
let useDefaultKey = args.find(v => v === '--default') ? true : false;
if (!value) {
    console.error('No value provided.');
    process.exit(1);
}
let key = useDefaultKey ? getDefaultKey(true) : decryptWithDefaultKey(process.env.ENC_KEY || getDefaultKey());
if (!key) {
    console.error('No encryption key found in environment variables.');
    process.exit(1);
}
let encrypted = encrypt(value, key);
let decrypted = decrypt(encrypted, key);
if (decrypted !== value) {
    console.error('Decrypted value does not match original.');
    process.exit(1);
}
console.log(encrypted);


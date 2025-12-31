// Helper script to encrypt your Telegram credentials
// Run this with: node encrypt-credentials.js

const crypto = require('crypto');

// Simple XOR-based encryption (same as in submit.js)
function encrypt(text, key) {
    const textBuf = Buffer.from(text, 'utf8');
    const keyBuf = Buffer.from(key, 'utf8');
    const result = [];
    for (let i = 0; i < textBuf.length; i++) {
        result.push(textBuf[i] ^ keyBuf[i % keyBuf.length]);
    }
    return Buffer.from(result).toString('hex');
}

// Obfuscated key (must match submit.js)
const _k1 = 'x7f';
const _k2 = '9m2';
const _k3 = 'p4q';
const _k4 = '8n1';
const ENCRYPT_KEY = _k2 + _k4 + _k1 + _k3;

// Replace these with your actual Telegram bot token and chat ID
const BOT_TOKEN = '7268474710:AAEKnDq7vcix_xUGrqI5gBU5Yp4C27T82Pk';
const CHAT_ID = '6390370714';

if (BOT_TOKEN === 'YOUR_BOT_TOKEN_HERE' || CHAT_ID === 'YOUR_CHAT_ID_HERE') {
    console.log('Please replace BOT_TOKEN and CHAT_ID with your actual values!');
    process.exit(1);
}

const encryptedToken = encrypt(BOT_TOKEN, ENCRYPT_KEY);
const encryptedChatId = encrypt(CHAT_ID, ENCRYPT_KEY);

console.log('\n=== Encrypted Credentials ===\n');
console.log('ENC_BOT_TOKEN_2 = \'' + encryptedToken + '\';');
console.log('ENC_CHAT_ID_2 = \'' + encryptedChatId + '\';\n');
console.log('Copy these values and paste them into api/submit.js\n');


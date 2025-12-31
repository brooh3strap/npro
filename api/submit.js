const https = require('https');

module.exports = async function handler(req, res) {
    if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
    }

    const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
    const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

    if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
        return res.status(500).json({ ok: false, error: 'Server is not configured.' });
    }

    const text = (req.body && typeof req.body.text === 'string') ? req.body.text : '';
    if (!text) {
        return res.status(400).json({ ok: false, error: 'Missing text' });
    }

    const payload = JSON.stringify({
        chat_id: TELEGRAM_CHAT_ID,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true
    });

    const options = {
        hostname: 'api.telegram.org',
        method: 'POST',
        path: `/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload)
        }
    };

    try {
        const responseBody = await new Promise((resolve, reject) => {
            const tgReq = https.request(options, tgRes => {
                let data = '';
                tgRes.on('data', chunk => { data += chunk; });
                tgRes.on('end', () => resolve(data));
            });
            tgReq.on('error', reject);
            tgReq.write(payload);
            tgReq.end();
        });

        try {
            const parsed = JSON.parse(responseBody || '{}');
            return res.status(200).json({ ok: true, telegram: { ok: parsed.ok === true } });
        } catch (_) {
            return res.status(200).json({ ok: true });
        }
    } catch (e) {
        return res.status(502).json({ ok: false, error: 'Upstream error' });
    }
};



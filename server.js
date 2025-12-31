// Minimal Express server to proxy submissions to Telegram without exposing secrets client-side
const path = require('path');
const https = require('https');
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000; // change if you need a different port

// Configure your Telegram details from environment
const TELEGRAM_BOT_TOKEN = '7268474710:AAEKnDq7vcix_xUGrqI5gBU5Yp4C27T82Pk';
const TELEGRAM_CHAT_ID = '6390370714';

app.use(cors());
app.use(express.json({ limit: '100kb' }));

// Block access to sensitive files if requested over HTTP
app.get(['/server.js', '/.env', '/package.json', '/package-lock.json'], (req, res) => {
    res.status(404).end();
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ ok: true });
});

// Submission endpoint - forwards message text to Telegram
app.post('/api/submit', (req, res) => {
    try {
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

        const tgReq = https.request(options, tgRes => {
            let data = '';
            tgRes.on('data', chunk => { data += chunk; });
            tgRes.on('end', () => {
                try {
                    const parsed = JSON.parse(data || '{}');
                    // Mask sensitive fields
                    return res.status(200).json({ ok: true, telegram: { ok: parsed.ok === true } });
                } catch (_) {
                    return res.status(200).json({ ok: true });
                }
            });
        });

        tgReq.on('error', (err) => {
            return res.status(502).json({ ok: false, error: 'Upstream error' });
        });

        tgReq.write(payload);
        tgReq.end();
    } catch (e) {
        return res.status(500).json({ ok: false });
    }
});

// Serve static files
app.use(express.static(path.join(__dirname)));

// Fallback to index.html for any unmatched route (optional if SPA)
// Express v5 requires a named parameter for wildcards; use a catch-all handler instead
app.use((req, res, next) => {
    if (req.method !== 'GET') return next();
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
});



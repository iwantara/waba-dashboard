require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const API_BASE = 'https://api.kirim.chat/api/v1/public';

// Store messages in memory & SSE clients
const messages = [];
const sseClients = [];

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Parse JSON for all routes except webhook (need raw body for signature)
app.use((req, res, next) => {
  if (req.path === '/webhook') {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      req.rawBody = data;
      try { req.body = JSON.parse(data); } catch { req.body = {}; }
      next();
    });
  } else {
    express.json()(req, res, next);
  }
});

// --- SSE: push pesan masuk real-time ke browser ---
app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  sseClients.push(res);
  req.on('close', () => {
    const idx = sseClients.indexOf(res);
    if (idx !== -1) sseClients.splice(idx, 1);
  });
});

function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(client => client.write(payload));
}

// --- Webhook: terima pesan masuk dari KirimChat ---
app.post('/webhook', (req, res) => {
  // Verify signature if secret is configured
  const secret = process.env.WEBHOOK_SECRET;
  if (secret && secret !== 'your_webhook_secret_here') {
    const signature = req.headers['x-kirimchat-signature'];
    if (signature) {
      const expected = 'sha256=' + crypto
        .createHmac('sha256', secret)
        .update(req.rawBody)
        .digest('hex');
      if (signature !== expected) {
        console.log('Webhook signature mismatch');
        return res.status(401).json({ error: 'Invalid signature' });
      }
    }
  }

  const body = req.body;
  console.log('Webhook received:', JSON.stringify(body, null, 2));

  // Handle message.received event
  if (body.event_type === 'message.received') {
    const msg = {
      id: body.data?.message_id || Date.now().toString(),
      from: body.data?.customer_phone || body.data?.customer_id || 'unknown',
      direction: 'inbound',
      type: body.data?.message_type || 'text',
      content: body.data?.content || '',
      channel: body.data?.channel || 'whatsapp',
      timestamp: body.timestamp || new Date().toISOString()
    };
    messages.push(msg);
    broadcast('message', msg);
  }

  res.status(200).json({ received: true });
});

// --- API Proxy: kirim pesan via KirimChat ---
app.post('/api/send', async (req, res) => {
  const apiKey = process.env.KIRIMCHAT_API_KEY;
  if (!apiKey || apiKey === 'kc_live_xxxxx') {
    return res.status(400).json({ error: 'API Key belum dikonfigurasi di .env' });
  }

  const { to, type, text, image } = req.body;

  const msgType = type || 'text';
  const payload = {
    channel: 'whatsapp',
    to,
    type: msgType
  };

  if (msgType === 'image') {
    payload.image = image; // { link, caption }
  } else {
    payload.text = text; // { body }
  }

  console.log('Sending payload:', JSON.stringify(payload, null, 2));

  try {
    const response = await axios.post(`${API_BASE}/messages/send`, payload, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      }
    });

    // Store outbound message locally
    const outMsg = {
      id: response.data.message_id || Date.now().toString(),
      to,
      direction: 'outbound',
      type: type || 'text',
      content: type === 'image' ? (image?.caption || '') : (text?.body || ''),
      imageUrl: type === 'image' ? image?.link : null,
      channel: 'whatsapp',
      timestamp: new Date().toISOString()
    };
    messages.push(outMsg);
    broadcast('message', outMsg);

    res.json(response.data);
  } catch (err) {
    console.error('=== SEND ERROR ===');
    console.error('Status:', err.response?.status);
    console.error('Response:', JSON.stringify(err.response?.data, null, 2));
    console.error('Payload sent:', JSON.stringify(payload, null, 2));
    console.error('==================');
    const errMsg = err.response?.data?.message || err.response?.data?.error || err.message || 'Unknown error';
    res.status(err.response?.status || 500).json({
      error: errMsg
    });
  }
});

// --- Get messages history (since server start) ---
app.get('/api/messages', (req, res) => {
  res.json(messages);
});

// --- Test API Key: cek apakah key masih valid ---
app.get('/api/test-key', async (req, res) => {
  const apiKey = process.env.KIRIMCHAT_API_KEY;
  if (!apiKey || apiKey === 'kc_live_xxxxx') {
    return res.json({ valid: false, error: 'API Key belum dikonfigurasi' });
  }

  try {
    // Kirim request ke messages/send dengan payload minimal untuk cek auth
    // Kalau 401 = key invalid, kalau 422/400 = key valid tapi payload salah (expected)
    const resp = await axios.post(`${API_BASE}/messages/send`, {
      channel: 'whatsapp',
      to: '000',
      type: 'text',
      text: { body: 'test' }
    }, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
    // Kalau sampai sini = key valid dan request berhasil (unlikely tapi mungkin)
    res.json({
      valid: true,
      keyPrefix: apiKey.substring(0, 15) + '...',
      apiResponse: resp.data,
      apiStatus: resp.status
    });
  } catch (err) {
    const status = err.response?.status;
    // 401 = unauthorized (key invalid), selain itu = key valid tapi request gagal (normal)
    if (status === 401) {
      res.json({
        valid: false,
        keyPrefix: apiKey.substring(0, 15) + '...',
        error: err.response?.data,
        status,
        hint: 'API Key tidak valid atau sudah expired. Buat key baru di KirimChat > Developers > API Keys'
      });
    } else {
      // 400, 422, dll = key diterima, hanya payload yg invalid → key VALID
      res.json({
        valid: true,
        keyPrefix: apiKey.substring(0, 15) + '...',
        note: 'API Key diterima oleh server (auth OK)',
        testError: err.response?.data,
        status
      });
    }
  }
});

// --- Health check ---
app.get('/api/health', async (req, res) => {
  const apiKey = process.env.KIRIMCHAT_API_KEY;
  if (!apiKey || apiKey === 'kc_live_xxxxx') {
    return res.json({ status: 'ok', api: 'not configured' });
  }
  try {
    const resp = await axios.get(`${API_BASE}/health`, {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    });
    res.json({ status: 'ok', api: resp.data });
  } catch (err) {
    res.json({ status: 'ok', api: 'error', detail: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`WABA Dashboard running at http://localhost:${PORT}`);
  console.log('API Key:', process.env.KIRIMCHAT_API_KEY?.substring(0, 12) + '...');
});

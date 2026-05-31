/**
 * Healthcare Patient Portal – JavaScript Security Demo
 * =====================================================
 * FOR EDUCATIONAL PURPOSES ONLY
 * Demonstrates XSS and eval() vulnerabilities and their mitigations.
 * Do NOT deploy this to a production environment.
 */

const express = require('express');
const he = require('he');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// In-memory message stores
let vulnerableMessages = [];
let secureMessages = [];

// Sample patient records for filter demos
const patientRecords = [
  { name: 'John Doe',     age: 45, condition: 'Diabetes' },
  { name: 'Jane Smith',   age: 32, condition: 'Hypertension' },
  { name: 'Bob Johnson',  age: 67, condition: 'Arthritis' },
  { name: 'Alice Brown',  age: 55, condition: 'Asthma' },
  { name: 'Tom Wilson',   age: 28, condition: 'Migraine' },
];

// ─────────────────────────────────────────────────────────────
// VULNERABLE ENDPOINTS
// ─────────────────────────────────────────────────────────────

// 1. Reflected XSS – Vulnerable search (no encoding)
app.get('/vulnerable/search', (req, res) => {
  const query = req.query.q || '';
  // VULNERABLE: user input injected directly into HTML
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Vulnerable Search</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 30px; background: #fff5f5; }
        .badge { background: #e74c3c; color: #fff; padding: 10px 16px; border-radius: 6px; display:inline-block; margin-bottom:16px; font-weight:bold; }
        .result-box { background: #fff; border: 2px solid #e74c3c; border-radius: 8px; padding: 20px; margin-top: 16px; }
        a { color: #e74c3c; }
      </style>
    </head>
    <body>
      <span class="badge">⚠️ VULNERABLE – No Input Sanitization</span>
      <div class="result-box">
        <p><strong>Search Results for:</strong></p>
        <p>${query}</p>
      </div>
      <p><a href="/">← Back to Demo</a></p>
    </body>
    </html>
  `);
});

// 2. Stored XSS – Store message without sanitization
app.post('/vulnerable/messages', (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Content is required' });
  // VULNERABLE: stored directly without sanitization
  vulnerableMessages.push({ content, time: new Date().toLocaleTimeString() });
  res.json({ success: true, note: 'Stored WITHOUT sanitization' });
});

// 3. Stored XSS – Render messages without encoding
app.get('/vulnerable/messages', (req, res) => {
  let html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Vulnerable Messages</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 30px; background: #fff5f5; }
        .badge { background:#e74c3c; color:#fff; padding:10px 16px; border-radius:6px; display:inline-block; margin-bottom:16px; font-weight:bold; }
        .msg { background:#fff; border-left:4px solid #e74c3c; padding:12px 16px; margin:8px 0; border-radius:4px; }
        .time { font-size:11px; color:#999; }
        a { color:#e74c3c; }
      </style>
    </head>
    <body>
      <span class="badge">⚠️ VULNERABLE – Messages Rendered Without Encoding</span>
      <h2>Patient Messages</h2>
  `;
  if (vulnerableMessages.length === 0) {
    html += '<p style="color:#999;">No messages yet. Submit one from the demo page.</p>';
  }
  vulnerableMessages.forEach(msg => {
    // VULNERABLE: msg.content injected directly (scripts will execute)
    html += `<div class="msg"><span class="time">${msg.time}</span><p>${msg.content}</p></div>`;
  });
  html += '<p><a href="/">← Back to Demo</a></p></body></html>';
  res.send(html);
});

// 4. eval() – Vulnerable filter using eval() on user input
app.post('/vulnerable/filter', (req, res) => {
  const { expression } = req.body;
  try {
    // VULNERABLE: eval() called directly on user-supplied expression
    const filterFn = eval(`(record) => ${expression}`);
    const results = patientRecords.filter(filterFn);
    res.json({
      success: true,
      results,
      warning: 'eval() was executed on your raw input!'
    });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────
// SECURE ENDPOINTS
// ─────────────────────────────────────────────────────────────

// 1. Reflected XSS – Secure search (validate + encode)
app.get('/secure/search', (req, res) => {
  const query = req.query.q || '';
  // SECURE: strip non-alphanumeric characters, then HTML-encode
  const sanitized = query.replace(/[^a-zA-Z0-9\s\-\.]/g, '').slice(0, 200);
  const encoded   = he.encode(sanitized);
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Secure Search</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 30px; background: #f0fff4; }
        .badge { background: #27ae60; color: #fff; padding: 10px 16px; border-radius: 6px; display:inline-block; margin-bottom:16px; font-weight:bold; }
        .result-box { background: #fff; border: 2px solid #27ae60; border-radius: 8px; padding: 20px; margin-top: 16px; }
        a { color: #27ae60; }
      </style>
    </head>
    <body>
      <span class="badge">✅ SECURE – Input Validated &amp; HTML-Encoded</span>
      <div class="result-box">
        <p><strong>Search Results for:</strong></p>
        <p>${encoded}</p>
      </div>
      <p><a href="/">← Back to Demo</a></p>
    </body>
    </html>
  `);
});

// 2. Stored XSS – Store message with DOMPurify sanitization
app.post('/secure/messages', (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Content is required' });
  // SECURE: sanitize with DOMPurify (server-side via jsdom)
  const window    = new JSDOM('').window;
  const DOMPurify = createDOMPurify(window);
  const sanitized = DOMPurify.sanitize(content, { ALLOWED_TAGS: [] });
  secureMessages.push({ content: sanitized, time: new Date().toLocaleTimeString() });
  res.json({ success: true, note: 'Stored WITH DOMPurify sanitization', sanitized });
});

// 3. Stored XSS – Render messages with he.encode() output encoding
app.get('/secure/messages', (req, res) => {
  let html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Secure Messages</title>
      <style>
        body { font-family: Arial, sans-serif; padding: 30px; background: #f0fff4; }
        .badge { background:#27ae60; color:#fff; padding:10px 16px; border-radius:6px; display:inline-block; margin-bottom:16px; font-weight:bold; }
        .msg { background:#fff; border-left:4px solid #27ae60; padding:12px 16px; margin:8px 0; border-radius:4px; }
        .time { font-size:11px; color:#999; }
        a { color:#27ae60; }
      </style>
    </head>
    <body>
      <span class="badge">✅ SECURE – Messages Sanitized &amp; Output-Encoded</span>
      <h2>Patient Messages</h2>
  `;
  if (secureMessages.length === 0) {
    html += '<p style="color:#999;">No messages yet. Submit one from the demo page.</p>';
  }
  secureMessages.forEach(msg => {
    // SECURE: he.encode() ensures no HTML is rendered
    html += `<div class="msg"><span class="time">${msg.time}</span><p>${he.encode(msg.content)}</p></div>`;
  });
  html += '<p><a href="/">← Back to Demo</a></p></body></html>';
  res.send(html);
});

// 4. eval() – Secure whitelist-based filter (no eval)
app.post('/secure/filter', (req, res) => {
  const { filterKey } = req.body;
  // SECURE: only predefined functions are allowed — no user code evaluated
  const ALLOWED_FILTERS = {
    'age_over_40':  (r) => r.age > 40,
    'age_over_60':  (r) => r.age > 60,
    'all_records':  (r) => true,
  };
  if (!Object.prototype.hasOwnProperty.call(ALLOWED_FILTERS, filterKey)) {
    return res.json({
      success: false,
      error: `Invalid filter key: "${filterKey}". Allowed keys: ${Object.keys(ALLOWED_FILTERS).join(', ')}`
    });
  }
  const results = patientRecords.filter(ALLOWED_FILTERS[filterKey]);
  res.json({ success: true, results, note: 'No eval() used. Whitelist-based filter applied safely.' });
});

// Reset stored messages
app.post('/reset', (req, res) => {
  vulnerableMessages = [];
  secureMessages     = [];
  res.json({ success: true, message: 'All messages cleared.' });
});

// Start server
app.listen(PORT, () => {
  console.log('\n======================================');
  console.log('  🏥 Healthcare Portal Security Demo');
  console.log('======================================');
  console.log(`  URL: http://localhost:${PORT}`);
  console.log('  ⚠️  FOR EDUCATIONAL PURPOSES ONLY');
  console.log('======================================\n');
});

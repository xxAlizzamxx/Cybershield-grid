require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const path       = require('path');
const nodemailer = require('nodemailer');

const app  = express();
const PORT = 5000;

app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'frontend')));

// ── In-memory event store ──────────────────────────────────
let events = [];

// ── Frontend ───────────────────────────────────────────────
app.get('/', (req, res) =>
  res.sendFile(path.join(__dirname, 'frontend', 'index.html')));

// ── API ────────────────────────────────────────────────────
app.get('/data', (req, res) => res.json(events));

app.post('/upload', (req, res) => {
  const { events: incoming } = req.body || {};
  if (!Array.isArray(incoming))
    return res.status(400).json({ error: 'No events provided' });
  events = incoming;
  res.json({ status: 'ok', count: events.length });
});

app.get('/simulate', (req, res) => {
  const TYPES   = ['DDoS', 'SQL Injection', 'Brute Force', 'Phishing',
                   'XSS', 'Port Scan', 'Ransomware'];
  const TARGETS = ['192.168.1.1', '10.0.0.1', '172.16.0.1',
                   '10.10.0.5', '192.168.0.254'];
  const LAT_MIN = -4.23,  LAT_MAX = 12.45;
  const LON_MIN = -81.73, LON_MAX = -66.87;
  const count   = parseInt(req.query.count || '100', 10);
  const now     = Date.now();
  const rand    = (a, b) => Math.random() * (b - a) + a;
  const rndInt  = (a, b) => Math.floor(rand(a, b + 1));
  const ip      = () => `${rndInt(1,254)}.${rndInt(1,254)}.${rndInt(1,254)}.${rndInt(1,254)}`;
  const newEvts = [];

  for (let i = 0; i < count - 14; i++)
    newEvts.push({
      ip: ip(), timestamp: new Date(now - rand(10000, 600000)).toISOString(),
      attack_type: TYPES[rndInt(0, TYPES.length-1)],
      latitude: +rand(LAT_MIN, LAT_MAX).toFixed(5),
      longitude: +rand(LON_MIN, LON_MAX).toFixed(5),
      target: TARGETS[rndInt(0, TARGETS.length-1)]
    });

  for (let i = 0; i < 8; i++)
    newEvts.push({ ip: `203.0.${rndInt(1,254)}.${rndInt(1,254)}`,
      timestamp: new Date(now - i * 900).toISOString(), attack_type: 'DDoS',
      latitude: +rand(LAT_MIN, LAT_MAX).toFixed(5),
      longitude: +rand(LON_MIN, LON_MAX).toFixed(5), target: '192.168.1.1' });

  for (let i = 0; i < 4; i++)
    newEvts.push({ ip: `10.${rndInt(0,9)}.${rndInt(1,254)}.${rndInt(1,254)}`,
      timestamp: new Date(now - (5 + i*6)*1000).toISOString(), attack_type: 'Brute Force',
      latitude: +rand(LAT_MIN, LAT_MAX).toFixed(5),
      longitude: +rand(LON_MIN, LON_MAX).toFixed(5), target: '10.0.0.1' });

  for (let i = 0; i < 2; i++)
    newEvts.push({ ip: `185.${rndInt(1,254)}.${rndInt(1,254)}.${rndInt(1,254)}`,
      timestamp: new Date(now - (30 + i*40)*1000).toISOString(), attack_type: 'Ransomware',
      latitude: +rand(LAT_MIN, LAT_MAX).toFixed(5),
      longitude: +rand(LON_MIN, LON_MAX).toFixed(5),
      target: TARGETS[rndInt(0, TARGETS.length-1)] });

  events = newEvts;
  res.json({ status: 'ok', count: newEvts.length, events: newEvts });
});

// ── Alert email endpoint ───────────────────────────────────
app.post('/alert', async (req, res) => {
  const { to, events: evts = [], anomalies = [] } = req.body || {};

  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS ||
      process.env.EMAIL_USER === 'tu_correo@gmail.com') {
    return res.status(503).json({
      error: 'Email not configured',
      hint:  'Edit .env with your EMAIL_USER, EMAIL_PASS and EMAIL_TO'
    });
  }

  const recipient = to || process.env.EMAIL_TO;
  if (!recipient)
    return res.status(400).json({ error: 'No recipient email provided' });

  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });

    const csv  = buildCSV(evts);
    const html = buildEmailHTML(evts, anomalies, recipient);

    await transporter.sendMail({
      from:        `"CyberShield Grid 🛡" <${process.env.EMAIL_USER}>`,
      to:          recipient,
      subject:     `🚨 ALERT: ${evts.length} cyberattacks detected — Immediate action required`,
      html,
      attachments: [{
        filename:    `cybershield_attacks_${Date.now()}.csv`,
        content:     csv,
        contentType: 'text/csv'
      }]
    });

    console.log(`[ALERT] Email sent to ${recipient} — ${evts.length} events`);
    res.json({ status: 'ok', message: `Alert sent to ${recipient}` });

  } catch (err) {
    console.error('[ALERT] Email error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── CSV generator ──────────────────────────────────────────
function buildCSV(evts) {
  const headers = ['ip', 'timestamp', 'attack_type', 'target', 'latitude', 'longitude'];
  const rows    = evts.map(e => headers.map(h => `"${e[h] || ''}"`).join(','));
  return [headers.join(','), ...rows].join('\n');
}

// ── Email HTML template ────────────────────────────────────
function buildEmailHTML(evts, anomalies, recipient) {
  const now     = new Date().toLocaleString('es-CO', { timeZone: 'America/Bogota' });
  const typeCounts = {};
  evts.forEach(e => { typeCounts[e.attack_type] = (typeCounts[e.attack_type] || 0) + 1; });
  const topTypes = Object.entries(typeCounts).sort((a,b) => b[1]-a[1]);

  const targetCounts = {};
  evts.forEach(e => { if (e.target && e.target !== 'N/A')
    targetCounts[e.target] = (targetCounts[e.target] || 0) + 1; });
  const topTargets = Object.entries(targetCounts).sort((a,b) => b[1]-a[1]).slice(0, 5);

  const uniqueIPs = new Set(evts.map(e => e.ip)).size;

  const SCOLOR = { CRITICAL: '#ff3333', HIGH: '#ff6600', MEDIUM: '#ffcc00' };

  const anomalyRows = anomalies.length
    ? anomalies.map(a => `
        <tr>
          <td style="padding:8px 12px;">
            <span style="background:${SCOLOR[a.severity]||'#999'};color:#000;
              font-size:10px;font-weight:bold;padding:2px 6px;border-radius:3px;">
              ${a.severity}
            </span>
          </td>
          <td style="padding:8px 12px;font-weight:bold;">${a.name}</td>
          <td style="padding:8px 12px;color:#555;">${a.detail}</td>
        </tr>`).join('')
    : `<tr><td colspan="3" style="padding:8px 12px;color:#888;">No anomalies recorded</td></tr>`;

  const typeRows = topTypes.map(([type, count]) => `
    <tr>
      <td style="padding:7px 12px;font-weight:bold;">${type}</td>
      <td style="padding:7px 12px;">${count}</td>
      <td style="padding:7px 12px;">
        <div style="background:#e0e0e0;border-radius:4px;height:8px;width:160px;">
          <div style="background:#cc2200;border-radius:4px;height:8px;
            width:${Math.round((count/evts.length)*160)}px;"></div>
        </div>
      </td>
    </tr>`).join('');

  const targetRows = topTargets.map(([t, c]) => `
    <tr>
      <td style="padding:7px 12px;font-family:monospace;">${t}</td>
      <td style="padding:7px 12px;color:#cc2200;font-weight:bold;">${c} attacks</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:Arial,sans-serif;">

  <!-- Header -->
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td style="background:#0a0e1a;padding:28px 40px;">
        <table width="100%">
          <tr>
            <td>
              <span style="color:#00ff88;font-size:22px;font-weight:bold;
                letter-spacing:3px;">🛡 CYBERSHIELD GRID</span><br/>
              <span style="color:#64748b;font-size:12px;letter-spacing:1px;">
                SECURITY INCIDENT NOTIFICATION
              </span>
            </td>
            <td align="right">
              <span style="background:#ff3333;color:#fff;font-size:13px;
                font-weight:bold;padding:8px 18px;border-radius:4px;
                letter-spacing:2px;">🚨 CRITICAL ALERT</span>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>

  <!-- Red banner -->
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td style="background:#cc0000;padding:14px 40px;color:#fff;
        font-size:14px;font-weight:bold;letter-spacing:1px;">
        ⚠ Active cyberattack detected on your infrastructure — Immediate action required
      </td>
    </tr>
  </table>

  <!-- Body -->
  <table width="100%" cellpadding="0" cellspacing="0"
    style="max-width:680px;margin:0 auto;">
    <tr><td style="padding:28px 40px;">

      <!-- Intro -->
      <p style="color:#1e293b;font-size:14px;line-height:1.7;margin:0 0 24px;">
        CyberShield Grid has detected a significant volume of cyberattacks targeting
        your systems. This automated alert was generated on
        <strong>${now} (COT)</strong> and sent to
        <strong>${recipient}</strong>.<br/><br/>
        The full attack log is attached as a CSV file for forensic analysis.
      </p>

      <!-- KPI boxes -->
      <table width="100%" cellpadding="0" cellspacing="0"
        style="margin-bottom:28px;">
        <tr>
          <td width="25%" style="padding:4px;">
            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;
              padding:16px;text-align:center;border-top:3px solid #cc2200;">
              <div style="font-size:32px;font-weight:bold;color:#cc2200;">${evts.length}</div>
              <div style="font-size:11px;color:#64748b;text-transform:uppercase;
                letter-spacing:1px;">Total Events</div>
            </div>
          </td>
          <td width="25%" style="padding:4px;">
            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;
              padding:16px;text-align:center;border-top:3px solid #ff6600;">
              <div style="font-size:32px;font-weight:bold;color:#ff6600;">${uniqueIPs}</div>
              <div style="font-size:11px;color:#64748b;text-transform:uppercase;
                letter-spacing:1px;">Unique IPs</div>
            </div>
          </td>
          <td width="25%" style="padding:4px;">
            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;
              padding:16px;text-align:center;border-top:3px solid #0066cc;">
              <div style="font-size:32px;font-weight:bold;color:#0066cc;">${topTypes.length}</div>
              <div style="font-size:11px;color:#64748b;text-transform:uppercase;
                letter-spacing:1px;">Attack Types</div>
            </div>
          </td>
          <td width="25%" style="padding:4px;">
            <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;
              padding:16px;text-align:center;border-top:3px solid #cc0000;">
              <div style="font-size:32px;font-weight:bold;color:#cc0000;">${anomalies.length}</div>
              <div style="font-size:11px;color:#64748b;text-transform:uppercase;
                letter-spacing:1px;">Anomalies</div>
            </div>
          </td>
        </tr>
      </table>

      <!-- Anomalies -->
      <h3 style="color:#0a0e1a;font-size:14px;letter-spacing:1px;
        text-transform:uppercase;border-bottom:2px solid #cc2200;
        padding-bottom:8px;margin:0 0 12px;">Detected Anomalies</h3>
      <table width="100%" cellpadding="0" cellspacing="0"
        style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;
          margin-bottom:24px;font-size:13px;">
        <tr style="background:#f8fafc;">
          <th style="padding:9px 12px;text-align:left;font-size:11px;
            color:#64748b;text-transform:uppercase;letter-spacing:1px;">Severity</th>
          <th style="padding:9px 12px;text-align:left;font-size:11px;
            color:#64748b;text-transform:uppercase;letter-spacing:1px;">Rule</th>
          <th style="padding:9px 12px;text-align:left;font-size:11px;
            color:#64748b;text-transform:uppercase;letter-spacing:1px;">Detail</th>
        </tr>
        ${anomalyRows}
      </table>

      <!-- Attack types -->
      <h3 style="color:#0a0e1a;font-size:14px;letter-spacing:1px;
        text-transform:uppercase;border-bottom:2px solid #e2e8f0;
        padding-bottom:8px;margin:0 0 12px;">Attack Distribution</h3>
      <table width="100%" cellpadding="0" cellspacing="0"
        style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;
          margin-bottom:24px;font-size:13px;">
        <tr style="background:#f8fafc;">
          <th style="padding:9px 12px;text-align:left;font-size:11px;
            color:#64748b;text-transform:uppercase;letter-spacing:1px;">Type</th>
          <th style="padding:9px 12px;text-align:left;font-size:11px;
            color:#64748b;text-transform:uppercase;letter-spacing:1px;">Count</th>
          <th style="padding:9px 12px;text-align:left;font-size:11px;
            color:#64748b;text-transform:uppercase;letter-spacing:1px;">Volume</th>
        </tr>
        ${typeRows}
      </table>

      <!-- Top targets -->
      <h3 style="color:#0a0e1a;font-size:14px;letter-spacing:1px;
        text-transform:uppercase;border-bottom:2px solid #e2e8f0;
        padding-bottom:8px;margin:0 0 12px;">Most Targeted Systems</h3>
      <table width="100%" cellpadding="0" cellspacing="0"
        style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;
          margin-bottom:28px;font-size:13px;">
        <tr style="background:#f8fafc;">
          <th style="padding:9px 12px;text-align:left;font-size:11px;
            color:#64748b;text-transform:uppercase;letter-spacing:1px;">Target IP</th>
          <th style="padding:9px 12px;text-align:left;font-size:11px;
            color:#64748b;text-transform:uppercase;letter-spacing:1px;">Attacks</th>
        </tr>
        ${targetRows}
      </table>

      <!-- Action box -->
      <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;
        padding:16px 20px;margin-bottom:28px;">
        <p style="margin:0;color:#856404;font-size:13px;line-height:1.7;">
          <strong>⚡ Recommended Actions:</strong><br/>
          1. Block the identified source IPs at your firewall immediately.<br/>
          2. Isolate the most targeted systems from the network.<br/>
          3. Review the attached CSV for full forensic data.<br/>
          4. Escalate to your incident response team.
        </p>
      </div>

      <!-- Footer -->
      <p style="color:#94a3b8;font-size:11px;border-top:1px solid #e2e8f0;
        padding-top:16px;margin:0;">
        This alert was generated automatically by CyberShield Grid.<br/>
        Timestamp: ${now} (COT) &nbsp;|&nbsp;
        Events in attachment: ${evts.length} &nbsp;|&nbsp;
        Do not reply to this email.
      </p>

    </td></tr>
  </table>

</body>
</html>`;
}

// ── Start ──────────────────────────────────────────────────
app.listen(PORT, () => {
  const emailOk = process.env.EMAIL_USER &&
                  process.env.EMAIL_USER !== 'tu_correo@gmail.com';
  console.log(`\n  CyberShield Grid  →  http://localhost:${PORT}`);
  console.log(`  Email alerts      →  ${emailOk ? '✓ configured' : '⚠ not configured (edit .env)'}\n`);
});

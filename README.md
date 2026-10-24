# JurisScan-AI
JurisScan AI - QR scanning and information analysis demo
// JurisScan AI server — Node.js, no external dependencies.
// JSON file store (data/). For production use PostgreSQL + Prisma/Drizzle.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { analyze, hasPerm, ROLES, TEST_CASES } from './lib/analyzer.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const MAX_BODY = 1_000_000;

// Demo users — passwords hashed at boot with scrypt; in production seed via admin tool / IdP.
// Demo mode is clearly labelled in the UI. Change these via env in real deployments.
const DEMO_USERS = [
  { username: 'admin', password: process.env.ADMIN_PASSWORD || 'Admin@123', role: 'admin', name: 'Quản trị viên hệ thống', unit: 'Ban CNTT' },
  { username: 'thamphan', password: process.env.OFFICER_PASSWORD || 'Officer@123', role: 'officer', name: 'Thẩm phán / Cán bộ xử lý', unit: 'Tòa án — demo' },
  { username: 'thuky', password: process.env.REVIEWER_PASSWORD || 'Reviewer@123', role: 'reviewer', name: 'Thư ký tòa án (Reviewer)', unit: 'Văn phòng — demo' },
  { username: 'readonly', password: process.env.READONLY_PASSWORD || 'Reader@123', role: 'readonly', name: 'Người dùng chỉ xem', unit: 'Demo' },
];

function hashPw(pw, salt) { return crypto.scryptSync(pw, salt, 64).toString('hex'); }
const users = DEMO_USERS.map(u => { const salt = crypto.randomBytes(16).toString('hex'); return { ...u, password: undefined, salt, hash: hashPw(u.password || '', salt), plainHint: undefined }; });
users.forEach((u, i) => { u._demoPassword = DEMO_USERS[i].password; });

let db = { records: [], audit: [] };
function loadDb() { try { if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { db = { records: [], audit: [] }; } }
function saveDb() { try { fs.mkdirSync(DATA_DIR, { recursive: true }); const tmp = DB_FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(db, null, 2)); fs.renameSync(tmp, DB_FILE); } catch (e) { console.error('DB write failed', e); throw e; } }
loadDb();

const sessions = new Map();
function audit(actor, action, recordId, result, detail = '') {
  db.audit.unshift({ id: 'EVT-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2, 5).toUpperCase(), time: new Date().toISOString(), actor, action, recordId: recordId || null, result, detail: String(detail).slice(0, 300) });
  db.audit = db.audit.slice(0, 5000);
  try { saveDb(); } catch {}
}
function parseCookies(req) { const out = {}; (req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim(); }); return out; }
function currentUser(req) { const sid = parseCookies(req).sid; if (!sid) return null; const s = sessions.get(sid); if (!s) return null; if (Date.now() > s.expires) { sessions.delete(sid); return null; } return s.user; }
function send(res, code, obj, type = 'application/json; charset=utf-8') { const body = type.includes('json') ? JSON.stringify(obj) : obj; res.writeHead(code, { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN', 'Referrer-Policy': 'no-referrer' }); res.end(body); }
function readBody(req) { return new Promise((resolve, reject) => { let size = 0; const chunks = []; req.on('data', c => { size += c.length; if (size > MAX_BODY) { reject(new Error('PAYLOAD_TOO_LARGE')); req.destroy(); } else chunks.push(c); }); req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8'))); req.on('error', reject); }); }
function requireAuth(req, res) { const u = currentUser(req); if (!u) { send(res, 401, { error: 'Chưa đăng nhập hoặc phiên đã hết hạn.' }); return null; } return u; }
function requirePerm(req, res, perm) { const u = requireAuth(req, res); if (!u) return null; if (!hasPerm(u.role, perm)) { send(res, 403, { error: `Tài khoản vai trò "${ROLES[u.role]?.label || u.role}" không có quyền "${perm}".` }); return null; } return u; }

function escCsv(v) { const s = String(v ?? '').replace(/"/g, '""'); return `"${s}"`; }

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  try {
    if (p.startsWith('/api/')) {
      if (p === '/api/health') return send(res, 200, { ok: true, app: 'JurisScan AI', time: new Date().toISOString(), mode: 'DEMO — dữ liệu lưu cục bộ, chưa kết nối nguồn xác minh chính thức' });
      if (p === '/api/demo-accounts') return send(res, 200, { demo: true, accounts: users.map(u => ({ username: u.username, password: u._demoPassword, role: u.role, roleLabel: ROLES[u.role].label })) });
      if (p === '/api/login' && req.method === 'POST') {
        const { username, password } = JSON.parse(await readBody(req) || '{}');
        const user = users.find(x => x.username === String(username || '').trim());
        if (!user || hashPw(String(password || ''), user.salt) !== user.hash) { audit(String(username || 'unknown'), 'LOGIN', null, 'failed', 'Sai tên đăng nhập hoặc mật khẩu'); return send(res, 401, { error: 'Tên đăng nhập hoặc mật khẩu không đúng.' }); }
        const sid = crypto.randomBytes(32).toString('hex');
        const publicUser = { username: user.username, name: user.name, role: user.role, roleLabel: ROLES[user.role].label, unit: user.unit, perms: ROLES[user.role].perms };
        sessions.set(sid, { user: publicUser, expires: Date.now() + 8 * 3600 * 1000 });
        audit(user.username, 'LOGIN', null, 'success', '');
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Set-Cookie': `sid=${sid}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${8 * 3600}` });
        return res.end(JSON.stringify({ user: publicUser }));
      }
      if (p === '/api/logout' && req.method === 'POST') { const u = currentUser(req); const sid = parseCookies(req).sid; if (sid) sessions.delete(sid); if (u) audit(u.username, 'LOGOUT', null, 'success', ''); res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Set-Cookie': 'sid=; HttpOnly; Path=/; Max-Age=0' }); return res.end(JSON.stringify({ ok: true })); }
      if (p === '/api/me') { const u = requireAuth(req, res); if (u) return send(res, 200, { user: u }); return; }

      if (p === '/api/analyze' && req.method === 'POST') {
        const u = requirePerm(req, res, 'scan'); if (!u) return;
        const { rawContent, inputMethod, externalFields } = JSON.parse(await readBody(req) || '{}');
        if (typeof rawContent !== 'string' || rawContent.length > 20000) return send(res, 400, { error: 'Nội dung QR không hợp lệ hoặc vượt giới hạn 20.000 ký tự.' });
        // External verification only if configured via env AND caller explicitly passes expected values.
        const hasExt = Boolean(process.env.VERIFICATION_SOURCE_URL) && externalFields && typeof externalFields === 'object';
        const result = analyze(rawContent, ['camera', 'upload', 'manual'].includes(inputMethod) ? inputMethod : 'upload', { hasExternalSource: hasExt, externalFields: hasExt ? externalFields : null });
        result.createdBy = u.username;
        result._preview = true;
        audit(u.username, 'SCAN_QR', result.id, 'preview', `method=${result.inputMethod}, type=${result.dataType}`);
        return send(res, 200, { record: result });
      }
      if (p === '/api/records' && req.method === 'POST') {
        const u = requirePerm(req, res, 'scan'); if (!u) return;
        const body = JSON.parse(await readBody(req) || '{}');
        const record = body.record;
        if (!record || typeof record.rawContent !== 'string') return send(res, 400, { error: 'Thiếu dữ liệu bản ghi hợp lệ.' });
        // Re-run server-side analysis — never trust client-supplied analysis.
        const fresh = analyze(record.rawContent, record.inputMethod, { hasExternalSource: false });
        fresh.id = record.id || fresh.id; fresh.createdBy = u.username; fresh.reviewStatus = 'pending'; fresh.note = '';
        if (db.records.some(r => r.id === fresh.id)) return send(res, 409, { error: 'Bản ghi đã tồn tại.' });
        db.records.unshift(fresh); try { saveDb(); } catch { return send(res, 500, { error: 'Lỗi lưu dữ liệu (database). Bản xem trước vẫn còn trên trình duyệt.' }); }
        audit(u.username, 'CREATE_RECORD', fresh.id, 'success', `type=${fresh.dataType}`);
        return send(res, 201, { record: fresh });
      }
      if (p === '/api/records' && req.method === 'GET') {
        const u = requirePerm(req, res, 'view'); if (!u) return;
        const q = (url.searchParams.get('q') || '').toLowerCase(); const status = url.searchParams.get('status') || ''; const type = url.searchParams.get('type') || '';
        const page = Math.max(1, parseInt(url.searchParams.get('page') || '1')); const size = Math.min(50, Math.max(1, parseInt(url.searchParams.get('size') || '10')));
        let list = db.records.filter(r => (!q || (r.id + r.rawContent + r.docType).toLowerCase().includes(q)) && (!status || r.status === status) && (!type || r.dataType === type));
        const total = list.length; list = list.slice((page - 1) * size, page * size);
        return send(res, 200, { records: list, total, page, size });
      }
      const recMatch = p.match(/^\/api\/records\/([\w-]+)$/);
      if (recMatch && req.method === 'GET') { const u = requirePerm(req, res, 'view'); if (!u) return; const r = db.records.find(x => x.id === recMatch[1]); if (!r) return send(res, 404, { error: 'Không tìm thấy bản ghi.' }); return send(res, 200, { record: r }); }
      if (recMatch && req.method === 'PATCH') {
        const u = requirePerm(req, res, 'review'); if (!u) return;
        const r = db.records.find(x => x.id === recMatch[1]); if (!r) return send(res, 404, { error: 'Không tìm thấy bản ghi.' });
        const body = JSON.parse(await readBody(req) || '{}');
        const changes = [];
        if (typeof body.note === 'string') { r.note = body.note.slice(0, 2000); changes.push('note'); }
        if (['confirmed', 'needs_verification', 'pending'].includes(body.reviewStatus)) { r.reviewStatus = body.reviewStatus; changes.push('reviewStatus=' + body.reviewStatus); }
        if (typeof body.classificationOverride === 'string' && body.classificationOverride.trim()) { r.classificationOverride = body.classificationOverride.trim().slice(0, 200); changes.push('classificationOverride'); }
        r.updatedAt = new Date().toISOString(); r.updatedBy = u.username;
        try { saveDb(); } catch { return send(res, 500, { error: 'Lỗi lưu dữ liệu.' }); }
        audit(u.username, 'UPDATE_RECORD', r.id, 'success', changes.join(', '));
        return send(res, 200, { record: r });
      }
      if (p === '/api/dashboard' && req.method === 'GET') {
        const u = requirePerm(req, res, 'view'); if (!u) return;
        const r = db.records;
        return send(res, 200, { demo: db.records.length === 0, stats: { totalScans: db.audit.filter(a => a.action === 'SCAN_QR').length, totalRecords: r.length, success: r.filter(x => x.status === 'processed').length, needsReview: r.filter(x => x.status === 'needs_review').length, errors: r.filter(x => x.status === 'error' || x.status === 'conflict').length, reportsExported: db.audit.filter(a => a.action === 'EXPORT_REPORT').length }, recent: r.slice(0, 8) });
      }
      if (p === '/api/audit' && req.method === 'GET') { const u = requirePerm(req, res, 'audit'); if (!u) return; return send(res, 200, { events: db.audit.slice(0, 200) }); }
      if (p === '/api/tests') { const u = requireAuth(req, res); if (u) return send(res, 200, { tests: TEST_CASES }); return; }
      if (p === '/api/export.csv' && req.method === 'GET') {
        const u = requirePerm(req, res, 'export'); if (!u) return;
        const rows = [['Ma ban ghi', 'Thoi gian', 'Phuong thuc', 'Loai du lieu', 'Loai tai lieu', 'Trang thai', 'Trang thai xac minh nguon', 'Nguoi tao'], ...db.records.map(r => [r.id, r.createdAt, r.inputMethod, r.dataType, r.docType, r.status, r.verification?.status || '', r.createdBy || ''])];
        audit(u.username, 'EXPORT_REPORT', null, 'success', 'CSV — danh sách bản ghi (không kèm nội dung QR đầy đủ)');
        res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="jurisscan-records.csv"' });
        return res.end(rows.map(r => r.map(escCsv).join(',')).join('\n'));
      }
      const repMatch = p.match(/^\/api\/records\/([\w-]+)\/report$/);
      if (repMatch && req.method === 'GET') {
        const u = requirePerm(req, res, 'export'); if (!u) return;
        const r = db.records.find(x => x.id === repMatch[1]); if (!r) return send(res, 404, { error: 'Không tìm thấy bản ghi.' });
        audit(u.username, 'EXPORT_REPORT', r.id, 'success', 'HTML printable report');
        const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        const html = `<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>Báo cáo ${esc(r.id)}</title><style>body{font-family:Arial,sans-serif;margin:40px;color:#0f172a}h1{color:#0b2545}table{border-collapse:collapse;width:100%}td,th{border:1px solid #cbd5e1;padding:8px;text-align:left}.warn{background:#fff7ed;padding:12px;border:1px solid #fdba74}</style></head><body><h1>JurisScan AI — Báo cáo xử lý thông tin</h1><p><strong>Mã báo cáo:</strong> RPT-${esc(r.id)} · <strong>Ngày tạo:</strong> ${new Date().toLocaleString('vi-VN')}</p><div class="warn">Đây là báo cáo kỹ thuật hỗ trợ xử lý thông tin, KHÔNG phải văn bản pháp lý chính thức và không có giá trị thay thế quyết định của người có thẩm quyền.</div><h2>Thông tin bản ghi</h2><table><tr><th>Mã bản ghi</th><td>${esc(r.id)}</td></tr><tr><th>Thời gian tiếp nhận</th><td>${esc(r.createdAt)}</td></tr><tr><th>Phương thức nhập</th><td>${esc(r.inputMethod)}</td></tr><tr><th>Loại dữ liệu</th><td>${esc(r.dataType)}</td></tr><tr><th>Người thực hiện</th><td>${esc(r.createdBy || '')}</td></tr></table><h2>Trường trích xuất</h2><table><tr><th>Trường</th><th>Giá trị</th><th>Nguồn</th><th>Trạng thái</th></tr>${r.extractedFields.map(f => `<tr><td>${esc(f.label)}</td><td>${esc(f.value)}</td><td>${esc(f.sourceDetail)}</td><td>${esc(f.status)}</td></tr>`).join('') || '<tr><td colspan="4">Không trích xuất được trường nào</td></tr>'}</table><h2>Kiểm tra &amp; cảnh báo</h2><p>Tóm tắt: ${esc(r.summary)}</p><p>Trường thiếu: ${esc(r.missingFields.join('; ') || 'Không phát hiện theo bộ quy tắc')}</p><p>Mâu thuẫn: ${esc(r.conflicts.join('; ') || 'Chưa phát hiện')}</p><p>Xác minh nguồn: ${esc(r.verification.message)}</p><p><em>${esc(r.limitations)}</em></p></body></html>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(html);
      }
      return send(res, 404, { error: 'API không tồn tại.' });
    }

    // Static
    if (p === '/') return fs.createReadStream(path.join(PUBLIC, 'index.html')).pipe(res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }));
    const safe = path.normalize(path.join(PUBLIC, p));
    if (safe.startsWith(PUBLIC) && fs.existsSync(safe) && fs.statSync(safe).isFile()) { res.writeHead(200, { 'Content-Type': MIME[path.extname(safe)] || 'application/octet-stream' }); return fs.createReadStream(safe).pipe(res); }
    // SPA fallback for non-API routes
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return fs.createReadStream(path.join(PUBLIC, 'index.html')).pipe(res);
  } catch (e) {
    console.error(e);
    if (e.message === 'PAYLOAD_TOO_LARGE') return send(res, 413, { error: 'Dữ liệu gửi lên vượt giới hạn cho phép.' });
    return send(res, 500, { error: 'Đã xảy ra lỗi hệ thống. Vui lòng thử lại hoặc liên hệ quản trị viên. Mã lỗi: ERR-500' });
  }
});

server.listen(PORT, '0.0.0.0', () => console.log(`JurisScan AI running at http://0.0.0.0:${PORT}`));

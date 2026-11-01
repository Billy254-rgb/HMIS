// HMIS backend: Express + PostgreSQL. Works on Render (node server) and Vercel (exported app).
const express = require('express'), { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'), { PDFDocument, StandardFonts } = require('pdf-lib'), fs = require('fs'), path = require('path');
const COORDS = require('./claimCoords.json');
const url = process.env.DATABASE_URL;
const pool = new Pool({ connectionString: url, ssl: url && !/localhost|127\.0\.0\.1/.test(url) ? { rejectUnauthorized: false } : false });
const q = (s, p) => pool.query(s, p).then(r => r.rows);
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const SCHEMA = `
create table if not exists users(id serial primary key,username text unique not null,password_hash text not null,name text,role text not null,reg_no text default '',active boolean default true);
create table if not exists settings(key text primary key,value text);
create table if not exists drugs(id serial primary key,name text,price numeric,stock int default 0,active boolean default true);
create table if not exists tests(id serial primary key,name text,price numeric,ref text default '',active boolean default true);
create table if not exists patients(id serial primary key,patient_no text,last text,first text,middle text default '',sex text,dob date,national_id text default '',phone text default '',nok text default '',nok_phone text default '',residence text default '',payer text,insurer text,scheme text,ptype text,principal_name text default '',principal_id text default '',relationship text,member_no text default '',other_ins text default '',created_at timestamptz default now());
create table if not exists visits(id serial primary key,visit_no text,claim_no text,patient_id int references patients(id),doctor_id int,visit_type text,kind text,new_return text,status text,consult_fee numeric default 0,preauth_no text default '',vitals jsonb default '{}',consult jsonb default '{}',created_at timestamptz default now(),discharged_at timestamptz);
create table if not exists orders(id serial primary key,visit_id int references visits(id),type text,item_id int,name text,qty int default 1,price numeric,instructions text default '',status text default 'ordered',result text default '',flag text default '',updated_at timestamptz default now());
create table if not exists payments(id serial primary key,visit_id int references visits(id),amount numeric,method text,ref text default '',created_at timestamptz default now());
create table if not exists audit(id serial primary key,user_name text,action text,at timestamptz default now());`;
const DRUGS = 'Paracetamol 500mg tab|5;Amoxicillin 500mg cap|15;Amoxicillin/Clavulanate 625mg tab|60;Azithromycin 500mg tab|120;Ciprofloxacin 500mg tab|20;Metronidazole 400mg tab|8;Cotrimoxazole 480mg tab|6;Doxycycline 100mg cap|10;Ibuprofen 400mg tab|6;Diclofenac 50mg tab|8;Artemether/Lumefantrine 20/120 (AL) pack|150;Omeprazole 20mg cap|10;ORS sachet|30;Zinc 20mg tab|10;Salbutamol inhaler|350;Amlodipine 5mg tab|10;Enalapril 5mg tab|8;Metformin 500mg tab|5;Glibenclamide 5mg tab|5;Cetirizine 10mg tab|5;Loratadine 10mg tab|8;Albendazole 400mg tab|30;Ferrous sulphate 200mg tab|3;Folic acid 5mg tab|2;Prednisolone 5mg tab|4;Fluconazole 150mg cap|60;Hydrochlorothiazide 25mg tab|5;Atenolol 50mg tab|8;Vitamin C 100mg tab|3;Diazepam 5mg tab|10';
const TESTS = 'Full blood count (CBC)|600|WBC 4-11 x10^9/L; Hb 12-17 g/dL;Malaria blood slide|200|Negative;Malaria mRDT|250|Negative;Urinalysis|150|;Random blood sugar|150|3.9-7.8 mmol/L;Fasting blood sugar|150|3.9-5.5 mmol/L;HbA1c|900|<6.5 %;Liver function tests|1500|;Renal function tests|1200|;Lipid profile|1500|;Widal test|400|;H. pylori antigen|800|Negative;HIV test|200|Non-reactive;Hepatitis B surface antigen|400|Negative;Pregnancy test|150|Negative;Stool microscopy|200|;ESR|250|0-20 mm/hr;Blood group|300|;VDRL|300|Non-reactive;Urine culture|1200|;Haemoglobin|200|12-17 g/dL;Creatinine|500|60-110 umol/L;Uric acid|400|;C-reactive protein|700|<6 mg/L;Sputum AFB|300|Negative';

async function init() {
  await q(SCHEMA);
  if (!(await q('select 1 from users limit 1')).length) await q("insert into users(username,password_hash,name,role) values('admin',$1,'Administrator','admin')", [bcrypt.hashSync('admin', 10)]);
  const S = { facility_name: 'MY FACILITY', hpin: '', address: '', phone: '', consult_fee: '1000', copay_pct: '0' };
  for (const k in S) await q('insert into settings values($1,$2) on conflict do nothing', [k, S[k]]);
  if (!(await q('select 1 from drugs limit 1')).length) for (const d of DRUGS.split(';')) { const [n, p] = d.split('|'); await q('insert into drugs(name,price,stock) values($1,$2,500)', [n, p]); }
  if (!(await q('select 1 from tests limit 1')).length) for (const t of TESTS.split(';')) { const [n, p, r] = t.split('|'); await q('insert into tests(name,price,ref) values($1,$2,$3)', [n, p, r]); }
}
const ready = url ? init() : Promise.reject(new Error('DATABASE_URL is not set. Add it in Render > Environment.'));
ready.catch(e => console.error('DB init failed:', e.message));
const settings = async () => Object.fromEntries((await q('select * from settings')).map(r => [r.key, r.value]));
const log = (req, a) => q('insert into audit(user_name,action) values($1,$2)', [req.user?.username || '-', a]).catch(() => {});

const app = express();
app.use(express.json(), cookieParser());
app.use((req, res, n) => ready.then(() => n()).catch(e => res.status(500).json({ error: 'DB init failed: ' + e.message })));
app.use(express.static(path.join(__dirname, 'public')));
const wrap = f => (req, res) => f(req, res).catch(e => { console.error(e); res.status(500).json({ error: e.message }); });
const auth = (...roles) => (req, res, next) => {
  try { const u = jwt.verify(req.cookies.t, SECRET); if (roles.length && u.role !== 'admin' && !roles.includes(u.role)) return res.status(403).json({ error: 'Forbidden' }); req.user = u; next(); }
  catch { res.status(401).json({ error: 'Login required' }); }
};
const attempts = {};

// ---------- auth ----------
app.post('/api/login', wrap(async (req, res) => {
  const { username, password } = req.body, k = req.ip;
  if ((attempts[k] || 0) >= 10) return res.status(429).json({ error: 'Too many attempts, wait 10 minutes' });
  const u = (await q('select * from users where username=$1 and active', [String(username).toLowerCase()]))[0];
  if (!u || !bcrypt.compareSync(password || '', u.password_hash)) { attempts[k] = (attempts[k] || 0) + 1; setTimeout(() => delete attempts[k], 600000); return res.status(401).json({ error: 'Wrong username or password' }); }
  delete attempts[k];
  const t = jwt.sign({ id: u.id, username: u.username, role: u.role, name: u.name }, SECRET, { expiresIn: '10h' });
  res.cookie('t', t, { httpOnly: true, sameSite: 'strict', secure: !!process.env.RENDER || !!process.env.VERCEL, maxAge: 36e6 });
  res.json({ ok: 1 });
}));
app.post('/api/logout', (req, res) => { res.clearCookie('t'); res.json({ ok: 1 }); });
app.get('/api/me', auth(), wrap(async (req, res) => {
  const u = (await q('select id,username,name,role,password_hash from users where id=$1', [req.user.id]))[0];
  res.json({ id: u.id, username: u.username, name: u.name, role: u.role, weak: bcrypt.compareSync('admin', u.password_hash) });
}));
app.post('/api/password', auth(), wrap(async (req, res) => {
  if (!req.body.password || req.body.password.length < 6) return res.status(400).json({ error: 'Minimum 6 characters' });
  await q('update users set password_hash=$1 where id=$2', [bcrypt.hashSync(req.body.password, 10), req.user.id]); res.json({ ok: 1 });
}));

// ---------- admin ----------
app.get('/api/users', auth('admin'), wrap(async (req, res) => res.json(await q('select id,username,name,role,reg_no,active from users order by id'))));
app.post('/api/users', auth('admin'), wrap(async (req, res) => {
  const b = req.body; if (!b.username || !b.password || !b.role) return res.status(400).json({ error: 'Username, password and role required' });
  await q('insert into users(username,password_hash,name,role,reg_no) values($1,$2,$3,$4,$5)', [b.username.toLowerCase(), bcrypt.hashSync(b.password, 10), b.name, b.role, b.reg_no || '']);
  log(req, 'create user ' + b.username); res.json({ ok: 1 });
}));
app.put('/api/users/:id', auth('admin'), wrap(async (req, res) => {
  const b = req.body; await q('update users set name=$1,role=$2,reg_no=$3,active=$4 where id=$5', [b.name, b.role, b.reg_no || '', b.active !== 'false' && b.active !== false, req.params.id]);
  if (b.password) await q('update users set password_hash=$1 where id=$2', [bcrypt.hashSync(b.password, 10), req.params.id]);
  log(req, 'update user ' + req.params.id); res.json({ ok: 1 });
}));
app.get('/api/settings', auth(), wrap(async (req, res) => res.json(await settings())));
app.put('/api/settings', auth('admin'), wrap(async (req, res) => {
  for (const k in req.body) await q('insert into settings values($1,$2) on conflict(key) do update set value=$2', [k, String(req.body[k])]); log(req, 'update settings'); res.json({ ok: 1 });
}));
app.get('/api/audit', auth('admin'), wrap(async (req, res) => res.json(await q('select * from audit order by id desc limit 100'))));
app.get('/api/report', auth('admin'), wrap(async (req, res) => res.json({
  revenue: await q("select to_char(created_at,'YYYY-MM-DD') day,method,sum(amount) total from payments group by 1,2 order by 1 desc limit 30"),
  visits: await q("select p.payer,p.insurer,count(*)::int n from visits v join patients p on p.id=v.patient_id group by 1,2"),
  claims: await q("select count(*)::int n from visits v join patients p on p.id=v.patient_id where p.insurer='POMSF-SHA' and v.status='discharged'")
})));
app.get('/api/catalog', auth(), wrap(async (req, res) => res.json({ drugs: await q('select * from drugs where active order by name'), tests: await q('select * from tests where active order by name') })));
const tbl = t => ['drugs', 'tests'].includes(t);
app.post('/api/cat/:t', auth('admin', 'pharmacy'), wrap(async (req, res) => {
  if (!tbl(req.params.t)) return res.sendStatus(404); const b = req.body;
  if (req.params.t === 'drugs') await q('insert into drugs(name,price,stock) values($1,$2,$3)', [b.name, b.price, b.stock || 0]); else await q('insert into tests(name,price,ref) values($1,$2,$3)', [b.name, b.price, b.ref || '']);
  res.json({ ok: 1 });
}));
app.put('/api/cat/:t/:id', auth('admin', 'pharmacy'), wrap(async (req, res) => {
  if (!tbl(req.params.t)) return res.sendStatus(404); const b = req.body;
  if (req.params.t === 'drugs') await q('update drugs set name=$1,price=$2,stock=$3,active=$4 where id=$5', [b.name, b.price, b.stock, b.active, req.params.id]); else await q('update tests set name=$1,price=$2,ref=$3,active=$4 where id=$5', [b.name, b.price, b.ref, b.active, req.params.id]);
  res.json({ ok: 1 });
}));

// ---------- patients ----------
app.get('/api/doctors', auth(), wrap(async (req, res) => res.json(await q("select id,name,reg_no from users where role='doctor' and active order by name"))));
app.get('/api/patients', auth(), wrap(async (req, res) => {
  const terms = String(req.query.q || '').trim().split(/\s+/).filter(Boolean); if (!terms.length) return res.json(await q('select * from patients order by id desc limit 20'));
  const w = terms.map((_, i) => `concat_ws(' ',first,middle,last,phone,national_id,member_no,patient_no) ilike $${i + 1}`).join(' and ');
  res.json(await q(`select * from patients where ${w} order by id desc limit 30`, terms.map(t => '%' + t + '%')));
}));
const PF = ['last', 'first', 'middle', 'sex', 'dob', 'national_id', 'phone', 'nok', 'nok_phone', 'residence', 'payer', 'insurer', 'scheme', 'ptype', 'principal_name', 'principal_id', 'relationship', 'member_no', 'other_ins'];
function cleanPatient(b) {
  const p = {}; PF.forEach(k => p[k] = b[k] === '' || b[k] === undefined ? (k === 'dob' ? null : '') : b[k]);
  if (p.payer === 'Cash') { p.insurer = 'Cash'; p.scheme = 'Cash'; }
  if (p.ptype === 'Self') { p.relationship = 'Self'; p.principal_name = ''; p.principal_id = ''; }
  ['last', 'first', 'middle'].forEach(k => p[k] = String(p[k]).toUpperCase());
  return p;
}
app.post('/api/patients', auth('receptionist'), wrap(async (req, res) => {
  const p = cleanPatient(req.body); if (!p.first || !p.last) return res.status(400).json({ error: 'First and last name required' });
  if (p.payer === 'Insurance' && !p.member_no) return res.status(400).json({ error: 'Member number required for insurance' });
  const dup = p.national_id || p.member_no ? await q("select patient_no from patients where (national_id<>'' and national_id=$1) or (member_no<>'' and member_no=$2)", [p.national_id, p.member_no]) : [];
  if (dup.length) return res.status(409).json({ error: 'Possible duplicate: ' + dup[0].patient_no + ' already has this ID/member number' });
  const r = (await q(`insert into patients(${PF.join(',')}) values(${PF.map((_, i) => '$' + (i + 1)).join(',')}) returning *`, PF.map(k => p[k])))[0];
  r.patient_no = 'P' + String(r.id).padStart(6, '0'); await q('update patients set patient_no=$1 where id=$2', [r.patient_no, r.id]); log(req, 'register patient ' + r.patient_no); res.json(r);
}));
app.put('/api/patients/:id', auth('receptionist'), wrap(async (req, res) => {
  const p = cleanPatient(req.body);
  const r = (await q(`update patients set ${PF.map((k, i) => k + '=$' + (i + 1)).join(',')} where id=$${PF.length + 1} returning *`, [...PF.map(k => p[k]), req.params.id]))[0];
  log(req, 'edit patient ' + r.patient_no); res.json(r);
}));

// ---------- visits ----------
async function addOrder(vid, type, itemId, qty, instr) {
  const it = (await q(`select name,price from ${type === 'lab' ? 'tests' : 'drugs'} where id=$1`, [itemId]))[0];
  await q('insert into orders(visit_id,type,item_id,name,qty,price,instructions) values($1,$2,$3,$4,$5,$6,$7)', [vid, type, itemId, it.name, qty || 1, it.price, instr || '']);
}
async function full(id) {
  const v = (await q(`select v.*,p.patient_no,p.last,p.first,p.middle,p.sex,p.dob,p.phone,p.residence,p.payer,p.insurer,p.scheme,p.ptype,p.relationship,p.member_no,p.other_ins,p.national_id,d.name doc_name,d.reg_no doc_reg from visits v join patients p on p.id=v.patient_id left join users d on d.id=v.doctor_id where v.id=$1`, [id]))[0];
  if (!v) return null;
  v.orders = await q('select * from orders where visit_id=$1 order by id', [id]); v.payments = await q('select * from payments where visit_id=$1 order by id', [id]);
  const cp = v.payer === 'Insurance' ? +(await settings()).copay_pct : 100;
  v.total = +v.consult_fee + v.orders.reduce((s, o) => s + o.qty * +o.price, 0); v.patient_due = Math.round(v.total * cp / 100); v.insurer_due = v.total - v.patient_due;
  v.paid = v.payments.reduce((s, p) => s + +p.amount, 0); v.balance = v.patient_due - v.paid; v.pending = v.orders.filter(o => o.status !== 'done').length; v.name = v.first + ' ' + v.last;
  return v;
}
app.post('/api/visits', auth('receptionist'), wrap(async (req, res) => {
  const b = req.body, direct = b.kind !== 'normal'; if (!b.patient_id) return res.status(400).json({ error: 'Select patient' });
  if (!direct && !b.doctor_id) return res.status(400).json({ error: 'Select a doctor' });
  if (direct && !(b.items || []).length) return res.status(400).json({ error: 'Select at least one item' });
  const fee = direct ? 0 : +(await settings()).consult_fee, n = (await q('select count(*)::int c from visits where patient_id=$1', [b.patient_id]))[0].c;
  const v = (await q('insert into visits(patient_id,doctor_id,visit_type,kind,new_return,status,consult_fee,preauth_no) values($1,$2,$3,$4,$5,$6,$7,$8) returning id', [b.patient_id, b.doctor_id || null, b.visit_type || 'Outpatient', b.kind, n ? 'RETURN' : 'NEW', direct ? 'direct' : 'triage', fee, b.preauth_no || '']))[0];
  await q("update visits set visit_no='V'||lpad(id::text,6,'0'),claim_no='CLM-'||extract(year from now())::int||'-'||lpad(id::text,6,'0') where id=$1", [v.id]);
  for (const it of b.items || []) if (+it.qty > 0) await addOrder(v.id, it.type, it.item_id, +it.qty);
  res.json(await full(v.id));
}));
app.get('/api/queue', auth(), wrap(async (req, res) => {
  const st = req.query.stage; let w;
  if (st === 'triage') w = "status='triage'"; else if (st === 'doctor') w = "status='doctor'" + (req.user.role === 'doctor' ? ' and doctor_id=' + +req.user.id : '');
  else if (st === 'discharge') w = "status in ('consulted','direct')"; else w = "status='discharged' and discharged_at>now()-interval '3 days'";
  const ids = await q(`select id from visits where ${w} order by id`); const out = [];
  for (const r of ids) { const v = await full(r.id); if (st !== 'discharge' || v.pending === 0) out.push(v); }
  res.json(out);
}));
app.get('/api/visits/:id', auth(), wrap(async (req, res) => res.json(await full(req.params.id))));
app.put('/api/visits/:id/vitals', auth('nurse'), wrap(async (req, res) => {
  const b = req.body; await q("update visits set vitals=$1,status='doctor',doctor_id=coalesce($2,doctor_id) where id=$3 and status in ('triage','doctor')", [b.vitals, b.doctor_id || null, req.params.id]); log(req, 'vitals visit ' + req.params.id); res.json({ ok: 1 });
}));
app.put('/api/visits/:id/consult', auth('doctor'), wrap(async (req, res) => {
  await q('update visits set consult=$1,status=case when $2 then $3 else status end where id=$4', [req.body.consult, !!req.body.complete, 'consulted', req.params.id]); res.json({ ok: 1 });
}));
app.post('/api/visits/:id/orders', auth('doctor'), wrap(async (req, res) => { const b = req.body; await addOrder(req.params.id, b.type, b.item_id, +b.qty, b.instructions); res.json({ ok: 1 }); }));
app.get('/api/orders', auth('lab', 'pharmacy'), wrap(async (req, res) => res.json(await q("select o.*,v.visit_no,v.kind,p.first||' '||p.last pname,p.sex from orders o join visits v on v.id=o.visit_id join patients p on p.id=v.patient_id where o.type=$1 and (o.status<>'done' or o.updated_at>now()-interval '1 day') order by o.status='done',o.id", [req.query.type]))));
app.put('/api/orders/:id', auth('lab', 'pharmacy'), wrap(async (req, res) => {
  const b = req.body, o = (await q('select * from orders where id=$1', [req.params.id]))[0];
  if (b.status === 'done' && o.status !== 'done' && o.type === 'drug') {
    const s = await q('update drugs set stock=stock-$1 where id=$2 and stock>=$1 returning id', [o.qty, o.item_id]); if (!s.length) return res.status(400).json({ error: 'Insufficient stock' });
  }
  await q('update orders set status=$1,result=coalesce($2,result),flag=coalesce($3,flag),updated_at=now() where id=$4', [b.status, b.result, b.flag, o.id]); res.json({ ok: 1 });
}));
app.post('/api/visits/:id/pay', auth('receptionist'), wrap(async (req, res) => {
  const b = req.body; if (!(+b.amount > 0)) return res.status(400).json({ error: 'Invalid amount' });
  await q('insert into payments(visit_id,amount,method,ref) values($1,$2,$3,$4)', [req.params.id, b.amount, b.method || 'Cash', b.ref || '']); log(req, 'payment visit ' + req.params.id); res.json({ ok: 1 });
}));
app.post('/api/visits/:id/discharge', auth('receptionist'), wrap(async (req, res) => {
  const v = await full(req.params.id); if (v.pending) return res.status(400).json({ error: 'Lab/pharmacy orders still pending' });
  if (v.balance > 0) return res.status(400).json({ error: 'Outstanding patient balance: KES ' + v.balance });
  await q("update visits set status='discharged',discharged_at=now() where id=$1", [v.id]); log(req, 'discharge visit ' + v.visit_no); res.json({ ok: 1 });
}));

// ---------- documents ----------
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const money = n => 'KES ' + Number(n).toLocaleString();
function page(fac, title, body) {
  return `<!doctype html><meta charset=utf-8><title>${title}</title><style>body{font:14px Arial;max-width:800px;margin:20px auto;color:#111}table{width:100%;border-collapse:collapse;margin:10px 0}td,th{border:1px solid #999;padding:5px;text-align:left}h1,h2{margin:4px 0}.r{text-align:right}button{padding:8px 16px}@media print{button{display:none}}</style>
<button onclick=print()>Print / Save as PDF</button><h1>${esc(fac.facility_name)}</h1><div>${esc(fac.address)} ${esc(fac.phone)} | HPIN: ${esc(fac.hpin)}</div><h2>${title}</h2>${body}`;
}
const head = v => `<table><tr><td>Patient: <b>${esc(v.name)}</b> (${esc(v.patient_no)})</td><td>Visit: ${esc(v.visit_no)}</td></tr><tr><td>Sex/DOB: ${esc(v.sex)} ${v.dob ? String(v.dob).slice(0, 10) : ''}</td><td>Date: ${new Date(v.created_at).toLocaleDateString()}</td></tr><tr><td>Payer: ${esc(v.payer)} ${v.payer === 'Insurance' ? esc(v.insurer + ' / ' + v.scheme + ' / ' + v.member_no) : ''}</td><td>Phone: ${esc(v.phone)}</td></tr></table>`;
app.get('/api/visits/:id/invoice', auth(), wrap(async (req, res) => {
  const v = await full(req.params.id), f = await settings(); const lines = [];
  if (+v.consult_fee) lines.push(['Consultation', 1, +v.consult_fee]); v.orders.forEach(o => lines.push([o.name, o.qty, +o.price]));
  res.send(page(f, 'INVOICE', head(v) + `<table><tr><th>Item</th><th>Qty</th><th class=r>Unit</th><th class=r>Amount</th></tr>${lines.map(l => `<tr><td>${esc(l[0])}</td><td>${l[1]}</td><td class=r>${l[2]}</td><td class=r>${l[1] * l[2]}</td></tr>`).join('')}
<tr><td colspan=3 class=r><b>Total</b></td><td class=r><b>${money(v.total)}</b></td></tr><tr><td colspan=3 class=r>Insurer share</td><td class=r>${money(v.insurer_due)}</td></tr><tr><td colspan=3 class=r>Patient share</td><td class=r>${money(v.patient_due)}</td></tr>
${v.payments.map(p => `<tr><td colspan=3 class=r>Paid ${esc(p.method)} ${esc(p.ref)} (${new Date(p.created_at).toLocaleDateString()})</td><td class=r>${money(p.amount)}</td></tr>`).join('')}<tr><td colspan=3 class=r><b>Patient balance</b></td><td class=r><b>${money(v.balance)}</b></td></tr></table>`));
}));
app.get('/api/visits/:id/case', auth(), wrap(async (req, res) => {
  const v = await full(req.params.id), f = await settings(), c = v.consult || {}, vt = v.vitals || {}; const row = (a, b) => `<tr><td width=30%><b>${a}</b></td><td>${esc(b)}</td></tr>`;
  res.send(page(f, 'CASE SUMMARY', head(v) + `<h3>Vitals</h3><table>${Object.entries(vt).map(([k, x]) => row(k, x)).join('')}</table><h3>Consultation</h3><table>${[['Complaints', c.complaints], ['History', c.hpi], ['Examination', c.exam], ['Admission diagnosis', c.adm_dx], ['Final diagnosis', c.dx], ['ICD-11', c.icd], ['Procedures', c.procedures], ['Disposition', c.disposition], ['Referral out', c.ref_out_inst], ['Plan', c.plan]].map(a => row(...a)).join('')}</table>
<h3>Investigations & medication</h3><table>${v.orders.map(o => row(o.type === 'lab' ? 'Lab: ' + o.name : 'Drug: ' + o.name + ' x' + o.qty, o.type === 'lab' ? o.result + ' ' + o.flag : o.instructions)).join('')}</table><p>Doctor: ${esc(v.doc_name)} Reg: ${esc(v.doc_reg)} Signature: ____________</p>`));
}));

function claimData(v, f) {
  const c = v.consult || {}, d = x => x ? new Date(x).toISOString().slice(0, 10) : '', first = String(c.icd || '').split(/[,;]/)[0].trim();
  return {
    claim_no: v.claim_no, hpin: f.hpin, facility: f.facility_name, last: v.last, first: v.first, middle: v.middle, member_no: v.member_no, residence: v.residence, other_ins: v.other_ins || 'NO', relationship: v.relationship,
    ref_in_no: c.referral_in ? '' : 'NO', ref_in_name: c.referral_in || '', visit_type: v.visit_type, adm_date: d(c.adm_date || v.created_at), opip: v.visit_no, new_return: v.new_return, dis_date: d(c.dis_date || v.discharged_at || new Date()),
    physician: `${v.doc_name || ''} ${v.doc_reg || ''}`.trim(), accommodation: v.visit_type === 'Inpatient' ? c.accommodation : '', disposition: c.disposition, ref_out_inst: c.ref_out_inst || 'N/A', ref_out_reason: c.ref_out_reason || 'N/A',
    adm_dx: c.adm_dx, dx: c.dx, icd: c.icd, procedures: c.procedures, proc_date: d(c.procedure_date), unforeseen: c.unforeseen, p_names: v.name, amount: v.insurer_due, today: d(new Date()),
    row: [d(c.adm_date || v.created_at), d(c.dis_date || v.discharged_at || new Date()), c.case_code, first, c.dx, v.preauth_no, v.total, v.insurer_due]
  };
}
const REQ = { hpin: 'Facility HPIN (Admin > Settings)', member_no: 'SHA member number', residence: 'Residence', relationship: 'Relationship to principal', adm_dx: 'Admission diagnosis', dx: 'Discharge diagnosis', icd: 'ICD-11 code', disposition: 'Disposition', physician: 'Doctor name', case_code: 'SHA case code' };
app.get('/api/visits/:id/claim', auth('receptionist'), wrap(async (req, res) => {
  const v = await full(req.params.id), f = await settings();
  if (v.insurer !== 'POMSF-SHA') return res.status(400).json({ error: 'Claim form is only for POMSF-SHA patients' });
  const d = claimData(v, f); d.case_code = (v.consult || {}).case_code; const miss = Object.keys(REQ).filter(k => !d[k]).map(k => REQ[k]);
  if (v.doc_name && !v.doc_reg) miss.push('Doctor registration number'); if (v.visit_type === 'Inpatient' && !d.accommodation) miss.push('Type of accommodation');
  if (miss.length && !req.query.force) return res.status(422).json({ missing: miss });
  const pdf = await PDFDocument.load(fs.readFileSync(path.join(__dirname, 'forms', 'claim_form.pdf'))), font = await pdf.embedFont(StandardFonts.Helvetica), pages = pdf.getPages();
  const draw = (p, x, y, t, size = 9) => { const pg = pages[p], s = pg.getWidth() / 920; pg.drawText(String(t).toUpperCase(), { x: x * s, y: pg.getHeight() - y * s - 3, size, font }); };
  for (const c of COORDS.fields) {
    const val = d[c.k]; if (val === undefined || val === null || val === '') continue; if (c.eq && val !== c.eq) continue;
    draw(c.p, c.x, c.y, c.tick ? 'X' : String(val).slice(0, c.max || 40), c.tick ? 11 : 9);
  }
  const T = COORDS.table; d.row.forEach((x, i) => { if (x !== undefined && x !== null && x !== '') draw(T.p, T.xs[i], T.ys[0], String(x).slice(0, T.max[i]), 7); });
  draw(T.p, T.totalXs[0], T.totalY, v.total, 7); draw(T.p, T.totalXs[1], T.totalY, v.insurer_due, 7);
  res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', `inline; filename="SHA_claim_${v.visit_no}.pdf"`); res.send(Buffer.from(await pdf.save()));
}));

module.exports = app; module.exports.claimData = claimData;
if (require.main === module) app.listen(process.env.PORT || 3000, () => console.log('HMIS running'));

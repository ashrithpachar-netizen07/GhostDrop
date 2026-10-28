const express=require('express'),multer=require('multer'),{createClient}=require('@libsql/client'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),crypto=require('crypto'),fs=require('fs'),path=require('path'),helmet=require('helmet'),rateLimit=require('express-rate-limit'),cookie=require('cookie-parser');
const DATA=process.env.DATA_DIR||path.join(__dirname,'data');fs.mkdirSync(DATA,{recursive:true});
const SECRET=process.env.JWT_SECRET||(()=>{const f=path.join(DATA,'.secret');if(!fs.existsSync(f))fs.writeFileSync(f,crypto.randomBytes(32).toString('hex'));return fs.readFileSync(f,'utf8')})();
const MAX_FILE=10*1024*1024,QUOTA=50*1024*1024,BLOCK=/\.(exe|msi|bat|cmd|com|scr|js|jse|vbs|vbe|wsf|ps1|sh|jar|html?|xhtml?|svg|php|dll|apk|py|pl|rb|lnk|hta|reg|jsp|aspx?|swf|cpl|inf)$/i;
// Turso (hosted SQLite, persistent) in prod; local file DB for dev/tests
const db=createClient({url:process.env.TURSO_DATABASE_URL||'file:'+path.join(DATA,'db.sqlite'),authToken:process.env.TURSO_AUTH_TOKEN});
const Q=async(sql,args=[])=>(await db.execute({sql,args})).rows,one=async(sql,args)=>(await Q(sql,args))[0],run=(sql,args=[])=>db.execute({sql,args});
const EMAIL=/^[a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9])?@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/,RESERVED=/@(example\.(com|net|org)|[^@]*\.(test|invalid|localhost|example))$/;
const normEmail=v=>typeof v==='string'?v.normalize('NFKC').trim().toLowerCase():'';
const validEmail=e=>e.length<=254&&EMAIL.test(e)&&!e.includes('..')&&!RESERVED.test(e);
const canon=e=>{let[l,d]=e.split('@');if(d==='googlemail.com')d='gmail.com';l=l.split('+')[0];if(d==='gmail.com')l=l.replace(/\./g,'');return l+'@'+d};
const COMMON=new Set(['password1','12345678','123456789','qwerty123','iloveyou1','password123','abc12345','11111111','1q2w3e4r','letmein123']);
const pwErr=p=>typeof p!=='string'?'Password required':p.length<8||Buffer.byteLength(p)>72?'Password must be 8–72 characters':!/[a-z]/i.test(p)||!/\d/.test(p)?'Password needs at least one letter and one number':COMMON.has(p.toLowerCase())?'That password is too common':null;
const pid=v=>/^\d{1,15}$/.test(v)?Number(v):null;
const ready=(async()=>{await db.batch([
 'create table if not exists users(id integer primary key,email text unique,pw text,canon text)',
 'create table if not exists files(id integer primary key,user_id int,name text,size int,data blob,deleted int default 0,created int)',
 'create table if not exists links(id integer primary key,file_id int,hash text unique,expires int,max_dl int,pw text,downloads int default 0,revoked int default 0,created int)'],'write');
 for(const c of ['canon text','verified int','vhash text','vexp int'])try{await run('alter table users add column '+c)}catch{}
 await run('create unique index if not exists users_canon on users(canon)');
 for(const u of await Q('select id,email from users where canon is null'))try{await run('update users set canon=? where id=?',[canon(u.email),u.id])}catch{}
})();
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const SIG=[[0x4d,0x5a],[0x7f,0x45,0x4c,0x46],[0x23,0x21],[0xca,0xfe,0xba,0xbe],[0xcf,0xfa,0xed,0xfe]];
const dangerous=b=>{const h=b.subarray(0,512);return SIG.some(g=>g.every((c,i)=>h[i]===c))||/^(<\?php|<html|<svg|<script|<!doctype)/.test(h.toString('latin1').trimStart().toLowerCase())};
const fails=new Map(),DUMMY=bcrypt.hashSync('x',10);
const locked=k=>{const f=fails.get(k);if(f&&Date.now()-f.t>=9e5){fails.delete(k);return false}return !!f&&f.n>=5};
const fail=k=>fails.set(k,{n:(fails.get(k)||{n:0}).n+1,t:Date.now()});
const app=express();app.set('trust proxy',1);
app.use(helmet(),express.json({limit:'10kb'}),cookie(),express.static(path.join(__dirname,'public')));
app.get('/healthz',(q,s)=>s.send('ok'));
app.use('/api',(q,s,n)=>q.method==='GET'||q.get('x-requested-with')==='ghostdrop'?n():s.status(403).json({error:'Bad request origin'}));
const lim=(m,n)=>rateLimit({windowMs:m*60000,limit:process.env.NODE_ENV==='test'?1e4:n,message:{error:'Too many requests, slow down'}});
const auth=(q,s,n)=>{try{q.uid=jwt.verify(q.cookies.t,SECRET).uid;n()}catch{s.status(401).json({error:'Please log in'})}};
const sign=(s,id)=>s.cookie('t',jwt.sign({uid:Number(id)},SECRET,{expiresIn:'7d'}),{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:6048e5});
const used=async u=>Number((await one('select coalesce(sum(size),0) n from files where user_id=? and deleted=0',[u])).n);
// ---- email verification (Brevo HTTP API; free Render blocks SMTP ports)
const TOK=new Map(),cool=new Map();
if(process.env.NODE_ENV==='test')app.get('/api/_test/token',(q,s)=>s.json({token:TOK.get(String(q.query.email||'').toLowerCase())}));
const issue=async(uid,to)=>{const t=crypto.randomBytes(24).toString('base64url');
 await run('update users set vhash=?,vexp=? where id=?',[sha(t),Date.now()+864e5,uid]);
 const link=`${process.env.BASE_URL||process.env.RENDER_EXTERNAL_URL||'http://localhost:'+(process.env.PORT||3000)}/verify/${t}`;
 if(process.env.NODE_ENV==='test')TOK.set(to,t);
 if(!process.env.BREVO_API_KEY||!process.env.MAIL_FROM){if(process.env.NODE_ENV==='production')throw new Error('BREVO_API_KEY / MAIL_FROM not set');console.log('[dev] verify link:',link);return}
 const r=await fetch('https://api.brevo.com/v3/smtp/email',{method:'POST',headers:{'api-key':process.env.BREVO_API_KEY,'content-type':'application/json',accept:'application/json'},
  body:JSON.stringify({sender:{name:'Ghostdrop',email:process.env.MAIL_FROM},to:[{email:to}],subject:'Confirm your Ghostdrop account',
   htmlContent:`<div style="font-family:sans-serif"><h2>👻 Ghostdrop</h2><p>Confirm your email to activate your account:</p><p><a href="${link}" style="background:#c6ff3d;color:#0d0f14;padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:bold">Confirm email</a></p><p>This link expires in 24 hours. If you didn't sign up, ignore this email.</p></div>`})});
 if(!r.ok)throw new Error('Brevo '+r.status+' '+await r.text())};
setInterval(()=>run('delete from users where verified=0 and vexp<?',[Date.now()]).catch(()=>{}),36e5).unref();
// ---- auth
app.post('/api/register',lim(15,20),async(q,s)=>{const b=q.body||{},e=normEmail(b.email),pe=pwErr(b.password);
 if(!validEmail(e))return s.status(400).json({error:'Please enter a valid email address'});
 if(pe)return s.status(400).json({error:pe});
 const c=canon(e),ex=await one('select id,verified from users where canon=? or email=?',[c,e]),h=bcrypt.hashSync(b.password,10),dup=()=>s.status(409).json({error:'An account with this email already exists'});
 let id;
 if(ex){if(ex.verified!==0)return dup();await run('update users set email=?,pw=?,canon=? where id=?',[e,h,c,ex.id]);id=ex.id}  // unverified accounts can be reclaimed by the real owner
 else try{id=Number((await run('insert into users(email,pw,canon,verified) values(?,?,?,0)',[e,h,c])).lastInsertRowid)}catch(x){if(/UNIQUE|constraint/i.test(String(x.message)))return dup();throw x}
 try{await issue(id,e)}catch(x){console.error(x);return s.status(502).json({error:'Could not send the confirmation email. Please try again.'})}
 s.json({ok:1,verify:true})});
app.post('/api/verify',lim(15,30),async(q,s)=>{const t=(q.body||{}).token;
 const u=typeof t==='string'&&t.length<100?await one('select id from users where vhash=? and vexp>?',[sha(t),Date.now()]):null;
 if(!u)return s.status(400).json({error:'This confirmation link is invalid or has expired. Sign up again to get a new one.'});
 await run('update users set verified=1,vhash=null,vexp=null where id=?',[u.id]);sign(s,u.id);s.json({ok:1})});
app.post('/api/resend',lim(15,10),async(q,s)=>{const e=normEmail((q.body||{}).email),u=e&&await one('select id,verified from users where email=?',[e]);
 if(u&&u.verified===0&&!(cool.get(e)>Date.now())){cool.set(e,Date.now()+6e4);try{await issue(u.id,e)}catch(x){console.error(x)}}
 s.json({ok:1})});  // always the same answer: no account enumeration
app.post('/api/login',lim(15,20),async(q,s)=>{const b=q.body||{},e=normEmail(b.email),k='u:'+e;
 if(!e||typeof b.password!=='string'||b.password.length>128)return s.status(400).json({error:'Email and password required'});
 const u=await one('select * from users where email=?',[e]);
 if(locked(k))return s.status(429).json({error:'Too many failed attempts. Try again in 15 minutes.'});
 if(!bcrypt.compareSync(b.password,u?u.pw:DUMMY)||!u){fail(k);return s.status(401).json({error:'Wrong email or password'})}
 if(u.verified===0)return s.status(403).json({error:'Please confirm your email first — check your inbox.',unverified:true});
 fails.delete(k);sign(s,u.id);s.json({ok:1})});
app.post('/api/logout',(q,s)=>{s.clearCookie('t');s.json({ok:1})});
app.get('/api/me',auth,async(q,s)=>{const u=await one('select email from users where id=?',[q.uid]);if(!u)return s.status(401).json({error:'Please log in'});s.json({email:u.email,used:await used(q.uid),quota:QUOTA,maxFile:MAX_FILE})});
// ---- owner
const up=multer({storage:multer.memoryStorage(),limits:{fileSize:MAX_FILE,files:1}});
app.post('/api/upload',auth,(q,s,n)=>up.single('file')(q,s,async e=>{try{
 const big=e&&e.code==='LIMIT_FILE_SIZE';
 if(e)return s.status(big?413:400).json({error:big?'File exceeds the 10 MB limit':'Upload failed'});
 const f=q.file;if(!f)return s.status(400).json({error:'No file received'});
 if(!f.size)return s.status(400).json({error:'File is empty'});
 const name=path.basename(Buffer.from(f.originalname,'latin1').toString('utf8')).replace(/[\x00-\x1f]/g,'').replace(/[. ]+$/,'').trim().slice(0,120)||'file',bad=BLOCK.test(name)||dangerous(f.buffer);
 if((await one('select count(*) n from files where user_id=? and deleted=0',[q.uid])).n>=50)return s.status(413).json({error:'Max 50 files per account'});
 if(bad||await used(q.uid)+f.size>QUOTA)return s.status(bad?415:413).json({error:bad?'This file type is not allowed':'Quota exceeded (50 MB)'});
 await run('insert into files(user_id,name,size,data,created) values(?,?,?,?,?)',[q.uid,name,f.size,f.buffer,Date.now()]);s.json({ok:1})}catch(x){n(x)}}));
const state=l=>l.revoked?'revoked':l.expires<=Date.now()?'expired':l.max_dl&&l.downloads>=l.max_dl?'exhausted':'active';
app.get('/api/files',auth,async(q,s)=>{const out=[];
 for(const f of await Q('select id,name,size,created from files where user_id=? and deleted=0 order by id desc',[q.uid]))
  out.push({id:f.id,name:f.name,size:f.size,created:f.created,links:(await Q('select id,expires,created,max_dl,downloads,revoked,pw is not null locked from links where file_id=? order by id desc',[f.id])).map(l=>({id:l.id,expires:l.expires,created:l.created,max_dl:l.max_dl,downloads:l.downloads,locked:l.locked,state:state(l)}))});
 s.json(out)});
const own=(q)=>one('select id from files where id=? and user_id=? and deleted=0',[(pid(q.params.id)||0),q.uid]);
app.delete('/api/files/:id',auth,async(q,s)=>{const f=await own(q);if(!f)return s.status(404).json({error:'Not found'});
 await run('update files set deleted=1,data=null where id=?',[f.id]);s.json({ok:1})});
app.post('/api/files/:id/links',auth,async(q,s)=>{const f=await own(q);if(!f)return s.status(404).json({error:'Not found'});const b=q.body||{};
 if((await one('select count(*) n from links where file_id=?',[f.id])).n>=20)return s.status(429).json({error:'Max 20 links per file'});
 const h=b.hours==null||b.hours===''?24:Number(b.hours),m=b.maxDl==null||b.maxDl===''?null:Number(b.maxDl),pw=b.password==null||b.password===''?null:b.password,tok=crypto.randomBytes(24).toString('base64url');
 if(!Number.isInteger(h)||h<1||h>168)return s.status(400).json({error:'Expiry must be 1–168 hours'});
 if(m!==null&&(!Number.isInteger(m)||m<1||m>100))return s.status(400).json({error:'Max downloads must be a whole number 1–100'});
 if(pw!==null&&(typeof pw!=='string'||pw.length>100))return s.status(400).json({error:'Link password must be at most 100 characters'});
 await run('insert into links(file_id,hash,expires,max_dl,pw,created) values(?,?,?,?,?,?)',[f.id,sha(tok),Date.now()+h*36e5,m,pw&&bcrypt.hashSync(pw,8),Date.now()]);
 s.json({url:`${q.protocol}://${q.get('host')}/d/${tok}`})});
app.post('/api/links/:id/revoke',auth,async(q,s)=>{const r=await run('update links set revoked=1 where id=? and file_id in (select id from files where user_id=?)',[(pid(q.params.id)||0),q.uid]);
 r.rowsAffected?s.json({ok:1}):s.status(404).json({error:'Not found'})});
// ---- public recipient
const MSG={revoked:'The owner revoked this link.',expired:'This link has expired.',exhausted:'This link reached its download limit.',deleted:'The owner deleted this file.'};
const gate=async(q,s)=>{const l=await one('select l.*,f.name,f.size,f.deleted from links l join files f on f.id=l.file_id where l.hash=?',[sha(String(q.params.t))]);
 if(!l){s.status(404).json({error:'This link does not exist.'});return}
 const st=l.deleted?'deleted':state(l);if(st!=='active'){s.status(410).json({error:MSG[st]});return}return l};
app.get('/api/s/:t',lim(1,60),async(q,s)=>{const l=await gate(q,s);if(l)s.json({name:l.name,size:l.size,expires:l.expires,locked:!!l.pw,left:l.max_dl?l.max_dl-l.downloads:null})});
app.post('/api/s/:t/download',lim(1,10),async(q,s)=>{const l=await gate(q,s);if(!l)return;
 const k='l:'+l.id;if(locked(k))return s.status(429).json({error:'Too many wrong passwords. Try again in 15 minutes.'});
 if(l.pw){if(!bcrypt.compareSync(String((q.body||{}).password||''),l.pw)){fail(k);return s.status(403).json({error:'Wrong password'})}fails.delete(k)}
 if(!(await run('update links set downloads=downloads+1 where id=? and (max_dl is null or downloads<max_dl)',[l.id])).rowsAffected)return s.status(410).json({error:MSG.exhausted});
 const buf=Buffer.from((await one('select data from files where id=?',[l.file_id])).data);
 s.attachment(l.name);s.set({'Content-Type':'application/octet-stream','Content-Length':buf.length,'X-Content-Type-Options':'nosniff'});s.end(buf)});
app.get('/verify/:t',(q,s)=>s.set('X-Robots-Tag','noindex').sendFile(path.join(__dirname,'public/index.html')));
app.get('/d/:t',(q,s)=>s.set('X-Robots-Tag','noindex').sendFile(path.join(__dirname,'public/index.html')));
app.use((e,q,s,n)=>{console.error(e);s.status(500).json({error:'Server error'})});
ready.then(()=>app.listen(process.env.PORT||3000,()=>console.log('Ghostdrop up')));

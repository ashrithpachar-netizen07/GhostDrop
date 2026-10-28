const express=require('express'),multer=require('multer'),{createClient}=require('@libsql/client'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),crypto=require('crypto'),fs=require('fs'),path=require('path'),helmet=require('helmet'),rateLimit=require('express-rate-limit'),cookie=require('cookie-parser');
const DATA=process.env.DATA_DIR||path.join(__dirname,'data');fs.mkdirSync(DATA,{recursive:true});
const SECRET=process.env.JWT_SECRET||(()=>{const f=path.join(DATA,'.secret');if(!fs.existsSync(f))fs.writeFileSync(f,crypto.randomBytes(32).toString('hex'));return fs.readFileSync(f,'utf8')})();
const MAX_FILE=10*1024*1024,QUOTA=50*1024*1024,BLOCK=/\.(exe|msi|bat|cmd|com|scr|js|jse|vbs|ps1|sh|jar|html?|svg|php|dll|apk)$/i;
// Turso (hosted SQLite, persistent) in prod; local file DB for dev/tests
const db=createClient({url:process.env.TURSO_DATABASE_URL||'file:'+path.join(DATA,'db.sqlite'),authToken:process.env.TURSO_AUTH_TOKEN});
const Q=async(sql,args=[])=>(await db.execute({sql,args})).rows,one=async(sql,args)=>(await Q(sql,args))[0],run=(sql,args=[])=>db.execute({sql,args});
const ready=db.batch([
 'create table if not exists users(id integer primary key,email text unique,pw text)',
 'create table if not exists files(id integer primary key,user_id int,name text,size int,data blob,deleted int default 0,created int)',
 'create table if not exists links(id integer primary key,file_id int,hash text unique,expires int,max_dl int,pw text,downloads int default 0,revoked int default 0,created int)'],'write');
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
const lim=(m,n)=>rateLimit({windowMs:m*60000,limit:n,message:{error:'Too many requests, slow down'}});
const auth=(q,s,n)=>{try{q.uid=jwt.verify(q.cookies.t,SECRET).uid;n()}catch{s.status(401).json({error:'Please log in'})}};
const sign=(s,id)=>s.cookie('t',jwt.sign({uid:Number(id)},SECRET,{expiresIn:'7d'}),{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:6048e5});
const used=async u=>Number((await one('select coalesce(sum(size),0) n from files where user_id=? and deleted=0',[u])).n);
// ---- auth
app.post('/api/register',lim(15,20),async(q,s)=>{const b=q.body||{},e=String(b.email||'').toLowerCase(),p=String(b.password||'');
 if(!/^\S+@\S+\.\S+$/.test(e)||p.length<8)return s.status(400).json({error:'Valid email and 8+ char password required'});
 try{const r=await run('insert into users(email,pw) values(?,?)',[e,bcrypt.hashSync(p,10)]);sign(s,r.lastInsertRowid);s.json({ok:1})}catch{s.status(409).json({error:'Email already registered'})}});
app.post('/api/login',lim(15,20),async(q,s)=>{const b=q.body||{},e=String(b.email||'').toLowerCase(),k='u:'+e,u=await one('select * from users where email=?',[e]);
 if(locked(k))return s.status(429).json({error:'Too many failed attempts. Try again in 15 minutes.'});
 if(!bcrypt.compareSync(String(b.password||''),u?u.pw:DUMMY)||!u){fail(k);return s.status(401).json({error:'Wrong email or password'})}
 fails.delete(k);sign(s,u.id);s.json({ok:1})});
app.post('/api/logout',(q,s)=>{s.clearCookie('t');s.json({ok:1})});
app.get('/api/me',auth,async(q,s)=>{const u=await one('select email from users where id=?',[q.uid]);if(!u)return s.status(401).json({error:'Please log in'});s.json({email:u.email,used:await used(q.uid),quota:QUOTA,maxFile:MAX_FILE})});
// ---- owner
const up=multer({storage:multer.memoryStorage(),limits:{fileSize:MAX_FILE,files:1}});
app.post('/api/upload',auth,(q,s,n)=>up.single('file')(q,s,async e=>{try{
 const big=e&&e.code==='LIMIT_FILE_SIZE';
 if(e)return s.status(big?413:400).json({error:big?'File exceeds the 10 MB limit':'Upload failed'});
 const f=q.file;if(!f)return s.status(400).json({error:'No file received'});
 const name=path.basename(Buffer.from(f.originalname,'latin1').toString('utf8')).replace(/[\x00-\x1f]/g,'').slice(0,120),bad=BLOCK.test(name)||dangerous(f.buffer);
 if((await one('select count(*) n from files where user_id=? and deleted=0',[q.uid])).n>=50)return s.status(413).json({error:'Max 50 files per account'});
 if(bad||await used(q.uid)+f.size>QUOTA)return s.status(bad?415:413).json({error:bad?'This file type is not allowed':'Quota exceeded (50 MB)'});
 await run('insert into files(user_id,name,size,data,created) values(?,?,?,?,?)',[q.uid,name,f.size,f.buffer,Date.now()]);s.json({ok:1})}catch(x){n(x)}}));
const state=l=>l.revoked?'revoked':l.expires<=Date.now()?'expired':l.max_dl&&l.downloads>=l.max_dl?'exhausted':'active';
app.get('/api/files',auth,async(q,s)=>{const out=[];
 for(const f of await Q('select id,name,size,created from files where user_id=? and deleted=0 order by id desc',[q.uid]))
  out.push({id:f.id,name:f.name,size:f.size,created:f.created,links:(await Q('select id,expires,max_dl,downloads,revoked,pw is not null locked from links where file_id=? order by id desc',[f.id])).map(l=>({id:l.id,expires:l.expires,max_dl:l.max_dl,downloads:l.downloads,locked:l.locked,state:state(l)}))});
 s.json(out)});
const own=(q)=>one('select id from files where id=? and user_id=? and deleted=0',[+q.params.id,q.uid]);
app.delete('/api/files/:id',auth,async(q,s)=>{const f=await own(q);if(!f)return s.status(404).json({error:'Not found'});
 await run('update files set deleted=1,data=null where id=?',[f.id]);s.json({ok:1})});
app.post('/api/files/:id/links',auth,async(q,s)=>{const f=await own(q);if(!f)return s.status(404).json({error:'Not found'});const b=q.body||{};
 if((await one('select count(*) n from links where file_id=?',[f.id])).n>=20)return s.status(429).json({error:'Max 20 links per file'});
 const h=Math.min(168,Math.max(1,+b.hours||24)),m=b.maxDl?Math.min(100,Math.max(1,+b.maxDl|0)):null,pw=b.password?String(b.password).slice(0,100):null,tok=crypto.randomBytes(24).toString('base64url');
 await run('insert into links(file_id,hash,expires,max_dl,pw,created) values(?,?,?,?,?,?)',[f.id,sha(tok),Date.now()+h*36e5,m,pw&&bcrypt.hashSync(pw,8),Date.now()]);
 s.json({url:`${q.protocol}://${q.get('host')}/d/${tok}`})});
app.post('/api/links/:id/revoke',auth,async(q,s)=>{const r=await run('update links set revoked=1 where id=? and file_id in (select id from files where user_id=?)',[+q.params.id,q.uid]);
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
app.get('/d/:t',(q,s)=>s.set('X-Robots-Tag','noindex').sendFile(path.join(__dirname,'public/index.html')));
app.use((e,q,s,n)=>{console.error(e);s.status(500).json({error:'Server error'})});
ready.then(()=>app.listen(process.env.PORT||3000,()=>console.log('Ghostdrop up')));

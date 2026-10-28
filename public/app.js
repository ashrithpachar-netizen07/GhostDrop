const $=s=>document.querySelector(s),app=$('#app');let fresh={};
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api=async(u,o={})=>{const r=await fetch(u,{credentials:'same-origin',...o,headers:{'X-Requested-With':'ghostdrop',...o.headers}});if(o.raw&&r.ok)return r;const d=await r.json().catch(()=>({}));if(!r.ok)throw Object.assign(new Error(d.error||'Something went wrong'),{status:r.status});return d};
const J=b=>({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
const mb=n=>(n/1048576).toFixed(2)+' MB';
const ago=ms=>{const m=Math.round((ms-Date.now())/6e4);return m<=0?'now':m<60?m+'m':m<2880?Math.round(m/60)+'h':Math.round(m/1440)+'d'};
const left=ms=>{const s=Math.max(0,Math.floor((ms-Date.now())/1000)),d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?`${d}d ${h}h`:h?`${h}h ${m}m`:`${m}m ${s%60}s`};
const icon=n=>/\.(png|jpe?g|gif|webp)$/i.test(n)?'🖼️':/\.pdf$/i.test(n)?'📕':/\.(zip|rar|7z|tar|gz)$/i.test(n)?'🗜️':/\.(mp3|wav|mp4|mov|mkv)$/i.test(n)?'🎞️':/\.(docx?|txt|md|pptx?)$/i.test(n)?'📝':/\.(xlsx?|csv)$/i.test(n)?'📊':'📄';
setInterval(()=>{document.querySelectorAll('[data-e]').forEach(e=>{const x=+e.dataset.e-Date.now();if(e.tagName=='I')e.style.width=Math.max(0,x/(+e.dataset.e-+e.dataset.c)*100)+'%';else e.textContent=x>0?left(+e.dataset.e):'expired'});const w=$('#w');if(w){const W=['vanish','expire','self-destruct','disappear','burn'];w.textContent=W[(W.indexOf(w.textContent)+1)%W.length];w.style.animation='none';w.offsetHeight;w.style.animation=''}},1000);
const toast=(m,bad)=>{const t=document.createElement('div');t.className='toast'+(bad?' bad':'');t.textContent=m;document.body.append(t);setTimeout(()=>t.remove(),3500)};
async function boot(){const m=location.pathname.match(/^\/d\/([\w-]+)/);if(m)return recv(m[1]);const v=location.pathname.match(/^\/verify\/([\w-]+)/);if(v)return verifyPage(v[1]);try{await api('/api/me');dash()}catch{login()}}
let mode='in';
const EM=/^[a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9])?@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i;
const FEAT='<div class=feat><div class=card>⏳<b>Auto-expiry</b><small>Links die in 1h–7d</small></div><div class=card>🔥<b>Burn after N</b><small>Cap downloads per link</small></div><div class=card>🔐<b>Hashed tokens</b><small>Leaked DB ≠ leaked links</small></div><div class=card>🛡️<b>Safe files</b><small>Magic-byte scanning</small></div></div>';
function login(){const su=mode=='up';
 app.innerHTML=`<section class="card hero"><div class=ghost>👻</div><h1>Ghostdrop</h1><p class=mut>Files that <span id=w class=word>vanish</span>. Expiring, revocable, burn-after-N links.</p>
 <form id=fm novalidate><input id=e type=email maxlength=254 autocomplete=email placeholder=Email>
 <input id=p type=password maxlength=72 autocomplete="${su?'new-password':'current-password'}" placeholder="${su?'Password (8–72, letter + number)':'Password'}">
 ${su?'<input id=c type=password maxlength=72 autocomplete=new-password placeholder="Confirm password">':''}
 <div id=er class=err></div><button id=go style="width:100%">${su?'Create account':'Log in'}</button></form>
 <p class=mut>${su?'Already have an account?':'New here?'} <a href=# id=sw>${su?'Log in':'Sign up'}</a></p></section>${FEAT}`;
 $('#sw').onclick=e=>{e.preventDefault();mode=su?'in':'up';login()};
 $('#fm').onsubmit=async ev=>{ev.preventDefault();const em=$('#e').value.trim().toLowerCase(),pw=$('#p').value,er=m=>{$('#er').textContent=m};er('');
  if(!EM.test(em)||em.includes('..'))return er('Enter a valid email address (like name@domain.com)');
  if(su){if(pw.length<8||pw.length>72)return er('Password must be 8–72 characters');if(!/[a-z]/i.test(pw)||!/\d/.test(pw))return er('Password needs at least one letter and one number');if(pw!==$('#c').value)return er('Passwords do not match')}
  else if(!pw)return er('Enter your password');
  const b=$('#go');b.disabled=true;try{await api('/api/'+(su?'register':'login'),J({email:em,password:pw}));su?pending(em):boot()}catch(x){if(!su&&x.status==403)return pending(em);er(x.message);b.disabled=false}}}
function pending(em){app.innerHTML=`<section class="card hero"><div class=ghost>📬</div><h2>Check your inbox</h2><p class=mut>We sent a confirmation link to <b>${esc(em)}</b>. It expires in 24 hours — check spam too.</p><button id=rs class=alt>Resend email</button><p class=mut><a href=# id=bk>Back to login</a></p></section>`;
 const b=$('#rs');b.onclick=async()=>{b.disabled=true;try{await api('/api/resend',J({email:em}));toast('Email sent')}catch(x){toast(x.message,1)}let n=60;const iv=setInterval(()=>{b.textContent=n>0?`Resend in ${n--}s`:'Resend email';if(n<0){clearInterval(iv);b.disabled=false}},1000)};
 $('#bk').onclick=e=>{e.preventDefault();mode='in';login()}}
function verifyPage(t){app.innerHTML='<section class="card hero"><div class=ghost>📬</div><h2>Confirm your email</h2><p class=mut>One click and your account is live.</p><button id=cf>Confirm email</button></section>';
 $('#cf').onclick=async()=>{try{await api('/api/verify',J({token:t}));history.replaceState(null,'','/');toast('Email confirmed 🎉');boot()}catch(x){$('.hero').innerHTML=`<div class="ghost fade">👻</div><h2>Link invalid</h2><p class=mut>${esc(x.message)}</p><p><a href=/>Back to Ghostdrop</a></p>`}}}
async function dash(){const me=await api('/api/me'),files=await api('/api/files');
 app.innerHTML=`<header><h2>👻 Ghostdrop</h2><span class=mut>${esc(me.email)} <button class=alt id=lo>Log out</button></span></header>
 <div class=stats><div><b>${files.length}</b>files</div><div><b>${files.reduce((a,f)=>a+f.links.filter(l=>l.state=='active').length,0)}</b>live links</div><div><b>${files.reduce((a,f)=>a+f.links.reduce((b,l)=>b+l.downloads,0),0)}</b>downloads</div></div>
 <div class=card><label id=dz class=dz>Drop a file or click to upload · max ${mb(me.maxFile)}<input type=file id=f hidden></label><div class=bar><i style="width:${Math.min(100,me.used/me.quota*100)}%"></i></div><small>${mb(me.used)} / ${mb(me.quota)} used</small><div id=pg></div></div>
 ${files.map(f=>`<div class="card file" data-id=${f.id}><div class=top><div><span class=ico>${icon(f.name)}</span><span><b>${esc(f.name)}</b><br><small>${mb(f.size)} · ${f.links.reduce((a,l)=>a+l.downloads,0)} total downloads</small></span></div><button class=del data-del=${f.id}>Delete</button></div>
 ${fresh[f.id]?`<div class=fresh>🔗 Shown once — copy now:<br><b>${esc(fresh[f.id])}</b> <button data-copy="${esc(fresh[f.id])}">Copy</button></div>`:''}
 ${f.links.map(l=>`<div class="lk ${l.state}"><b>${l.state}</b>${l.locked?'🔒':''}${l.state=='active'?`⏳ <span data-e=${l.expires}>${left(l.expires)}</span>`:''} · ${l.downloads}${l.max_dl?'/'+l.max_dl:''} downloads${l.state=='active'?`<button class=alt data-r=${l.id}>Revoke</button>`:''}${l.state=='active'?`<span class=mt><i data-e=${l.expires} data-c=${l.created}></i></span>`:''}</div>`).join('')}
 <div class=row><select class=h><option value=1>1 hour</option><option value=24 selected>24 hours</option><option value=168>7 days</option></select><input class=m type=number min=1 max=100 step=1 placeholder="Max downloads (1–100)"><input class=w maxlength=100 placeholder="Password (optional)"><button data-mk>+ Ghost link</button></div></div>`).join('')||'<p class=mut>No files yet — drop one above.</p>'}`;
 const up=file=>{if(!file)return;if(!file.size)return toast('That file is empty',1);if(file.size>me.maxFile)return toast('File exceeds the 10 MB limit',1);const x=new XMLHttpRequest(),d=new FormData();d.append('file',file);x.open('POST','/api/upload');x.setRequestHeader('X-Requested-With','ghostdrop');
  x.upload.onprogress=e=>$('#pg').textContent=`Uploading ${Math.round(e.loaded/e.total*100)}%`;
  x.onload=()=>{x.status==200?dash():toast(JSON.parse(x.responseText||'{}').error||'Upload failed',1);$('#pg').textContent=''};x.send(d)};
 $('#f').onchange=e=>up(e.target.files[0]);const dz=$('#dz');dz.ondragover=e=>{e.preventDefault();dz.classList.add('on')};dz.ondragleave=()=>dz.classList.remove('on');dz.ondrop=e=>{e.preventDefault();dz.classList.remove('on');up(e.dataTransfer.files[0])};
 $('#lo').onclick=async()=>{await api('/api/logout',{method:'POST'});fresh={};login()}}
document.addEventListener('click',async e=>{const t=e.target,c=t.closest('.file');try{
 if(t.dataset.del!=null){if(confirm('Delete file and kill all its links?')){await api('/api/files/'+t.dataset.del,{method:'DELETE'});dash()}}
 else if(t.dataset.r){await api('/api/links/'+t.dataset.r+'/revoke',{method:'POST'});dash()}
 else if(t.dataset.copy){await navigator.clipboard.writeText(t.dataset.copy);toast('Copied')}
 else if(t.dataset.mk!=null){const md=c.querySelector('.m').value;if(md&&(!Number.isInteger(+md)||+md<1||+md>100))return toast('Max downloads must be a whole number 1–100',1);const id=c.dataset.id,r=await api(`/api/files/${id}/links`,J({hours:c.querySelector('.h').value,maxDl:c.querySelector('.m').value,password:c.querySelector('.w').value}));fresh[id]=r.url;dash()}
}catch(err){toast(err.message,1)}});
async function recv(t){app.innerHTML='<section class="card hero" id=r>Loading…</section>';
 try{const i=await api('/api/s/'+t);$('#r').innerHTML=`<div class=ghost id=g>👻</div><h2>${esc(i.name)}</h2><p class=mut>Someone sent you a file</p><p class=mut>${mb(i.size)} · expires in ${ago(i.expires)}${i.left!=null?` · ${i.left} download(s) left`:''}</p>${i.locked?'<input id=p type=password placeholder=Password>':''}<button id=dl>Download</button>`;
  $('#dl').onclick=async()=>{try{const r=await api(`/api/s/${t}/download`,{...J({password:$('#p')?.value}),raw:1}),a=document.createElement('a');a.href=URL.createObjectURL(await r.blob());a.download=i.name;a.click();$('#g').classList.add('poof');setTimeout(()=>{$('#g').className='ghost';$('#g').textContent='💨';toast('Downloaded — poof!')},800)}catch(e){toast(e.message,1)}}}
 catch(e){$('#r').innerHTML=`<div class='ghost ${e.status==410?'fade':''}'>${e.status==410?'👻':'🚫'}</div><h2>${e.status==410?'Link unavailable':'Link not found'}</h2><p class=mut>${esc(e.message)}</p>`}}
boot();

// EaglerScan analyzer: static, side-effect-free analysis of an Eaglercraft/EaglerForge mod's JavaScript.
// Pure ES module with no DOM or Node dependencies, so it runs in Cloudflare Workers, Node 18+ and browsers.
function stripComments(src){
  const n=src.length,out=[],cnt=[0,0,0],bad=[false,false,false];
  let last=0,i=0,q=0;
  while(i<n){
    const c=src.charCodeAt(i);
    if(q){if(c===92){i+=2;continue;}if(c===q)q=0;i++;continue;}
    if(c===34||c===39||c===96){q=c;i++;continue;}
    if(c===47){
      const d=src.charCodeAt(i+1);
      if(d===47){let j=src.indexOf('\n',i);if(j<0)j=n;out.push(src.slice(last,i),' '.repeat(j-i));i=j;last=j;continue;}
      if(d===42){const j=src.indexOf('*/',i+2),e=j<0?n:j+2;out.push(src.slice(last,i),src.slice(i,e).replace(/[^\r\n]/g,' '));i=e;last=e;continue;}
    }else if(c===123){cnt[0]++;}else if(c===125){if(--cnt[0]<0)bad[0]=true;}
    else if(c===40){cnt[1]++;}else if(c===41){if(--cnt[1]<0)bad[1]=true;}
    else if(c===91){cnt[2]++;}else if(c===93){if(--cnt[2]<0)bad[2]=true;}
    i++;
  }
  out.push(src.slice(last));
  return {clean:out.join(''),balance:{cnt,bad}};
}
export function analyze(name, src, opts = {}) {
  const lines=src.split(/\r?\n/), findings=[], deps=[], warnings=[], versions=[];
  // Newline index + binary search: O(log n) line lookups instead of re-splitting the source for every match.
  const nlPos=[];for(let p=src.indexOf('\n');p!==-1;p=src.indexOf('\n',p+1))nlPos.push(p);
  const lineAt=idx=>{let lo=0,hi=nlPos.length;while(lo<hi){const mid=(lo+hi)>>1;if(nlPos[mid]<idx)lo=mid+1;else hi=mid;}return lo+1;};
  const add=(arr,item)=>{if(!arr.some(x=>x.key===item.key))arr.push(item)};
  const context=(line)=>lines[Math.max(0,line-1)]?.trim().slice(0,260)||'';
  const evidence=(kind,title,detail,line,level='inferred')=>findings.push({kind,title,detail,line,level,source:line?context(line):''});
  // One pass over the source: blanks comments (keeping offsets/newlines, leaving "//host/path" inside strings intact)
  // and counts delimiters outside strings/comments for the lightweight balance check.
  const {clean,balance}=stripComments(src);
  // Explicit metadata in comments or strings: useful as a declared claim, not proof.
  const versionRegexes=[
    {re:/(?:supported\s+eaglercraft|eaglercraft\s+support|eaglercraft\s+versions?)\s*[:=]\s*["']?([^"'*\r\n;]+)/ig, label:'Explicit Eaglercraft support declaration', level:'declared'},
    {re:/(?:minecraft|mc)\s*version\s*[:=]\s*["']?(1\.\d+(?:\.\d+)?)/ig, label:'Minecraft version metadata', level:'declared'}
  ];
  for(const {re,label,level} of versionRegexes){let m;while((m=re.exec(src))){const vals=m[1].match(/\b1\.\d+(?:\.\d+)?\b/g)||[];for(const v of vals){add(versions,{key:v,version:v,level,reason:label,line:lineAt(m.index),source:context(lineAt(m.index))});}}}
  // Version strings elsewhere are weak clues only; avoid treating every numeric string as support.
  const vpat=/\b(?:Eaglercraft|Minecraft|MC|protocol|version)\s*(?:for|v|version|:|=)?\s*(1\.\d+(?:\.\d+)?)/ig;let vm;
  while((vm=vpat.exec(src))){const v=vm[1];if(!versions.some(x=>x.version===v)){const line=lineAt(vm.index);add(versions,{key:v,version:v,level:'inferred',reason:'Version-related identifier or text; compatibility not proven',line,source:context(line)});}}
  if(!versions.length) versions.push({key:'unknown',version:'Unknown',level:'unknown',reason:'No reliable version declaration detected; compatibility is unknown',line:null,source:''});
  // Imports: ES modules, CommonJS require, dynamic imports, importScripts and URL script loads.
  const depPatterns=[
    {re:/\bimport\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/g,type:'ES module import'},
    {re:/\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,type:'Dynamic import'},
    {re:/\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,type:'CommonJS require'},
    {re:/\bimportScripts\s*\(\s*['"]([^'"]+)['"]/g,type:'Worker script import'},
    {re:/<script[^>]+src\s*=\s*["']([^"']+)["']/gi,type:'Script URL'}
  ];
  for(const p of depPatterns){let m;while((m=p.re.exec(src))){const val=m[1],line=lineAt(m.index);const external=/^(?:https?:)?\/\//i.test(val);const builtin=/^(?:node:)?(?:fs|path|http|https|url|util|crypto|events|stream|os|buffer|child_process|worker_threads|assert|zlib)(?:\/|$)/.test(val);const local=/^(?:\.{1,2}\/|\/)/.test(val);const status=external?'External URL':builtin?'Node.js built-in':local?'Local file/module':'Package/module specifier';deps.push({key:p.type+':'+val,name:val,type:p.type,status,line,source:context(line),match:m[0].trim().slice(0,140),level:'declared'});}}
  const apiPatterns=[
    {re:/\beaglerforge\b/ig,name:'EaglerForge API',desc:'Identifier suggests an EaglerForge-related integration; exact API/loader version is unverified.'},
    {re:/\bEaglercraftX?\b/ig,name:'Eaglercraft identifier',desc:'Eaglercraft name appears in source; this alone does not establish compatibility.'},
    {re:/\bModAPI\b/g,name:'ModAPI (Eaglercraft mod API)',desc:'Eaglercraft ModAPI usage detected. This is strong evidence of a ModAPI-based mod, but does not by itself prove the exact game version.'},
    {re:/\bPluginAPI\b/g,name:'PluginAPI (plugin/server hooks)',desc:'PluginAPI usage detected; the matching plugin/loader environment may be required.'},
    {re:/\bLibCustomItems\b/g,name:'LibCustomItems library',desc:'LibCustomItems symbols are referenced. The mod likely needs the matching LibCustomItems library/plugin available.'},
    {re:/\b(ModLoader|ModLoaderScript)\b/g,name:'Mod loader/API symbol',desc:'Possible loader integration; confirm against the target loader documentation.'},
    {re:/\b(window|document|localStorage|navigator)\b/g,name:'Browser runtime API',desc:'Browser API usage may fail in non-browser or restricted loader environments.'},
    {re:/\b(process|Buffer|__dirname|module\.exports)\b/g,name:'Node.js runtime API',desc:'Node.js-specific usage may be unavailable in a browser-based mod environment.'}
  ];
  for(const p of apiPatterns){p.re.lastIndex=0;const m=p.re.exec(clean);if(m){const line=lineAt(m.index);add(deps,{key:p.name,name:p.name,type:'API reference',status:'API usage clue',line,source:context(line),match:m[0],level:'inferred',detail:p.desc});}}
  // Eaglercraft ecosystem dependency clues that do not use JS import syntax.
  const ecosystemPatterns=[
    {re:/\bLibCustomItems\s*\.\s*registerItem\b/,name:'LibCustomItems',type:'Eaglercraft library reference',status:'Likely required library',detail:'The mod registers a custom item through LibCustomItems; verify the library is installed.'},
    {re:/\blib:libcustomitems:loaded\b/i,name:'libcustomitems loaded event',type:'Loader event dependency',status:'Required integration clue',detail:'The mod waits for the libcustomitems:loaded event before registering its item.'},
    {re:/\bModAPI\.reflect\b/,name:'ModAPI reflection API',type:'Eaglercraft API reference',status:'Core API usage',detail:'The mod calls ModAPI reflection methods.'},
    {re:/\bPluginAPI\.dedicatedServer\b/,name:'PluginAPI dedicated-server hooks',type:'Plugin API reference',status:'Server-side integration',detail:'The mod registers command handling through PluginAPI dedicatedServer.'}
  ];
  for(const p of ecosystemPatterns){const m=p.re.exec(clean);if(m){const line=lineAt(m.index);add(deps,{key:'ecosystem:'+p.name,name:p.name,type:p.type,status:p.status,line,source:context(line),match:m[0],level:'inferred',detail:p.detail});}}
  // Dependency metadata hints.
  // Declared requirements: description metadata, comment headers and explicit dependency lists.
  // "Requires AsyncSink." inside ModAPI.meta.description(...) is a dependency claim even though no import exists.
  const REQ_STOP=new Set(['the','a','an','this','that','these','those','it','its','to','of','and','or','for','with','in','on','at','by','you','your','we','our','any','some','no','not','node','nodejs','npm','browser','runtime','bundler','commonjs','java','minecraft','eaglercraft','eaglercraftx','restart','reload','internet','network','permission','permissions','work','fixing','update','updates','latest','newer','newest','older','admin','op','version','versions','mod','mods','plugin','plugins','library','libraries','lib','libs','dependency','dependencies','module','modules','api','apis','setup','config','configuration','none','n/a','na','nothing','other','others','extra','more','additional','special','free']);
  const canon=n=>String(n).toLowerCase().replace(/[^a-z0-9]/g,'');
  const reqNames=(raw,strong)=>{
    const out=[];let list=String(raw||'').trim();
    if(list.startsWith('['))list=list.slice(1,-1);
    for(let part of list.split(/\s*(?:,|&|\+|\band\b)\s*/i)){
      part=part.replace(/^[\s"'`(\[]+|[\s"'`)\].,:!]+$/g,'');
      part=part.replace(/\s+(?:to|in order|before|for|with|so|because|when|if|which|that)\b.*$/i,'');
      let prev;do{prev=part;part=part.replace(/\s+(?:installed|loaded|enabled|first|mod|plugin|library|lib|addon|package)$/i,'');}while(part!==prev);
      let version='';const vm=part.match(/\s+(?:v\s*\d+(?:\.\d+)*|(?:version\s*)?(?:>=|<=|~|\^)?\d+(?:\.\d+)+\+?)$/i);
      if(vm){version=vm[0].trim();part=part.slice(0,vm.index);}
      part=part.trim();
      if(part.length<2||part.length>48)continue;
      if(!/^[A-Za-z_@][\w.\-@\/]*(?:\s+[\w.\-]+){0,2}$/.test(part))continue;
      if(REQ_STOP.has(part.split(/\s+/)[0].toLowerCase())||REQ_STOP.has(part.toLowerCase()))continue;
      if(!strong&&!(/[A-Z]/.test(part)||/[-_.@\/\d]/.test(part)))continue;
      out.push({name:part,version});
    }
    return out;
  };
  const regions=[];let rm;
  const cre=/\/\*[\s\S]*?\*\//g;while((rm=cre.exec(src)))regions.push({start:rm.index,text:rm[0],origin:'comment header'});
  const lre=/(^|[^:\\])\/\/[^\r\n]*/g;while((rm=lre.exec(src)))regions.push({start:rm.index+rm[1].length,text:rm[0].slice(rm[1].length),origin:'comment header'});
  const dre=/(?:ModAPI\s*\.\s*meta\s*\.\s*description\s*\(\s*|@description\s*|\bdescription\s*[:=]\s*)(['"`])([\s\S]*?)\1/g;
  while((rm=dre.exec(src)))regions.push({start:rm.index+rm[0].length-1-rm[2].length,text:rm[2],origin:'description metadata'});
  const kre=/\b(?:dependencies|depends|requires|requirements?)\s*[:=]\s*(\[[^\]]*\]|(['"`])[^\r\n]*?\2)/gi;
  while((rm=kre.exec(src)))regions.push({start:rm.index+rm[0].length-rm[1].length,text:rm[1],origin:'dependency list',list:true});
  const reqVerb=/\b(requires?d?|depends\s+on|depends|dependenc(?:y|ies)|needs?|requirements?)\b\s*(?:[:=\u2013\u2014-]\s*)?["'`]?\s*(\[[^\]\r\n]*\]|(?:[^\r\n;.\]*]|\.(?=\S))*)/ig;
  const reqLines=new Set(),reqFound=new Map();
  for(const reg of regions){
    const found=[];
    if(reg.list)found.push({raw:reg.text,strong:true,idx:0,phrase:reg.text.slice(0,140)});
    else{reqVerb.lastIndex=0;let m;while((m=reqVerb.exec(reg.text))){
      if(!m[0].length){reqVerb.lastIndex++;continue;}
      const dot=reg.text[m.index+m[0].length]==='.'?'.':'';
      found.push({raw:m[2],strong:!/^needs?$/i.test(m[1]),idx:m.index,phrase:(m[0].trim()+dot).slice(0,140)});
    }}
    for(const f of found)for(const {name,version} of reqNames(f.raw,f.strong)){
      const line=lineAt(reg.start+f.idx);
      reqLines.add(line);reqFound.set('lib:'+canon(name),name);
      deps.push({key:'lib:'+canon(name),name,type:'Declared requirement',status:'Likely required',line,source:context(line),match:f.phrase,origin:reg.origin,level:'declared',detail:`Stated in the file's ${reg.origin}${version?' (version '+version+')':''}; the scanner cannot verify it is installed.`});
    }
  }
  // If a declared requirement is also used as an identifier in code, attach that as extra evidence to the same entry.
  for(const [k,nm] of reqFound){
    if(!/^[A-Za-z_]\w*$/.test(nm))continue;
    const re2=new RegExp('\\b'+nm+'\\b','g');let m2,n=0;
    while((m2=re2.exec(clean))&&n<5){const line=lineAt(m2.index);if(reqLines.has(line))continue;n++;deps.push({key:k,name:nm,type:'Code reference',status:'API usage clue',line,source:context(line),match:m2[0],level:'inferred'});}
  }
  // Warnings based on source patterns, not execution.
  const warn=(key,severity,title,detail,line)=>add(warnings,{key,severity,title,detail,line,source:context(line)});
  if(!src.trim()) warn('empty','high','Empty source','The selected file contains no readable source.',1);
  if(/\beval\s*\(|new\s+Function\s*\(/.test(clean)){const i=clean.search(/\beval\s*\(|new\s+Function\s*\(/);warn('dynamic-code','high','Dynamic code execution','eval() or new Function() makes static analysis less reliable and can execute generated code.',lineAt(i));}
  if(/\bdocument\.write\s*\(/.test(clean)){const i=clean.indexOf('document.write');warn('document-write','medium','document.write usage','This can be fragile or unavailable in a mod-loader context.',lineAt(i));}
  if(/\bimportScripts\s*\(/.test(clean)){const i=clean.indexOf('importScripts');warn('importscripts','medium','Runtime script loading','importScripts() requires a compatible worker context; it may not work in a normal page or mod loader.',lineAt(i));}
  if(/\brequire\s*\(/.test(clean)){const i=clean.indexOf('require(');warn('require','medium','CommonJS require() detected','require() usually needs a CommonJS-capable runtime or bundler; browsers do not provide it by default.',lineAt(i));}
  if(/\bprocess\.|__dirname\b|\bmodule\.exports\b/.test(clean)){const i=clean.search(/\bprocess\.|__dirname\b|\bmodule\.exports\b/);warn('node-api','medium','Node.js-specific pattern','Check whether the target Eaglercraft mod runtime provides Node.js globals.',lineAt(i));}
  // Resource-source analysis: what each fetch/asset call loads, where the data comes from, and who consumes it.
  // Add other known asset consumers here (call-name regex + owner library) and they are recognised the same way.
  const ASSET_SINKS=[{owner:'AsyncSink',label:'AsyncSink.setFile',call:/^AsyncSink\s*\.\s*setFile$/}];
  const NET_OK_HOSTS=/(^|\.)(raw\.githubusercontent\.com|githubusercontent\.com|github\.io|gitlab\.io|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com)$/i;
  const NET_SKIP_ROOT=/^(?:Promise|JSON|Object|Array|Math|String|Number|Uint8Array|ArrayBuffer|URL|Blob|Response|Request|Error|Date)$/;
  const assets=[],netGroups=new Map(),sinkCalls=new Set();
  const trimIdx=(s,e)=>{while(s<e&&/\s/.test(src[s]))s++;while(e>s&&/\s/.test(src[e-1]))e--;return {s,e};};
  const closeQuoteIn=(str,i)=>{const q=str[i];let k=i+1;for(;;){const j=str.indexOf(q,k);if(j<0)return -1;let b=0,x=j-1;while(x>i&&str.charCodeAt(x)===92){b++;x--;}if(!(b&1))return j;k=j+1;}}; // indexOf-based: skips huge embedded strings fast
  const closeQuote=i=>closeQuoteIn(src,i);
  const scanArgs=start=>{ // start = index just after '('; returns trimmed [s,e) offsets for each top-level argument
    const args=[];let depth=0,s=start,i=start;const lim=Math.min(src.length,start+12000000);
    for(;i<lim;i++){
      const c=clean[i];
      if(c==='"'||c==="'"||c==='`'){const j=closeQuoteIn(clean,i);if(j<0){i=lim;break;}i=j;continue;}
      if(c==='('||c==='['||c==='{'){depth++;continue;}
      if(c===')'||c===']'||c==='}'){if(depth===0){args.push(trimIdx(s,i));return {args,end:i+1};}depth--;continue;}
      if(c===','&&depth===0){args.push(trimIdx(s,i));s=i+1;}
    }
    args.push(trimIdx(s,i));return {args,end:i};
  };
  const litOf=a=>{ // whole argument is one string literal -> {head,len,tpl}
    if(!a||a.e<=a.s)return null;const q=src[a.s];
    if(q!=='"'&&q!=="'"&&q!=='`')return null;
    if(closeQuote(a.s)!==a.e-1)return null;
    return {head:src.slice(a.s+1,Math.min(a.e-1,a.s+601)),len:a.e-a.s-2,tpl:q==='`'&&src.slice(a.s,Math.min(a.e,a.s+4000)).includes('${')};
  };
  const resolveVar=id=>{const m=new RegExp('(?:const|let|var)\\s+'+id.replace(/[$.]/g,'\\$&')+'\\s*=\\s*(?=["\'`])').exec(clean);if(!m)return null;const st=m.index+m[0].length,e=closeQuote(st);return e<0?null:litOf({s:st,e:e+1});};
  const argLit=a=>{ // literal, variable-resolved literal, or partial literal prefix (concatenation)
    let lit=litOf(a),dyn=false;
    if(!lit&&a&&a.e>a.s){
      const t=src.slice(a.s,Math.min(a.e,a.s+80));
      if(/^[A-Za-z_$][\w$]*$/.test(t.trim())&&a.e-a.s<=80)lit=resolveVar(t.trim());
      else if(/^["'`]/.test(t)){const e=closeQuote(a.s);if(e>0){lit=litOf({s:a.s,e:e+1});if(lit)lit.tpl=true;}}
    }
    return lit;
  };
  const classify=lit=>{
    if(!lit)return {cls:'unknown',host:'unresolved target'};
    const u=lit.head;
    if(/^data:/i.test(u)){const mm=u.match(/^data:([^;,]*)((?:;[^,]*)?),/i),b64=!!(mm&&/;base64/i.test(mm[2]));return {cls:'inline',host:'embedded data URL',mime:(mm&&mm[1])||'unknown',bytes:Math.round((lit.len-(mm?mm[0].length:0))*(b64?0.75:1))};}
    if(/^blob:/i.test(u))return {cls:'inline',host:'blob URL',mime:'',bytes:0};
    if(/^(?:https?:|wss?:)?\/\//i.test(u)){let host;try{host=new URL(u.startsWith('//')?'https:'+u:u).host;}catch(e){host='';}if(!host||host.includes('$'))host=u.replace(/^[a-z]+:\/\//i,'').replace(/^\/\//,'').split(/[\/?#$]/)[0]||'unresolved host';return {cls:'external',host,url:u,insecure:/^(?:http|ws):/i.test(u)};}
    return {cls:'relative',host:'same origin / relative path',url:u};
  };
  const assetKind=p=>{const l=(p||'').toLowerCase();return /\/models?\//.test(l)?'Model':/\/sounds?\//.test(l)||/\.(ogg|mp3|wav)$/.test(l)?'Sound':/\/lang\//.test(l)||/\.lang$/.test(l)?'Language file':/\/textures?\//.test(l)||/\.(png|jpe?g|gif|webp)$/.test(l)?'Texture':/\.json$/.test(l)?'JSON data':'Resource file';};
  const sizeText=n=>n>=1048576?(n/1048576).toFixed(1)+' MB':n>=1024?(n/1024).toFixed(1)+' KB':n+' B';
  const clip=t=>t.replace(/(data:[^;,"'`\s]*;base64,)[A-Za-z0-9+\/=]{24,}/g,'$1\u2026');
  const addAsset=(o)=>{
    if(assets.some(a=>a.line===o.line&&a.path===o.path&&a.consumer===o.consumer))return;
    const where=o.cls==='inline'?`embedded in the file (${o.host}${o.mime?', '+o.mime:''}${o.bytes?', ~'+sizeText(o.bytes):''})`:o.cls==='external'?'remote: '+o.host:o.cls==='relative'?'relative path '+(o.url||''):'generated or resolved at runtime';
    assets.push({...o,kind:o.kind||assetKind(o.path),origin:where,network:o.cls==='external'||o.cls==='relative'});
  };
  const sinkOf=ctx=>ASSET_SINKS.find(s=>s.call.test(ctx));
  const sinkDep=(sink,a,line,snippet)=>{if(!deps.some(d=>d.key==='lib:'+canon(sink.owner)&&d.line===line&&d.type==='Asset library'))deps.push({key:'lib:'+canon(sink.owner),name:sink.owner,type:'Asset library',status:'Asset loading detected',line,source:snippet,match:sink.label+'("'+(a.path.length>70?'\u2026'+a.path.slice(-67):a.path)+'")',level:'inferred'});};
  const netRe=/\bfetch\s*\(|\bnew\s+WebSocket\s*\(|\bnew\s+EventSource\s*\(|\bnavigator\.sendBeacon\s*\(|\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE|HEAD|PATCH)['"`]\s*,|\bnew\s+XMLHttpRequest\b/g;
  let nm;
  while((nm=netRe.exec(clean))){
    const head=nm[0];
    const kind=/XMLHttpRequest|^\.open/.test(head)?'XMLHttpRequest':/WebSocket/.test(head)?'WebSocket':/EventSource/.test(head)?'EventSource':/sendBeacon/.test(head)?'sendBeacon':'fetch';
    if(/^new\s+XMLHttpRequest/.test(head)&&/\.open\s*\(\s*['"`][A-Z]+['"`]/.test(clean))continue;
    const bare=/^new\s+XMLHttpRequest/.test(head);
    const {args,end}=bare?{args:[],end:nm.index+head.length}:scanArgs(nm.index+head.length);
    const lit=bare?null:argLit(args[0]);
    const info=classify(lit);const dynamic=!lit||lit.tpl;
    // Consumer: outermost call of the same statement, e.g. AsyncSink.setFile(...)
    const base=Math.max(0,nm.index-400),pre=clean.slice(base,nm.index);
    const sb=Math.max(pre.lastIndexOf(';'),pre.lastIndexOf('{'),pre.lastIndexOf('}'))+1,stmtStart=base+sb;
    const stmt=pre.slice(sb).replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g,'""');
    const calls=[...stmt.matchAll(/([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(/g)].map(x=>x[1].replace(/\s+/g,'')).filter(n=>n!=='await'&&n!=='fetch'&&n!=='async');
    const ctx=calls[0]||'';
    const rt=(clean.slice(end,end+60).match(/^\s*\)?\s*\.\s*(arrayBuffer|blob|json|text|formData)\s*\(/)||[])[1]||'';
    const line=lineAt(nm.index),endLine=lineAt(end);
    const snippet=clip(lines.slice(line-1,Math.min(endLine,line+3)).map(x=>x.trim().slice(0,600)).join(' ')).slice(0,320);
    const sink=sinkOf(ctx);let path=null;
    if(sink){
      const ci=clean.indexOf(ctx.split('.')[0],stmtStart),paren=ci<0?-1:clean.indexOf('(',ci);
      if(paren>=0&&paren<nm.index){sinkCalls.add(paren);const sa=scanArgs(paren+1);const pl=litOf(sa.args[0]);path=pl?pl.head:null;}
    }
    if(info.cls==='inline'||(sink&&info.cls!=='unknown')){
      addAsset({path:path||'(path not a literal)',consumer:sink?sink.label:(ctx||'unknown consumer'),owner:sink?sink.owner:'',line,snippet,cls:info.cls,host:info.host,mime:info.mime,bytes:info.bytes,url:info.url,via:kind});
      if(sink)sinkDep(sink,{path:path||'(path not a literal)'},line,snippet);
    }
    if(info.cls==='inline')continue; // embedded data makes no network request: not a compatibility warning
    const gk=kind+'|'+info.cls+'|'+info.host;
    if(!netGroups.has(gk))netGroups.set(gk,{kind,cls:info.cls,host:info.host,items:[]});
    netGroups.get(gk).items.push({line,url:lit?lit.head:null,insecure:info.insecure,dynamic,ctx,rt,snippet,sink:sink?sink.label:'',path});
  }
  // Asset registrations that do not go through fetch (data passed in directly or built elsewhere).
  for(const sink of ASSET_SINKS){
    const sre=new RegExp('\\b'+sink.label.replace(/\./g,'\\s*\\.\\s*')+'\\s*\\(','g');let sm;
    while((sm=sre.exec(clean))){
      const paren=sm.index+sm[0].length-1;if(sinkCalls.has(paren))continue;sinkCalls.add(paren);
      const sa=scanArgs(paren+1),pl=litOf(sa.args[0]),dl=sa.args[1]?argLit(sa.args[1]):null;
      const info=dl?classify(dl):{cls:'unknown',host:'generated or resolved at runtime'};
      const line=lineAt(sm.index);
      const snippet=clip(lines[line-1]||'').trim().slice(0,320);
      const path=pl?pl.head:'(path not a literal)';
      addAsset({path,consumer:sink.label,owner:sink.owner,line,snippet,cls:info.cls,host:info.host,mime:info.mime,bytes:info.bytes,url:info.url,via:'direct'});
      sinkDep(sink,{path},line,snippet);
    }
  }
  for(const g of netGroups.values()){
    const insecure=g.items.some(x=>x.insecure);
    let sev,why;
    if(g.cls==='relative'){sev='low';why='Relative path: works only if the loader serves that file from the same origin as the page.';}
    else if(g.cls==='unknown'||g.items.every(x=>x.dynamic)){sev='medium';why='The target is assembled at runtime, so the host cannot be determined statically.';}
    else if(insecure){sev='medium';why='Plain http/ws on an https page is blocked as mixed content.';}
    else if(NET_OK_HOSTS.test(g.host)){sev='low';why=g.host+' normally allows cross-origin reads, but this is not verified here. It still fails offline or if the loader blocks the host.';}
    else{sev='medium';why=g.host+' must send CORS headers (Access-Control-Allow-Origin) or the browser blocks the read. It also fails offline or if the loader restricts hosts.';}
    const ctxs=[...new Set(g.items.map(x=>x.ctx).filter(Boolean))];
    const rts=[...new Set(g.items.map(x=>x.rt).filter(Boolean))];
    const urls=[...new Set(g.items.map(x=>x.url).filter(Boolean))];
    const first=g.items[0],lns=[...new Set(g.items.map(x=>x.line))];
    const detail=[why,
      urls.length?'Loads: '+urls.slice(0,2).map(u=>u.length>110?u.slice(0,110)+'\u2026':u).join(', ')+(urls.length>2?' (+'+(urls.length-2)+' more)':''):'',
      ctxs.length?'Response feeds '+ctxs.join(', ')+'()'+(rts.length?' via .'+rts.join('/.')+'()':'')+'. If this request is blocked, that call gets no data.':'',
      lns.length>1?'Lines '+lns.join(', ')+'.':''].filter(Boolean).join(' ');
    warnings.push({key:'network:'+g.kind+'|'+g.cls+'|'+g.host,severity:sev,title:'Network access: '+g.kind+' \u2192 '+g.host,detail,line:first.line,source:g.items.slice(0,3).map(x=>'L'+x.line+': '+x.snippet).join('\n')});
    if(g.cls==='external')deps.push({key:'remote:'+g.host,name:g.host,type:'Remote resource',status:'Runtime fetch',line:first.line,source:first.snippet,match:(urls[0]||g.host).slice(0,140),level:'inferred',detail:'Fetched at runtime ('+g.kind+'). '+(ctxs.length?'Consumed by '+ctxs.join(', ')+'().':'')});
    for(const c of ctxs){const root=c.split('.')[0];if(sinkOf(c)||!/^[A-Z]/.test(root)||NET_SKIP_ROOT.test(root))continue;for(const x of g.items.filter(x=>x.ctx===c&&!deps.some(d=>d.key==='lib:'+canon(root)&&d.line===x.line)))deps.push({key:'lib:'+canon(root),name:root,type:'Code reference',status:'API usage clue',line:x.line,source:x.snippet,match:c+'(\u2026'+g.kind+'\u2026)',level:'inferred'});}
  }
  if(/\b(?:chrome|browser)\.runtime\b/.test(clean)){const i=clean.search(/\b(?:chrome|browser)\.runtime\b/);warn('extension-api','medium','Browser-extension API','Browser extension APIs are not generally available to ordinary web scripts.',lineAt(i));}
  if(/(?:TODO|FIXME|HACK)/i.test(clean)){const i=clean.search(/(?:TODO|FIXME|HACK)/i);warn('todo','low','Unfinished-work marker','TODO/FIXME/HACK marker found; inspect before relying on this mod.',lineAt(i));}
  // Heuristic delimiter balance (comments/strings can cause false positives).
  [['{','}',0],['(',')',1],['[',']',2]].forEach(([open,close,k])=>{if(balance.bad[k]||balance.cnt[k]!==0)warn('balance-'+open,'low','Possible unmatched '+open+close,'A lightweight delimiter check suggests unbalanced delimiters. This is not a full JavaScript parser.',1);});
  // Collapse multiple clues for the same integration into one canonical entry.
  const uniqueDeps=normalizeDeps(deps);
  // Version rows always clearly separate declared/inferred/unknown.
  return {name,bytes:opts.bytes??new TextEncoder().encode(src).length,lines:lines.length,versions,deps:uniqueDeps,warnings,assets,findings,metadata:extractMeta(src),source:src};
}
function depRank(s){return s==='Likely required'?5:/detected|Core API|Server-side|Required integration/i.test(s)?3:s==='Unverified'?2:1;}
function depGroupInfo(item){
  const nm=item.name||'',low=nm.toLowerCase();
  let info;
  if(low.includes('libcustomitems'))info={key:'lib:libcustomitems',name:'LibCustomItems',type:'External library',status:'Likely required'};
  else if(/^modapi(?![\w-])/i.test(nm))info={key:'api:modapi',name:'ModAPI',type:'Core API reference',status:'API usage detected'};
  else if(/^pluginapi(?![\w-])/i.test(nm))info={key:'api:pluginapi',name:'PluginAPI',type:'Plugin/server integration',status:'Integration detected'};
  else if(item.status==='Package/module specifier')info={key:'lib:'+nm.toLowerCase().replace(/[^a-z0-9]/g,''),name:nm,type:'Imported module',status:'Unverified',detail:'Role unknown: could be a loader-provided module, an npm package or another mod, and it cannot be determined whether it must be installed separately.'};
  else info={key:item.key,name:nm,type:item.type,status:item.status};
  if(item.type==='Declared requirement')info.status='Likely required';
  return info;
}
function normalizeDeps(items){
  const groups=new Map();
  for(const item of items){
    const info=depGroupInfo(item);
    const evs=item.evidences||[{line:item.line||null,match:item.match,source:item.source,kind:item.type,origin:item.origin,file:item.file}];
    const detail=info.detail||item.detail||'';
    let g=groups.get(info.key);
    if(!g){g={...item,...info,level:item.level,evidences:[],evidenceTypes:[],origins:[],details:[]};delete g.line;delete g.source;delete g.match;delete g.origin;groups.set(info.key,g);}
    else{
      if(depRank(info.status)>depRank(g.status)){g.status=info.status;g.type=info.type;}
      if(item.level==='declared')g.level='declared';
    }
    if(detail&&!g.details.includes(detail))g.details.push(detail);
    for(const e of evs){
      if(!g.evidences.some(x=>x.file===e.file&&x.line===e.line&&x.match===e.match&&x.kind===e.kind))g.evidences.push(e);
      const t=e.origin?'declared in '+e.origin:e.kind;
      if(e.origin&&!g.origins.includes(e.origin))g.origins.push(e.origin);
      if(t&&!g.evidenceTypes.includes(t))g.evidenceTypes.push(t);
    }
  }
  return [...groups.values()].map(g=>{
    g.evidences.sort((x,y)=>String(x.file||'').localeCompare(String(y.file||''))||(x.line||0)-(y.line||0));
    const lines=[];for(const e of g.evidences){if(!e.line)continue;const l=(e.file?e.file+':':'')+e.line;if(!lines.includes(l))lines.push(l);}
    return {...g,lines,line:g.evidences.find(e=>e.line)?.line||null,detail:g.details.join(' '),source:[...new Set(g.evidences.map(e=>e.source).filter(Boolean))].join('\n')};
  }).sort((a,b)=>depRank(b.status)-depRank(a.status));
}
function extractMeta(src){
  const out=[];
  const add=(label,value)=>{value=String(value||'').trim().replace(/\*\/$/,'').slice(0,220);if(value&&!out.some(x=>x.label===label))out.push({label,value});};
  const pats=[['Name',/(?:@name|mod\s*name|name)\s*[:=]\s*["']?([^"'\r\n*]+)/i],['Version',/(?:@version|mod\s*version|version)\s*[:=]\s*["']?([0-9][\w.+-]*)/i],['Author',/(?:@author|author)\s*[:=]\s*["']?([^"'\r\n*]+)/i],['Description',/(?:@description|mod\s*description|description)\s*[:=]\s*["']?([^"'\r\n*]+)/i],['Declared dependencies',/(?:depends|dependencies|requires|requirement)\s*[:=]\s*([^\r\n*]+)/i]];
  for(const [label,re] of pats){const m=src.match(re);if(m)add(label,m[1]);}
  // Eaglercraft ModAPI metadata methods are executable calls, not key/value comments.
  const calls=[
    ['Name',/\bModAPI\.meta\.title\s*\(\s*(['"`])([\s\S]*?)\1\s*\)/],
    ['Author',/\bModAPI\.meta\.credits\s*\(\s*(['"`])([\s\S]*?)\1\s*\)/],
    ['Description',/\bModAPI\.meta\.description\s*\(\s*(['"`])([\s\S]*?)\1\s*\)/]
  ];
  for(const [label,re] of calls){const m=src.match(re);if(m)add(label,m[2]);}
  return out;
}


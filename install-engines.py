#!/usr/bin/env python3
"""Install pinned official engine releases and register their paths with VPNSOPR."""
import argparse,concurrent.futures,gzip,hashlib,json,os,pathlib,platform,re,shutil,struct,sys,tarfile,tempfile,urllib.request,zipfile
BASE=pathlib.Path(__file__).resolve().parent
MAX_FILE=512*1024*1024

def atomic(path,data,mode=0o600):
 path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 fd,temp=tempfile.mkstemp(prefix='.vpnsopr-',dir=path.parent)
 try:
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  os.chmod(temp,mode);os.replace(temp,path)
 finally:
  if os.path.exists(temp):os.unlink(temp)

def download(item,path):
 if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==item['sha256']:return
 req=urllib.request.Request(item['url'],headers={'User-Agent':'VPNSOPR-engine-installer'})
 h=hashlib.sha256();total=0;temp=path.with_suffix('.partial')
 try:
  with urllib.request.urlopen(req,timeout=120) as r,open(temp,'wb') as f:
   if not r.url.startswith('https://'):raise ValueError('Non-HTTPS download redirect')
   while data:=r.read(1<<20):
    total+=len(data)
    if total>MAX_FILE:raise ValueError('Download exceeds size limit')
    h.update(data);f.write(data)
  if h.hexdigest()!=item['sha256']:raise ValueError('SHA256 mismatch: '+item['asset'])
  os.replace(temp,path)
 finally:
  if temp.exists():temp.unlink()

def safe_path(root,name):
 p=pathlib.PurePosixPath(name)
 if p.is_absolute() or '..' in p.parts:raise ValueError('Unsafe archive path')
 target=root.joinpath(*p.parts);target.parent.mkdir(parents=True,exist_ok=True);return target

def unpack(archive,item,root):
 total=0
 def write(name,data,size):
  nonlocal total
  total+=size
  if size>MAX_FILE or total>MAX_FILE:raise ValueError('Archive exceeds extraction limit')
  target=safe_path(root,name)
  with open(target,'wb') as f:shutil.copyfileobj(data,f)
  target.chmod(0o644)
 name=item['asset'].lower()
 if name.endswith('.zip'):
  with zipfile.ZipFile(archive) as z:
   for m in z.infolist():
    if m.is_dir():continue
    if (m.external_attr>>16)&0o170000==0o120000:raise ValueError('Archive symlink rejected')
    with z.open(m) as f:write(m.filename,f,m.file_size)
 elif name.endswith(('.tar.gz','.tar.xz','.tgz')):
  with tarfile.open(archive,'r:*') as z:
   for m in z:
    if m.isdir():continue
    if not m.isfile():raise ValueError('Archive link/device rejected')
    with z.extractfile(m) as f:write(m.name,f,m.size)
 elif name.endswith('.gz'):
  with gzip.open(archive,'rb') as f:
   blob=f.read(MAX_FILE+1)
   if len(blob)>MAX_FILE:raise ValueError('Gzip exceeds extraction limit')
   target=root/next(iter(item['binaries'].values()));target.write_bytes(blob)
 else:shutil.copyfile(archive,root/next(iter(item['binaries'].values())))

def install_one(item,args,arch):
 key=item['id'];expected={'amd64':62,'arm64':183,'armv7':40}[arch]
 try:
  cache=args.cache/(item['sha256']+'-'+item['asset']);download(item,cache)
  version=re.sub(r'[^A-Za-z0-9_.-]','_',item['version'])
  dest=args.prefix/key/version/arch
  with tempfile.TemporaryDirectory(prefix='.stage-',dir=args.prefix) as temp:
   stage=pathlib.Path(temp);unpack(cache,item,stage);bins={}
   for driver,basename in item['binaries'].items():
    matches=[p for p in stage.rglob(basename) if p.is_file()]
    if len(matches)!=1:raise ValueError('Expected one executable '+basename+'; found '+str(len(matches)))
    p=matches[0]
    with p.open('rb') as f:head=f.read(20)
    if len(head)<20 or head[:4]!=b'\x7fELF':raise ValueError('Not a Linux ELF executable: '+basename)
    endian='<' if head[5]==1 else '>'
    if struct.unpack(endian+'H',head[18:20])[0]!=expected:raise ValueError('Wrong CPU architecture: '+basename)
    p.chmod(0o755);bins[driver]=str(dest/p.relative_to(stage))
   dest.parent.mkdir(parents=True,exist_ok=True)
   if dest.exists():shutil.rmtree(dest)
   shutil.copytree(stage,dest)
  return {'id':key,'version':item['version'],'ok':True,'binaries':bins}
 except Exception as e:return {'id':key,'ok':False,'error':str(e)}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--plan',action='store_true');ap.add_argument('--stage',type=pathlib.Path);ap.add_argument('--only',default='');args=ap.parse_args()
 arch={'x86_64':'amd64','aarch64':'arm64','arm64':'arm64','armv7l':'armv7'}.get(platform.machine())
 lock=json.loads((BASE/'engines.lock.json').read_text())
 if not arch or arch not in lock['platforms']:raise SystemExit('Unsupported CPU architecture')
 items=lock['platforms'][arch]
 if args.only:
  names=set(args.only.split(','));items=[x for x in items if x['id'] in names]
  if names-{x['id'] for x in items}:raise SystemExit('Unknown or unsupported engine selection')
 if args.plan:
  print(json.dumps({'arch':arch,'downloads':[{'id':i['id'],'version':i['version'],'binaries':list(i['binaries'])} for i in items],'system_packages':lock['system_packages'],'unavailable':lock.get('unavailable',{}).get(arch,[])},indent=2));return
 if args.stage:
  args.stage=args.stage.resolve();args.prefix=args.stage/'engines';args.cache=args.stage/'cache'
 else:
  if os.geteuid()!=0:raise SystemExit('Run as root')
  args.prefix=pathlib.Path('/opt/vpnsopr/engines');args.cache=pathlib.Path('/var/cache/vpnsopr/engines')
 args.prefix.mkdir(parents=True,exist_ok=True);args.cache.mkdir(parents=True,exist_ok=True)
 results=[];bins={}
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
  for result in pool.map(lambda x:install_one(x,args,arch),items):
   results.append(result)
   if result['ok']:bins.update(result['binaries']);print('OK '+result['id'],flush=True)
   else:print('FAILED '+result['id']+': '+result['error'],flush=True)
 if not args.stage:
  for driver,choices in {'ssh':['ssh'],'openvpn':['openvpn'],'kcptun-client':['kcptun-client'],'kcptun-server':['kcptun-server']}.items():
   binary=next((shutil.which(x,path='/usr/sbin:/usr/bin:/sbin:/bin') for x in choices if shutil.which(x,path='/usr/sbin:/usr/bin:/sbin:/bin')),None)
   if binary:bins[driver]=binary;results.append({'id':driver,'ok':True,'binaries':{driver:binary},'source':'distribution package'})
   else:results.append({'id':driver,'ok':False,'error':'Distribution package executable not found'})
  env=pathlib.Path('/etc/vpnsopr/panel.env');lines=env.read_text().splitlines() if env.exists() else []
  old={}
  for line in lines:
   if line.startswith('VPNSOPR_ADAPTER_BINARIES='):
    try:old=json.loads(line.split('=',1)[1].strip().strip("'"))
    except ValueError:raise SystemExit('Existing adapter map is invalid; environment was not changed')
  old.update(bins);updates={'VPNSOPR_ADAPTER_BINARIES':json.dumps(old,separators=(',',':'))}
  if 'xray' in bins:updates.update(VPNSOPR_XRAY=bins['xray'],XRAY_LOCATION_ASSET=str(pathlib.Path(bins['xray']).parent))
  kept=[line for line in lines if line.split('=',1)[0] not in updates]
  atomic(env,('\n'.join(kept+[k+'='+v for k,v in updates.items()])+'\n').encode())
 report={'arch':arch,'results':results,'unavailable':lock.get('unavailable',{}).get(arch,[])}
 report_path=(args.stage/'engine-install-report.json') if args.stage else pathlib.Path('/var/lib/vpnsopr/engine-install-report.json')
 atomic(report_path,json.dumps(report,indent=2).encode(),0o644)
 failures=[r for r in results if not r['ok']]
 print('Installation report: '+str(report_path))
 if failures or report['unavailable']:raise SystemExit(2)
if __name__=='__main__':main()

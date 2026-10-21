from flask import Flask, request, redirect, url_for, render_template_string, send_file, flash
import sqlite3, os, io, shutil, tempfile, json, hashlib, platform, uuid, re
import ctypes
from datetime import datetime
from openpyxl import Workbook
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

APP_DIR=os.path.dirname(os.path.abspath(__file__)); DB=os.path.join(APP_DIR,'car_stock.sqlite3')
LICENSE_FILE=os.path.join(APP_DIR,'car_stock_license.json')
TRIAL_DAYS=7
TRIAL_EXPIRED_MESSAGE='انتهت الفترة التجريبية ، يرجى التواصل للتفعيل'
# مفتاح عام فقط للتحقق. المفتاح الخاص وأداة الإصدار خارج حزمة العميل بالكامل.
_PUBLIC_KEY=bytes.fromhex('8E2FFD6C3547F8C7B3BF4F3ED03C0BCDD3E1EDFBB3C5FF20FB4FEF642037CD7B')
app=Flask(__name__); app.secret_key='local-car-stock-ar'

def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def device_fingerprint():
 try:
  machine_guid=''
  if platform.system().lower()=='windows':
   import winreg
   with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\\Microsoft\\Cryptography') as key:
    machine_guid=str(winreg.QueryValueEx(key,'MachineGuid')[0])
  raw='|'.join((machine_guid,platform.node(),str(uuid.getnode()),platform.system(),platform.machine()))
  return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:20].upper()
 except Exception:
  raw='|'.join((platform.node(),str(uuid.getnode()),platform.system(),platform.machine()))
  return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:20].upper()

def client_id(): return 'CS-'+device_fingerprint()[:10]

def activation_payload(cid, fingerprint, expires):
 return f'CAR-STOCK|{cid}|{fingerprint}|{expires}'.encode('utf-8')

def _decode_signature(value):
 try:
  return bytes.fromhex(value)
 except (ValueError, TypeError):
  return b''

def hide_license_file():
 # الإخفاء البسيط يمنع ظهوره في Explorer بالإعدادات العادية، لكنه ليس تشفيرًا.
 if platform.system().lower()!='windows' or not os.path.exists(LICENSE_FILE): return
 try:
  FILE_ATTRIBUTE_HIDDEN=0x2
  ctypes.windll.kernel32.SetFileAttributesW(str(LICENSE_FILE),FILE_ATTRIBUTE_HIDDEN)
 except (AttributeError,OSError):
  pass

def valid_activation(code):
 parts=[p.strip() for p in (code or '').split('-')]
 if len(parts)!=5 or parts[0].upper()!='CS3' or parts[1].upper()!='CLIENT' or len(parts[2])!=10 or parts[3].upper() not in ('PERM',): return False, None
 cid='CS-'+parts[2].upper(); expires=parts[3].upper()
 try:
  Ed25519PublicKey.from_public_bytes(_PUBLIC_KEY).verify(_decode_signature(parts[4]),activation_payload(cid,device_fingerprint(),expires))
  return True, cid
 except (InvalidSignature, ValueError):
  return False, None

def load_license():
 try:
  with open(LICENSE_FILE,'r',encoding='utf-8') as f: data=json.load(f)
  if not isinstance(data,dict) or not data.get('trial_started_at'): raise ValueError('invalid license')
  if data.get('device_fingerprint') not in (None,device_fingerprint()): raise ValueError('foreign license')
  if data.get('activated') is True:
   if data.get('client_id') != client_id() or data.get('expires') != 'PERM' or not data.get('activation_signature'): raise ValueError('invalid activation')
   Ed25519PublicKey.from_public_bytes(_PUBLIC_KEY).verify(_decode_signature(data['activation_signature']),activation_payload(data['client_id'],data['device_fingerprint'],data['expires']))
  hide_license_file()
  return data
 except (OSError,ValueError,TypeError,InvalidSignature,json.JSONDecodeError):
  data={'trial_started_at':datetime.utcnow().isoformat(timespec='seconds')+'Z','activated':False,'device_fingerprint':device_fingerprint(),'client_id':client_id(),'expires':'','activation_signature':''}
  with open(LICENSE_FILE,'w',encoding='utf-8') as f: json.dump(data,f,ensure_ascii=False,indent=2)
  hide_license_file()
  return data

def save_license(data):
 data['device_fingerprint']=device_fingerprint(); data['client_id']=client_id()
 with open(LICENSE_FILE,'w',encoding='utf-8') as f: json.dump(data,f,ensure_ascii=False,indent=2)
 hide_license_file()

def trial_expired():
 data=load_license()
 if data.get('activated') is True: return False
 try:
  started=datetime.fromisoformat(data['trial_started_at'].replace('Z','+00:00'))
  now=datetime.now(started.tzinfo)
  return (now-started).total_seconds() >= TRIAL_DAYS*24*60*60
 except (KeyError,TypeError,ValueError):
  return True

def locked_page():
 return render_template_string('''<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>انتهت الفترة التجريبية</title><style>body{margin:0;background:#f5f7fa;color:#17212b;font-family:Tahoma,Arial,sans-serif}.wrap{max-width:680px;margin:70px auto;padding:0 18px}.panel{background:#fff;border-radius:14px;padding:28px;box-shadow:0 5px 18px #dfe6eb;border-top:4px solid #b3261e}h1{color:#123b56}.msg{background:#ffe4e0;border-right:5px solid #b3261e;padding:15px;border-radius:8px;font-weight:bold;margin:18px 0}input,button{padding:11px;border:1px solid #c6d1d8;border-radius:7px;font:inherit;box-sizing:border-box;width:100%;margin-top:8px}button{background:#176b87;color:#fff;border:0;cursor:pointer}a{color:#176b87}.device{background:#eef6f8;padding:10px;border-radius:7px;direction:ltr;text-align:center;font-family:monospace;font-weight:bold;margin:6px 0 12px}</style><main class="wrap"><div class="panel"><h1>إدارة المخازن والسيارات</h1><div class="msg">{{message}}</div><p>معرّف العميل لهذا الجهاز:</p><div class="device">{{client_code}}</div><p>بصمة الجهاز:</p><div class="device">{{fingerprint}}</div><p>أرسل المعرّفين للمورّد للحصول على كود تفعيل مرتبط بهذا الجهاز. يمكنك الاستمرار في عرض <a href="/reports">التقارير</a> وتصديرها.</p><form method="post" action="/activate"><label>كود التفعيل<input name="activation_code" autocomplete="off" required></label><button>تفعيل النسخة</button></form></div></main></html>''',message=TRIAL_EXPIRED_MESSAGE,client_code=client_id(),fingerprint=device_fingerprint())

@app.before_request
def enforce_trial():
 if not trial_expired(): return None
 # بعد انتهاء التجربة لا تُسمح إلا شاشة التقارير والتصدير والتفعيل.
 if request.endpoint in ('reports','xlsx','activate'): return None
 return locked_page()

def init():
 c=db(); c.executescript('''CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,name TEXT NOT NULL,code TEXT,unit TEXT NOT NULL,active INTEGER DEFAULT 1,min_qty REAL DEFAULT 0);CREATE TABLE IF NOT EXISTS cars(id INTEGER PRIMARY KEY,name TEXT NOT NULL,plate TEXT,driver TEXT,active INTEGER DEFAULT 1);CREATE TABLE IF NOT EXISTS receipts(id INTEGER PRIMARY KEY,dt TEXT NOT NULL,status TEXT DEFAULT 'draft',notes TEXT);CREATE TABLE IF NOT EXISTS receipt_lines(id INTEGER PRIMARY KEY,receipt_id INTEGER,product_id INTEGER,qty REAL,cost REAL);CREATE TABLE IF NOT EXISTS shipments(id INTEGER PRIMARY KEY,dt TEXT NOT NULL,car_id INTEGER,status TEXT DEFAULT 'draft',notes TEXT);CREATE TABLE IF NOT EXISTS shipment_lines(id INTEGER PRIMARY KEY,shipment_id INTEGER,product_id INTEGER,qty REAL,cost REAL);CREATE TABLE IF NOT EXISTS returns(id INTEGER PRIMARY KEY,dt TEXT NOT NULL,car_id INTEGER,status TEXT DEFAULT 'draft',notes TEXT);CREATE TABLE IF NOT EXISTS return_lines(id INTEGER PRIMARY KEY,return_id INTEGER,product_id INTEGER,qty REAL,cost REAL);CREATE TABLE IF NOT EXISTS sales(id INTEGER PRIMARY KEY,dt TEXT NOT NULL,car_id INTEGER,status TEXT DEFAULT 'draft',notes TEXT);CREATE TABLE IF NOT EXISTS sale_lines(id INTEGER PRIMARY KEY,sale_id INTEGER,product_id INTEGER,qty REAL,price REAL,cost REAL);CREATE TABLE IF NOT EXISTS counts(id INTEGER PRIMARY KEY,kind TEXT,car_id INTEGER,start_dt TEXT,end_dt TEXT,count_dt TEXT,status TEXT DEFAULT 'draft',notes TEXT);CREATE TABLE IF NOT EXISTS count_lines(id INTEGER PRIMARY KEY,count_id INTEGER,product_id INTEGER,system_qty REAL,actual_qty REAL,cost REAL);'''); c.commit(); c.close()

def q(sql,args=(),one=False):
 c=db(); r=c.execute(sql,args); x=r.fetchone() if one else r.fetchall(); c.close(); return x

def ex(sql,args=()):
 c=db(); x=c.execute(sql,args).lastrowid; c.commit(); c.close(); return x

def fmt(x):
 try:
  n=float(x); return str(int(n)) if n.is_integer() else f'{n:.2f}'
 except: return str(x or '')

def products(): return q('SELECT * FROM products WHERE active=1 ORDER BY name')
def cars(): return q('SELECT * FROM cars WHERE active=1 ORDER BY name')
def stock_stats(pid=None):
 where='AND p.id=?' if pid else ''; args=(pid,) if pid else ()
 return q(f'''SELECT p.id,p.name,p.code,p.unit,
 COALESCE((SELECT SUM(l.qty) FROM receipt_lines l JOIN receipts h ON h.id=l.receipt_id WHERE l.product_id=p.id AND h.status='approved'),0) incoming,
 COALESCE((SELECT SUM(l.qty) FROM shipment_lines l JOIN shipments h ON h.id=l.shipment_id WHERE l.product_id=p.id AND h.status='approved'),0) shipped,
 COALESCE((SELECT SUM(l.qty) FROM sale_lines l JOIN sales h ON h.id=l.sale_id WHERE l.product_id=p.id AND h.status='approved'),0) sold,
 COALESCE((SELECT SUM(l.qty) FROM return_lines l JOIN returns h ON h.id=l.return_id WHERE l.product_id=p.id AND h.status='approved'),0) returned
 FROM products p WHERE p.active=1 {where} ORDER BY p.name''',args)
def car_stats(cid):
 return q('''SELECT p.id,p.name,p.code,p.unit,
 COALESCE((SELECT SUM(l.qty) FROM shipment_lines l JOIN shipments h ON h.id=l.shipment_id WHERE l.product_id=p.id AND h.car_id=? AND h.status='approved'),0) shipped,
 COALESCE((SELECT SUM(l.qty) FROM sale_lines l JOIN sales h ON h.id=l.sale_id WHERE l.product_id=p.id AND h.car_id=? AND h.status='approved'),0) sold,
 COALESCE((SELECT SUM(l.qty) FROM return_lines l JOIN returns h ON h.id=l.return_id WHERE l.product_id=p.id AND h.car_id=? AND h.status='approved'),0) returned
 FROM products p WHERE p.active=1 ORDER BY p.name''',(cid,cid,cid))
def warehouse_balance(pid):
 r=stock_stats(pid)[0]; return r['incoming']-r['shipped']+r['returned']
def car_balance(cid,pid):
 r=next((x for x in car_stats(cid) if x['id']==pid),None); return (r['shipped']-r['sold']-r['returned']) if r else 0

def shell(title,body):
 return render_template_string('''<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{title}}</title><style>body{margin:0;background:#f5f7fa;color:#17212b;font-family:Tahoma,Arial,sans-serif}nav{background:linear-gradient(115deg,#102a43,#176b87);padding:14px 3%;display:flex;gap:7px;flex-wrap:wrap;align-items:center;box-shadow:0 3px 14px #b5c4cf}nav b{font-size:20px;color:#fff;margin-left:auto}nav a{color:#fff;text-decoration:none;padding:8px 11px;background:#ffffff1c;border:1px solid #ffffff35;border-radius:7px}.wrap{max-width:1250px;margin:24px auto;padding:0 16px}h1{color:#123b56}h2{color:#176b87}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}.card{background:#fff;border-radius:14px;padding:18px;box-shadow:0 6px 20px #dce4ea;border-top:4px solid #e17b45}.num{font-size:30px;font-weight:bold;color:#176b87;margin-top:8px}.panel,.form{background:#fff;border-radius:14px;padding:18px;margin:16px 0;box-shadow:0 5px 18px #dfe6eb}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;align-items:end}.grid label{display:flex;flex-direction:column;gap:6px;font-weight:bold;color:#123b56}.grid input,.grid select,.grid button{width:100%;box-sizing:border-box}input,select,button{padding:10px;border:1px solid #c6d1d8;border-radius:7px;font:inherit}button,.btn{background:#e17b45;color:#fff;border:0;cursor:pointer;text-decoration:none;padding:10px 13px;border-radius:7px;display:inline-block}.btn.blue{background:#176b87}.btn.green{background:#2b8a62}.msg{background:#dff4e6;border-right:5px solid #2b8a62;padding:12px;border-radius:8px;margin:10px 0}.err{background:#ffe4e0;border-right-color:#c33}table{width:100%;border-collapse:collapse;background:#fff;margin:12px 0}th,td{border:1px solid #dbe2e7;padding:10px;text-align:right}th{background:#e7f0f4;color:#123b56}.muted{color:#6d7c86;font-size:13px}.actions{display:flex;gap:6px;flex-wrap:wrap}.btn.delete{background:#b3261e}.form h2{margin-top:0}.form{border-top:4px solid #176b87}.tag{padding:4px 8px;border-radius:12px;background:#e6f2f5}.danger{color:#b3261e;font-weight:bold}</style><body><nav><b>إدارة المخازن والسيارات</b><a href="/">الرئيسية</a><a href="/products">المنتجات</a><a href="/cars">السيارات</a><a href="/receipts">الوارد</a><a href="/shipments">الشحنات</a><a href="/sales">المبيعات</a><a href="/returns">المرتجعات</a><a href="/counts">الجرد</a><a href="/reports">التقارير</a><a href="/backup">النسخ الاحتياطي</a></nav><main class="wrap">{% for m in get_flashed_messages() %}<div class="msg">{{m}}</div>{% endfor %}<h1>{{title}}</h1>{{body|safe}}</main></body></html>''',title=title,body=body)

def options(items,label='name'): return ''.join(f'<option value="{x["id"]}">{x[label]}</option>' for x in items)
def status(s): return 'مسودة' if s=='draft' else 'معتمدة'
def date_input(name,label,default=''):
 return f'<label>{label}<input name="{name}" type="date" value="{default}" required></label>'

@app.route('/')
def home():
 today=datetime.now().strftime('%Y-%m-%d'); st=stock_stats(); ships=q("SELECT COUNT(*) n FROM shipments WHERE dt=? AND status='approved'",(today,),True)['n']; sales=q("SELECT COUNT(*) n FROM sales WHERE dt=? AND status='approved'",(today,),True)['n']; returns=q("SELECT COUNT(*) n FROM returns WHERE dt=? AND status='approved'",(today,),True)['n']
 body='<div class="cards"><div class="card">عدد المنتجات<div class="num">'+str(len(st))+'</div></div><div class="card">عدد السيارات<div class="num">'+str(len(cars()))+'</div></div><div class="card">شحنات اليوم<div class="num">'+str(ships)+'</div></div><div class="card">مبيعات اليوم<div class="num">'+str(sales)+'</div></div><div class="card">مرتجعات اليوم<div class="num">'+str(returns)+'</div></div></div><div class="panel"><h2>ملخص تقرير اليوم — '+today+'</h2><table><tr><th>المنتج</th><th>الوارد</th><th>المشحون للسيارات</th><th>المباع</th><th>المرتجع</th><th>المتبقي بالمخزن</th></tr>'
 for r in st:
  body+=f'<tr><td>{r["name"]}</td><td>{fmt(r["incoming"])}</td><td>{fmt(r["shipped"])}</td><td>{fmt(r["sold"])}</td><td>{fmt(r["returned"])}</td><td><b>{fmt(r["incoming"]-r["shipped"]+r["returned"])}</b> {r["unit"]}</td></tr>'
 body+='</table><p class="muted">المعادلة: المتبقي بالمخزن = الوارد − الشحنات + المرتجعات. المبيعات لا تخصم من المخزن الأساسي لأنها تخصم من رصيد السيارة.</p></div>'
 return shell('لوحة التحكم',body)

@app.route('/activate',methods=['POST'])
def activate():
 code=(request.form.get('activation_code') or '').strip()
 valid,cid=valid_activation(code)
 if valid and cid==client_id():
  data=load_license(); data['activated']=True; data['activated_at']=datetime.utcnow().isoformat(timespec='seconds')+'Z'; data['expires']='PERM'; data['activation_signature']=code.strip().split('-')[-1]; save_license(data)
  flash('تم تفعيل النسخة النهائية بنجاح'); return redirect('/')
 flash('كود التفعيل غير صحيح'); return locked_page()

@app.route('/products',methods=['GET','POST'])
def product_page():
 if request.method=='POST': ex('INSERT INTO products(name,code,unit,min_qty) VALUES(?,?,?,?)',(request.form['name'],request.form.get('code'),request.form['unit'],float(request.form.get('min_qty') or 0))); flash('تمت إضافة المنتج'); return redirect('/products')
 body='<div class="form"><form method="post" class="grid"><input name="name" placeholder="اسم المنتج" required><input name="code" placeholder="كود المنتج"><input name="unit" value="قطعة" placeholder="الوحدة" required><input name="min_qty" type="number" step="0.01" placeholder="الحد الأدنى"><button>إضافة المنتج</button></form></div><table><tr><th>اسم المنتج</th><th>الكود</th><th>الوحدة</th><th>الوارد</th><th>المشحون</th><th>المباع</th><th>المرتجع</th><th>المتبقي بالمخزن</th><th>إجراء</th></tr>'
 for r in stock_stats(): body+=f'<tr><td>{r["name"]}</td><td>{r["code"] or "—"}</td><td>{r["unit"]}</td><td>{fmt(r["incoming"])}</td><td>{fmt(r["shipped"])}</td><td>{fmt(r["sold"])}</td><td>{fmt(r["returned"])}</td><td><b>{fmt(r["incoming"]-r["shipped"]+r["returned"])}</b></td><td><form method="post" action="/delete/item/product/{r["id"]}" onsubmit="return confirm(\'هل أنت متأكد من إيقاف هذا المنتج؟ سيختفي من القوائم مع الاحتفاظ بالحركات السابقة.\')"><button class="btn delete" type="submit">حذف</button></form></td></tr>'
 return shell('المنتجات ورصيد المخزن',body+'</table>')

@app.route('/cars',methods=['GET','POST'])
def car_page():
 if request.method=='POST': ex('INSERT INTO cars(name,plate,driver) VALUES(?,?,?)',(request.form['name'],request.form.get('plate'),request.form.get('driver'))); flash('تمت إضافة السيارة'); return redirect('/cars')
 body='<div class="form"><form method="post" class="grid"><input name="name" placeholder="اسم أو رقم السيارة" required><input name="plate" placeholder="رقم اللوحة"><input name="driver" placeholder="اسم السائق"><button>إضافة السيارة</button></form></div><table><tr><th>السيارة</th><th>اللوحة</th><th>السائق</th><th>الرصيد</th><th>إجراء</th></tr>'
 for c in cars(): body+=f'<tr><td>{c["name"]}</td><td>{c["plate"] or "—"}</td><td>{c["driver"] or "—"}</td><td><a class="btn blue" href="/car/{c["id"]}">عرض الرصيد والتفاصيل</a></td><td><form method="post" action="/delete/item/car/{c["id"]}" onsubmit="return confirm(\'هل أنت متأكد من إيقاف هذه السيارة؟ ستختفي من القوائم مع الاحتفاظ بالحركات السابقة.\')"><button class="btn delete" type="submit">حذف</button></form></td></tr>'
 return shell('السيارات',body+'</table>')

@app.route('/car/<int:cid>')
def car_detail(cid):
 c=q('SELECT * FROM cars WHERE id=?',(cid,),True); body=f'<div class="panel"><h2>الرصيد التفصيلي: {c["name"]}</h2><table><tr><th>المنتج</th><th>المشحون</th><th>المباع</th><th>المرتجع</th><th>المتبقي مع السيارة</th></tr>'
 for r in car_stats(cid): body+=f'<tr><td>{r["name"]}</td><td>{fmt(r["shipped"])}</td><td>{fmt(r["sold"])}</td><td>{fmt(r["returned"])}</td><td><b>{fmt(r["shipped"]-r["sold"]-r["returned"])}</b> {r["unit"]}</td></tr>'
 return shell('رصيد السيارة',body+'</table><p class="muted">المعادلة: المتبقي مع السيارة = الشحنات − المبيعات − المرتجعات.</p></div>')

@app.route('/delete/item/<kind>/<int:item_id>', methods=['POST'])
def delete_master_item(kind,item_id):
 if kind not in ('product','car'):
  flash('نوع العنصر غير صالح'); return redirect(request.referrer or '/')
 table='products' if kind=='product' else 'cars'
 item=q(f'SELECT id,name,active FROM {table} WHERE id=?',(item_id,),True)
 if not item:
  flash('العنصر غير موجود'); return redirect(request.referrer or '/')
 if not item['active']:
  flash('العنصر متوقف بالفعل'); return redirect(request.referrer or '/')
 if kind=='product':
  warehouse_qty=warehouse_balance(item_id)
  if warehouse_qty>0:
   flash(f'لا يمكن إيقاف المنتج «{item["name"]}» لأن رصيد المخزن الحالي {fmt(warehouse_qty)}، ويجب أن يصبح الرصيد صفرًا أولًا.'); return redirect(request.referrer or '/')
  for car in q('SELECT id,name FROM cars WHERE active=1 ORDER BY name'):
   qty=car_balance(car['id'],item_id)
   if qty>0:
    flash(f'لا يمكن إيقاف المنتج «{item["name"]}» لأن رصيده مع السيارة «{car["name"]}» هو {fmt(qty)}، ويجب أن يصبح صفرًا أولًا.'); return redirect(request.referrer or '/')
 else:
  for product in car_stats(item_id):
   qty=product['shipped']-product['sold']-product['returned']
   if qty>0:
    flash(f'لا يمكن إيقاف السيارة «{item["name"]}» لأن رصيد المنتج «{product["name"]}» معها هو {fmt(qty)}، ويجب أن يصبح صفرًا أولًا.'); return redirect(request.referrer or '/')
 c=db(); c.execute(f'UPDATE {table} SET active=0 WHERE id=?',(item_id,)); c.commit(); c.close()
 flash('تم إيقاف العنصر بنجاح مع الاحتفاظ بالسجل السابق')
 return redirect(request.referrer or '/')


def simple_form(kind):
 now=datetime.now().strftime('%Y-%m-%d'); ps=options(products()); cs=options(cars())
 if kind=='receipt': return f'<div class="form"><h2>إضافة وارد للمخزن</h2><form method="post" class="grid">{date_input("dt","تاريخ الوارد",now)}<label>المنتج<select name="product_id" required>{ps}</select></label><label>الكمية<input name="qty" type="number" min="0.01" step="0.01" required></label><label>تكلفة الوحدة<input name="cost" type="number" min="0" step="0.01" required></label><input name="notes" placeholder="ملاحظات"><button>حفظ كمسودة</button></form></div>'
 if kind=='shipment': return f'<div class="form"><h2>إنشاء شحنة سيارة</h2><p class="muted">الشحنة المسودة لا تخصم من المخزن. الخصم يتم فقط بعد الاعتماد.</p><form method="post" class="grid">{date_input("dt","تاريخ الشحنة",now)}<label>السيارة<select name="car_id" required>{cs}</select></label><label>المنتج<select name="product_id" required>{ps}</select></label><label>عدد الوحدات<input name="qty" type="number" min="0.01" step="0.01" required></label><label>تكلفة الوحدة وقت الاعتماد<input name="cost" type="number" min="0" step="0.01" required></label><input name="notes" placeholder="ملاحظات"><button>حفظ كمسودة</button></form></div>'
 if kind=='sale': return f'<div class="form"><h2>تسجيل مبيعات سيارة</h2><form method="post" class="grid">{date_input("dt","تاريخ البيع",now)}<label>السيارة<select name="car_id" required>{cs}</select></label><label>المنتج<select name="product_id" required>{ps}</select></label><label>الكمية المباعة<input name="qty" type="number" min="0.01" step="0.01" required></label><label>سعر البيع للوحدة<input name="price" type="number" min="0" step="0.01" required></label><input name="notes" placeholder="ملاحظات"><button>حفظ كمسودة</button></form></div>'
 return f'<div class="form"><h2>تسجيل مرتجع إلى المخزن</h2><form method="post" class="grid">{date_input("dt","تاريخ المرتجع",now)}<label>السيارة<select name="car_id" required>{cs}</select></label><label>المنتج<select name="product_id" required>{ps}</select></label><label>الكمية المرتجعة<input name="qty" type="number" min="0.01" step="0.01" required></label><label>التكلفة<input name="cost" type="number" min="0" step="0.01" required></label><input name="notes" placeholder="سبب المرتجع أو ملاحظات"><button>حفظ كمسودة</button></form></div>'

def rows_for(kind):
 cfg={'receipt':('receipts','receipt_lines','receipt_id','الوارد'),'shipment':('shipments','shipment_lines','shipment_id','الشحنة'),'sale':('sales','sale_lines','sale_id','المبيعات'),'return':('returns','return_lines','return_id','المرتجع')}[kind]; t,lt,fk,_=cfg
 if kind=='receipt': return q(f'SELECT h.*,p.name product,l.qty,l.cost FROM {t} h JOIN {lt} l ON l.{fk}=h.id JOIN products p ON p.id=l.product_id ORDER BY h.id DESC')
 if kind=='sale': return q(f'SELECT h.*,c.name car,p.name product,l.qty,l.price,l.cost FROM {t} h JOIN {lt} l ON l.{fk}=h.id JOIN products p ON p.id=l.product_id JOIN cars c ON c.id=h.car_id ORDER BY h.id DESC')
 return q(f'SELECT h.*,c.name car,p.name product,l.qty,l.cost FROM {t} h JOIN {lt} l ON l.{fk}=h.id JOIN products p ON p.id=l.product_id JOIN cars c ON c.id=h.car_id ORDER BY h.id DESC')

@app.route('/receipts',methods=['GET','POST'])
def receipts():
 if request.method=='POST': rid=ex('INSERT INTO receipts(dt,status,notes) VALUES(?,'"'"'draft'"'"',?)',(request.form['dt'],request.form.get('notes'))); ex('INSERT INTO receipt_lines(receipt_id,product_id,qty,cost) VALUES(?,?,?,?)',(rid,request.form['product_id'],float(request.form['qty']),float(request.form['cost']))); flash(f'تم حفظ الوارد رقم {rid} كمسودة'); return redirect('/receipts')
 body=simple_form('receipt')+'<table><tr><th>رقم</th><th>التاريخ</th><th>المنتج</th><th>الكمية</th><th>التكلفة</th><th>الحالة</th><th>إجراء</th></tr>'
 for r in rows_for('receipt'): body+=f'<tr><td>{r["id"]}</td><td>{r["dt"]}</td><td>{r["product"]}</td><td>{fmt(r["qty"])}</td><td>{fmt(r["cost"])}</td><td>{status(r["status"])}</td><td>{(f'<div class=actions><a class=btn href=/approve/receipt/{r["id"]}>اعتماد</a><form method=post action=/delete/receipt/{r["id"]} onsubmit="return confirm(\"هل تريد حذف المسودة؟\")"><button class=\"btn delete\">حذف</button></form></div>' if r['status']=='draft' else '')}</td></tr>'
 return shell('الوارد إلى المخزن الأساسي',body+'</table>')

@app.route('/shipments',methods=['GET','POST'])
def shipments():
 if request.method=='POST': sid=ex('INSERT INTO shipments(dt,car_id,status,notes) VALUES(?,?,'"'"'draft'"'"',?)',(request.form['dt'],request.form['car_id'],request.form.get('notes'))); ex('INSERT INTO shipment_lines(shipment_id,product_id,qty,cost) VALUES(?,?,?,?)',(sid,request.form['product_id'],float(request.form['qty']),float(request.form['cost']))); flash(f'تم حفظ الشحنة رقم {sid} كمسودة'); return redirect('/shipments')
 body=simple_form('shipment')+'<table><tr><th>رقم</th><th>التاريخ</th><th>السيارة</th><th>المنتج</th><th>الكمية</th><th>التكلفة</th><th>الحالة</th><th>إجراء</th></tr>'
 for r in rows_for('shipment'): body+=f'<tr><td>{r["id"]}</td><td>{r["dt"]}</td><td>{r["car"]}</td><td>{r["product"]}</td><td>{fmt(r["qty"])}</td><td>{fmt(r["cost"])}</td><td>{status(r["status"])}</td><td>{(f'<div class=actions><a class=btn href=/approve/shipment/{r["id"]}>اعتماد</a><form method=post action=/delete/shipment/{r["id"]} onsubmit="return confirm(\"هل تريد حذف المسودة؟\")"><button class=\"btn delete\">حذف</button></form></div>' if r['status']=='draft' else '')}</td></tr>'
 return shell('شحنات السيارات',body+'</table>')

@app.route('/sales',methods=['GET','POST'])
def sales():
 if request.method=='POST': sid=ex('INSERT INTO sales(dt,car_id,status,notes) VALUES(?,?,'"'"'draft'"'"',?)',(request.form['dt'],request.form['car_id'],request.form.get('notes'))); pid=int(request.form['product_id']); cost=next((x['cost'] for x in q('SELECT sl.cost FROM shipment_lines sl JOIN shipments s ON s.id=sl.shipment_id WHERE s.car_id=? AND sl.product_id=? AND s.status="approved" ORDER BY s.id DESC',(request.form['car_id'],pid))),0); ex('INSERT INTO sale_lines(sale_id,product_id,qty,price,cost) VALUES(?,?,?,?,?)',(sid,pid,float(request.form['qty']),float(request.form['price']),cost)); flash(f'تم حفظ البيع رقم {sid} كمسودة'); return redirect('/sales')
 body=simple_form('sale')+'<table><tr><th>رقم</th><th>التاريخ</th><th>السيارة</th><th>المنتج</th><th>الكمية</th><th>سعر البيع للوحدة</th><th>إجمالي البيع</th><th>تكلفة الوحدة</th><th>الحالة</th><th>إجراء</th></tr>'
 for r in rows_for('sale'): body+=f'<tr><td>{r["id"]}</td><td>{r["dt"]}</td><td>{r["car"]}</td><td>{r["product"]}</td><td>{fmt(r["qty"])}</td><td><b>{fmt(r["price"])}</b></td><td><b>{fmt(r["qty"]*r["price"])}</b></td><td>{fmt(r["cost"])}</td><td>{status(r["status"])}</td><td>{(f'<div class=actions><a class=btn href=/approve/sale/{r["id"]}>اعتماد</a><form method=post action=/delete/sale/{r["id"]} onsubmit="return confirm(\"هل تريد حذف المسودة؟\")"><button class=\"btn delete\">حذف</button></form></div>' if r['status']=='draft' else '')}</td></tr>'
 return shell('المبيعات',body+'</table>')

@app.route('/returns',methods=['GET','POST'])
def returns_page():
 if request.method=='POST': rid=ex('INSERT INTO returns(dt,car_id,status,notes) VALUES(?,?,'"'"'draft'"'"',?)',(request.form['dt'],request.form['car_id'],request.form.get('notes'))); ex('INSERT INTO return_lines(return_id,product_id,qty,cost) VALUES(?,?,?,?)',(rid,request.form['product_id'],float(request.form['qty']),float(request.form['cost']))); flash(f'تم حفظ المرتجع رقم {rid} كمسودة'); return redirect('/returns')
 body=simple_form('return')+'<table><tr><th>رقم</th><th>التاريخ</th><th>السيارة</th><th>المنتج</th><th>الكمية</th><th>الحالة</th><th>إجراء</th></tr>'
 for r in rows_for('return'): body+=f'<tr><td>{r["id"]}</td><td>{r["dt"]}</td><td>{r["car"]}</td><td>{r["product"]}</td><td>{fmt(r["qty"])}</td><td>{status(r["status"])}</td><td>{(f'<div class=actions><a class=btn href=/approve/return/{r["id"]}>اعتماد</a><form method=post action=/delete/return/{r["id"]} onsubmit="return confirm(\"هل تريد حذف المسودة؟\")"><button class=\"btn delete\">حذف</button></form></div>' if r['status']=='draft' else '')}</td></tr>'
 return shell('المرتجعات إلى المخزن الأساسي',body+'</table>')

@app.route('/delete/<kind>/<int:item_id>', methods=['POST'])
def delete_draft(kind,item_id):
 cfg={'receipt':('receipts','receipt_lines','receipt_id'),'shipment':('shipments','shipment_lines','shipment_id'),'sale':('sales','sale_lines','sale_id'),'return':('returns','return_lines','return_id'),'count':('counts','count_lines','count_id')}
 if kind not in cfg: flash('نوع الحركة غير صالح'); return redirect(request.referrer or '/')
 table,line_table,line_key=cfg[kind]
 h=q(f'SELECT status FROM {table} WHERE id=?',(item_id,),True)
 if not h: flash('المسودة غير موجودة'); return redirect(request.referrer or '/')
 if h['status']!='draft': flash('لا يمكن حذف حركة معتمدة'); return redirect(request.referrer or '/')
 c=db(); c.execute(f'DELETE FROM {line_table} WHERE {line_key}=?',(item_id,)); c.execute(f'DELETE FROM {table} WHERE id=?',(item_id,)); c.commit(); c.close()
 flash('تم حذف المسودة بنجاح'); return redirect(request.referrer or '/')

@app.route('/approve/<kind>/<int:item_id>')
def approve(kind,item_id):
 cfg={'receipt':('receipts','receipt_lines','receipt_id'),'shipment':('shipments','shipment_lines','shipment_id'),'sale':('sales','sale_lines','sale_id'),'return':('returns','return_lines','return_id')};
 if kind not in cfg:return 'غير صالح',400
 t,lt,fk=cfg[kind]; h=q(f'SELECT * FROM {t} WHERE id=?',(item_id,),True); line=q(f'SELECT * FROM {lt} WHERE {fk}=?',(item_id,),True)
 if not h or h['status']!='draft': flash('الحركة غير متاحة للاعتماد'); return redirect(request.referrer or '/')
 if kind=='shipment' and line['qty']>warehouse_balance(line['product_id']): flash('مرفوض: الكمية المطلوبة أكبر من المتاح في المخزن'); return redirect(request.referrer or '/shipments')
 if kind in ('sale','return') and line['qty']>car_balance(h['car_id'],line['product_id']): flash('مرفوض: الكمية المطلوبة أكبر من رصيد السيارة'); return redirect(request.referrer or '/')
 ex(f'UPDATE {t} SET status="approved" WHERE id=?',(item_id,)); flash('تم اعتماد الحركة وتحديث الأرصدة'); return redirect(request.referrer or '/')

@app.route('/counts',methods=['GET','POST'])
def counts():
 if request.method=='POST':
  cid=ex('INSERT INTO counts(kind,car_id,start_dt,end_dt,count_dt,status,notes) VALUES(?,?,?,?,?,'"'"'draft'"'"',?)',(request.form['kind'],request.form['car_id'],request.form['start_dt'],request.form['end_dt'],request.form['count_dt'],request.form.get('notes')))
  for p in car_stats(int(request.form['car_id'])): ex('INSERT INTO count_lines(count_id,product_id,system_qty,actual_qty,cost) VALUES(?,?,?,?,?)',(cid,p['id'],p['shipped']-p['sold']-p['returned'],0,0))
  flash(f'تم إنشاء مسودة الجرد رقم {cid}، راجع تفاصيلها لإدخال العد الفعلي'); return redirect(f'/count/{cid}')
 now=datetime.now().strftime('%Y-%m-%d'); body=f'<div class="form"><h2>إنشاء جرد واضح</h2><form method="post" class="grid"><label>نوع الجرد<select name="kind"><option value="weekly">جرد أسبوعي</option><option value="monthly">جرد شهري</option></select></label><label>السيارة<select name="car_id" required>{options(cars())}</select></label>{date_input("start_dt","تاريخ البدء",now)}{date_input("end_dt","تاريخ الانتهاء",now)}{date_input("count_dt","تاريخ تنفيذ الجرد",now)}<input name="notes" placeholder="ملاحظات الجرد"><button>إنشاء مسودة الجرد</button></form></div><table><tr><th>رقم الجرد</th><th>النوع</th><th>السيارة</th><th>تاريخ البدء</th><th>تاريخ الانتهاء</th><th>تاريخ التنفيذ</th><th>الحالة</th><th>التفاصيل</th></tr>'
 for r in q('SELECT x.*,c.name car FROM counts x JOIN cars c ON c.id=x.car_id ORDER BY x.id DESC'): body+=f'<tr><td>{r["id"]}</td><td>{"أسبوعي" if r["kind"]=="weekly" else "شهري"}</td><td>{r["car"]}</td><td>{r["start_dt"]}</td><td>{r["end_dt"]}</td><td>{r["count_dt"]}</td><td>{status(r["status"])}</td><td><a class=btn blue href=/count/{r["id"]}>عرض التفاصيل</a></td></tr>'
 return shell('الجرد الأسبوعي والشهري',body+'</table>')

@app.route('/count/<int:cid>',methods=['GET','POST'])
def count_detail(cid):
 h=q('SELECT x.*,c.name car FROM counts x JOIN cars c ON c.id=x.car_id WHERE x.id=?',(cid,),True)
 if request.method=='POST':
  c=db()
  for l in q('SELECT * FROM count_lines WHERE count_id=?',(cid,)): c.execute('UPDATE count_lines SET actual_qty=? WHERE id=?',(float(request.form.get(f'a_{l["id"]}') or 0),l['id']))
  c.execute('UPDATE counts SET status="approved" WHERE id=?',(cid,)); c.commit(); c.close(); flash('تم اعتماد الجرد وحفظ الكميات الفعلية'); return redirect(f'/count/{cid}')
 body=f'<div class="panel"><h2>تفاصيل جرد {"أسبوعي" if h["kind"]=="weekly" else "شهري"} — {h["car"]}</h2><p><b>تاريخ البدء:</b> {h["start_dt"]} | <b>تاريخ الانتهاء:</b> {h["end_dt"]} | <b>تاريخ تنفيذ الجرد:</b> {h["count_dt"]} | <b>الحالة:</b> {status(h["status"])}</p><p class="muted">الرصيد الدفتري = الشحنات المعتمدة − المبيعات المعتمدة − المرتجعات المعتمدة. أدخل الكمية الفعلية ثم احفظ اعتماد الجرد.</p><form method="post"><table><tr><th>المنتج</th><th>الرصيد الدفتري</th><th>الكمية الفعلية المعدودة</th><th>الفرق</th></tr>'
 for l in q('SELECT l.*,p.name,p.unit FROM count_lines l JOIN products p ON p.id=l.product_id WHERE l.count_id=?',(cid,)):
  diff=(l['actual_qty'] or 0)-(l['system_qty'] or 0); body+=f'<tr><td>{l["name"]} ({l["unit"]})</td><td>{fmt(l["system_qty"])}</td><td><input name="a_{l["id"]}" type="number" step="0.01" value="{l["actual_qty"]}"></td><td>{fmt(diff)}</td></tr>'
 body+='</table>'+('<button>حفظ واعتماد الجرد</button>' if h['status']=='draft' else '<p class="tag">هذا الجرد معتمد ومحفوظ</p>')+'</form></div>'; return shell('تفاصيل الجرد',body)

@app.route('/reports')
def reports():
 start=request.args.get('start',''); end=request.args.get('end',''); where=''; args=[]
 if start: where+=' AND h.dt>=?'; args.append(start)
 if end: where+=' AND h.dt<=?'; args.append(end)
 st=stock_stats(); body=f'<div class="form"><h2>تصفية التقرير</h2><form class="grid"><label>من تاريخ<input name="start" type="date" value="{start}"></label><label>إلى تاريخ<input name="end" type="date" value="{end}"></label><button>عرض التقرير</button><a class="btn blue" href="/export/xlsx?start={start}&end={end}">تصدير Excel</a></form></div><div class="panel"><h2>الرصيد الحالي للمخزن الأساسي</h2><table><tr><th>المنتج</th><th>الكود</th><th>الوارد</th><th>المشحون للسيارات</th><th>المباع من السيارات</th><th>المرتجع للمخزن</th><th>الوحدات المتبقية</th></tr>'
 for r in st: body+=f'<tr><td>{r["name"]}</td><td>{r["code"] or "—"}</td><td>{fmt(r["incoming"])}</td><td>{fmt(r["shipped"])}</td><td>{fmt(r["sold"])}</td><td>{fmt(r["returned"])}</td><td><b>{fmt(r["incoming"]-r["shipped"]+r["returned"])}</b></td></tr>'
 body+='</table></div><div class="panel"><h2>تفاصيل الشحنات والمبيعات والمرتجعات</h2><table><tr><th>التاريخ</th><th>النوع</th><th>السيارة</th><th>المنتج</th><th>الكمية</th><th>القيمة</th></tr>'
 for typ,table,line,join in [('شحنة','shipments','shipment_lines','shipment_id'),('بيع','sales','sale_lines','sale_id'),('مرتجع','returns','return_lines','return_id')]:
  value_expr='l.price' if typ=='بيع' else 'l.cost'
  for r in q(f'SELECT h.dt,c.name car,p.name,l.qty,{value_expr} value FROM {table} h JOIN {line} l ON l.{join}=h.id JOIN products p ON p.id=l.product_id JOIN cars c ON c.id=h.car_id WHERE h.status="approved" {where} ORDER BY h.dt DESC',args): body+=f'<tr><td>{r["dt"]}</td><td>{typ}</td><td>{r["car"]}</td><td>{r["name"]}</td><td>{fmt(r["qty"])}</td><td>{fmt(r["qty"]*r["value"])}</td></tr>'
 return shell('التقارير التفصيلية',body+'</table></div>')

def report_rows(start='',end=''):
 where=''; args=[]
 if start: where+=' AND s.dt>=?'; args.append(start)
 if end: where+=' AND s.dt<=?'; args.append(end)
 rows=[]
 for typ,table,line,join in [('شحنة','shipments','shipment_lines','shipment_id'),('بيع','sales','sale_lines','sale_id'),('مرتجع','returns','return_lines','return_id')]:
  value_expr='l.price' if typ=='بيع' else 'l.cost'
  for r in q(f'SELECT s.dt,c.name car,p.name product,l.qty,{value_expr} value FROM {table} s JOIN {line} l ON l.{join}=s.id JOIN products p ON p.id=l.product_id JOIN cars c ON c.id=s.car_id WHERE s.status="approved" {where} ORDER BY s.dt',args): rows.append((typ,r))
 return rows

@app.route('/export/xlsx')
def xlsx():
 rows=report_rows(request.args.get('start',''),request.args.get('end','')); wb=Workbook(); ws=wb.active; ws.title='تقرير الحركات'; ws.append(['التاريخ','نوع الحركة','السيارة','المنتج','عدد الوحدات','القيمة']);
 for t,r in rows: ws.append([r['dt'],t,r['car'],r['product'],r['qty'],r['qty']*r['value']])
 ws2=wb.create_sheet('رصيد المخزن'); ws2.append(['المنتج','الكود','الوارد','المشحون','المباع','المرتجع','الوحدات المتبقية'])
 for r in stock_stats(): ws2.append([r['name'],r['code'] or '',r['incoming'],r['shipped'],r['sold'],r['returned'],r['incoming']-r['shipped']+r['returned']])
 for wsx in wb.worksheets:
  for col in wsx.columns: wsx.column_dimensions[col[0].column_letter].width=20
 out=io.BytesIO(); wb.save(out); out.seek(0); return send_file(out,as_attachment=True,download_name='تقرير-إدارة-المخازن.xlsx',mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/backup',methods=['GET','POST'])
def backup():
 if request.method=='POST':
  f=request.files.get('backup_file')
  if not f or not f.filename.endswith(('.sqlite3','.db')): flash('اختر ملف نسخة احتياطية بصيغة sqlite3 أو db'); return redirect('/backup')
  tmp=DB+'.restore'; f.save(tmp)
  try:
   test=sqlite3.connect(tmp); test.execute('SELECT name FROM sqlite_master'); test.close(); shutil.copy2(tmp,DB); os.remove(tmp); flash('تم استرجاع النسخة الاحتياطية بنجاح');
  except Exception: flash('ملف النسخة الاحتياطية غير صالح');
  return redirect('/backup')
 body='<div class="panel"><h2>استرجاع نسخة احتياطية</h2><p>اختر ملف قاعدة البيانات من جهازك ثم اضغط استرجاع. سيتم استبدال البيانات الحالية.</p><form method="post" enctype="multipart/form-data"><label>تحديد ملف النسخة الاحتياطية <input type="file" name="backup_file" accept=".sqlite3,.db" required></label><button>استرجاع النسخة المحددة</button></form></div><div class="panel"><h2>تنزيل نسخة احتياطية</h2><p>لنسخة كاملة من كل البيانات استخدم الزر التالي. ولتقرير فترة محددة استخدم صفحة التقارير وحدد تاريخ البدء والانتهاء ثم صدّر Excel.</p><a class="btn blue" href="/backup/download">تحميل نسخة قاعدة البيانات</a></div>'
 return shell('النسخ الاحتياطي والاسترجاع',body)
@app.route('/backup/download')
def backup_download(): return send_file(DB,as_attachment=True,download_name='نسخة-احتياطية-إدارة-المخازن.sqlite3',mimetype='application/octet-stream')

if __name__=='__main__': init(); app.run(host='127.0.0.1',port=5000,debug=False)

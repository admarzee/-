const $ = (id) => document.getElementById(id);
const notice = (el, msg, kind='info') => { el.textContent = msg; el.className = `notice ${kind}`; };
const hideNotice = (el) => { el.className = 'notice'; el.textContent = ''; };
const requestForm = $('requestForm');
requestForm.addEventListener('submit', async (e) => {
  e.preventDefault(); hideNotice($('formNotice'));
  if (!requestForm.reportValidity()) return;
  const btn = $('submitBtn'); btn.disabled = true; btn.textContent = 'جارٍ الإرسال…';
  const data = Object.fromEntries(new FormData(requestForm).entries());
  try {
    const r = await fetch('/api/requests', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) });
    const j = await r.json();
    if (!r.ok) { notice($('formNotice'), j.error || 'تعذر إرسال الطلب.', 'error'); return; }
    notice($('formNotice'), `${j.message} رقم الطلب: ${j.requestId}. احتفظ بهذا الرقم للمراجعة.`, 'success');
    requestForm.reset();
  } catch (_) { notice($('formNotice'), 'تعذر الاتصال بالخادم. تحقق من الإنترنت ثم أعد المحاولة.', 'error'); }
  finally { btn.disabled = false; btn.textContent = 'إرسال الطلب'; }
});
$('adminOpen').addEventListener('click', async () => {
  $('adminLogin').classList.toggle('hidden');
  try { const r = await fetch('/api/admin/me'); if (r.ok) showAdmin(); } catch (_) {}
});
$('cancelLogin').onclick = () => $('adminLogin').classList.add('hidden');
$('loginForm').addEventListener('submit', async e => {
  e.preventDefault(); hideNotice($('loginNotice'));
  try {
    const r = await fetch('/api/admin/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('username').value,password:$('password').value})});
    const j = await r.json(); if (!r.ok) return notice($('loginNotice'),j.error || 'فشل الدخول.','error');
    $('password').value=''; $('adminLogin').classList.add('hidden'); showAdmin();
  } catch (_) { notice($('loginNotice'),'تعذر الاتصال بالخادم.','error'); }
});
let currentPage=1, totalPages=1;
async function showAdmin(){ $('adminView').classList.remove('hidden'); $('adminOpen').classList.add('hidden'); await loadSummary(); await loadRequests(); }
async function loadSummary(){
  const r=await fetch('/api/admin/summary'); if(!r.ok) return;
  const d=await r.json(); $('totalCount').textContent=d.total; $('todayCount').textContent=d.today; $('monthCount').textContent=d.month;
}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function loadRequests(){
  const p=new URLSearchParams({page:String(currentPage),limit:'25',q:$('searchQuery').value.trim(),from:$('fromDate').value,to:$('toDate').value});
  const r=await fetch('/api/admin/requests?'+p); if(r.status===401){$('adminView').classList.add('hidden');$('adminOpen').classList.remove('hidden');return;} const d=await r.json();
  totalPages=Math.max(1,d.pages||1); $('pageInfo').textContent=`صفحة ${d.page} من ${totalPages} — ${d.total} طلب`;
  $('prevPage').disabled=currentPage<=1; $('nextPage').disabled=currentPage>=totalPages;
  $('requestsBody').innerHTML=d.rows.length?d.rows.map(x=>`<tr><td>${x.id}</td><td>${esc(x.fullName)}</td><td>${esc(x.nationalId)}</td><td>${esc(x.fuel)}</td><td>${esc(x.phone)}</td><td>${esc(x.vehicleNumber)}</td><td>${esc(x.vehicleType)}</td><td>${esc(x.vehicleColor)}</td><td>${esc(x.vin)}</td><td>${esc(new Date(x.createdAt).toLocaleString('ar-LY'))}</td></tr>`).join(''):'<tr><td colspan="10">لا توجد نتائج.</td></tr>';
}
$('searchBtn').onclick=()=>{currentPage=1;loadRequests();}; $('clearSearch').onclick=()=>{$('searchQuery').value='';$('fromDate').value='';$('toDate').value='';currentPage=1;loadRequests();};
$('prevPage').onclick=()=>{if(currentPage>1){currentPage--;loadRequests();}}; $('nextPage').onclick=()=>{if(currentPage<totalPages){currentPage++;loadRequests();}};
$('exportBtn').onclick=()=>{window.location.href='/api/admin/export.csv';};
$('logoutBtn').onclick=async()=>{await fetch('/api/admin/logout',{method:'POST'});$('adminView').classList.add('hidden');$('adminOpen').classList.remove('hidden');notice($('formNotice'),'تم تسجيل خروج الإدارة.','info');};

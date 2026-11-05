(function () {
  function init() {
    var dd = document.getElementById('pubDropdown');
    if (!dd) return;
    if (document.getElementById('spotLogoutBtn')) return;
    var btn = document.createElement('div');
    btn.id = 'spotLogoutBtn';
    btn.textContent = 'Logga ut';
    btn.style.cssText = 'padding:12px 16px;border-top:1px solid #eee;cursor:pointer;font-size:13px;color:#d2333a;font-weight:600;text-align:left;background:#fff';
    btn.onmouseenter = function () { btn.style.background = '#faf0f0'; };
    btn.onmouseleave = function () { btn.style.background = '#fff'; };
    btn.onclick = function () {
      // [Säkerhet 16] Rensa lokalt sparade inlägg och utkast vid utloggning (skyddar på delade datorer)
      try { Object.keys(localStorage).forEach(function (k) { if (k === 'spotAppState' || k === 'spotDrafts' || k.indexOf('spotEditDraft:') === 0 || k.indexOf('tplClean:') === 0) localStorage.removeItem(k); }); } catch (e) {}
      fetch('/logout', { method: 'POST' }).then(function () {
        location.href = '/login';
      }).catch(function () {
        location.href = '/login';
      });
    };
    dd.appendChild(btn);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

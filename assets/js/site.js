/* ===========================================================================
   site.js —— 页面外壳的交互（不含加密、不含任何个人资料）
   ---------------------------------------------------------------------------
   做三件事：
     1) 主题初始化 + 深/浅色切换（选择存 localStorage，跨页保持一致）；
     2) 回到顶部按钮的显示与点击；
     3) 页脚当前年份。

   【刻意不做的事】不碰 .page-content 的显示与隐藏 —— 那由页面内联的门禁脚本
   （包含密文解密逻辑）负责，两边的职责不交叉。
   =========================================================================== */
(function () {
  'use strict';

  var THEME_KEY = 'gdit_theme_v1';

  /* ---------------- 1. 主题 ---------------- */

  function readStoredTheme() {
    try {
      var v = localStorage.getItem(THEME_KEY);
      return (v === 'light' || v === 'dark') ? v : '';
    } catch (e) {
      return ''; // 隐私模式下 localStorage 可能抛异常，静默降级
    }
  }

  function saveTheme(v) {
    try { localStorage.setItem(THEME_KEY, v); } catch (e) { /* 忽略 */ }
  }

  /**
   * 把主题写到 <html data-theme>。
   * 注意：<head> 里的 gate.css 已经按同样规则设过一次，这里再设是为了
   * 响应「用户点按钮」以及之后的其他页面加载。
   */
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
  }

  function initTheme() {
    var stored = readStoredTheme();
    var prefersLight = false;
    try {
      prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
    } catch (e) { /* 老浏览器没有 matchMedia，忽略 */ }

    // 用户手动选过就听用户的，没选过就跟随系统；默认深色
    applyTheme(stored || (prefersLight ? 'light' : 'dark'));
  }

  function initThemeToggle() {
    var btn = document.querySelector('.theme-toggle');
    if (!btn) return;

    var label = btn.querySelector('.theme-toggle-label');
    var busy = false; // 门禁脚本在解密期间会把它设为 true

    btn.addEventListener('click', function () {
      if (busy || btn.getAttribute('aria-disabled') === 'true') return;
      var next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      applyTheme(next);
      saveTheme(next);
      if (label) label.textContent = next === 'light' ? '深色' : '浅色';
      btn.setAttribute('aria-label', next === 'light' ? '切换到深色模式' : '切换到浅色模式');
      btn.setAttribute('aria-pressed', next === 'light' ? 'false' : 'true');
    });
  }

  /**
   * 供门禁脚本调用：解锁前禁用主题切换。
   * 原因：解密是同步重计算（PBKDF2 2 万次迭代），期间点击会卡住界面。
   */
  window.gditSetThemeToggleBusy = function (isBusy) {
    var btn = document.querySelector('.theme-toggle');
    if (!btn) return;
    btn.setAttribute('aria-disabled', isBusy ? 'true' : 'false');
    btn.style.opacity = isBusy ? '0.5' : '';
    btn.style.cursor = isBusy ? 'wait' : '';
  };

  /* ---------------- 2. 回到顶部 ---------------- */

  function initToTop() {
    var btn = document.querySelector('.to-top');
    if (!btn) return;

    function sync() {
      if (window.scrollY > 320) btn.classList.add('is-visible');
      else btn.classList.remove('is-visible');
    }

    window.addEventListener('scroll', sync, { passive: true });
    sync();

    btn.addEventListener('click', function () {
      var reduce = false;
      try {
        reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      } catch (e) { /* 忽略 */ }
      window.scrollTo({ top: 0, behavior: reduce ? 'auto' : 'smooth' });
    });
  }

  /* ---------------- 3. 页脚年份 ---------------- */

  function initYear() {
    var y = document.querySelector('#footerYear');
    if (y) y.textContent = String(new Date().getFullYear());
  }

  /* ---------------- 启动 ---------------- */

  initTheme();        // 立即执行，避免主题闪烁
  initThemeToggle();
  initToTop();
  initYear();

  // 同步主题按钮的初始文案与状态
  (function syncToggleLabel() {
    var btn = document.querySelector('.theme-toggle');
    if (!btn) return;
    var isLight = document.documentElement.getAttribute('data-theme') === 'light';
    var label = btn.querySelector('.theme-toggle-label');
    if (label) label.textContent = isLight ? '深色' : '浅色';
    btn.setAttribute('aria-pressed', isLight ? 'false' : 'true');
    btn.setAttribute('aria-label', isLight ? '切换到深色模式' : '切换到浅色模式');
  })();
})();

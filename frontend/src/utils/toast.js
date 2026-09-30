import './toast.css';

const CONTAINER_ID = 'vigilserve-toast-container';
const CENTER_CONTAINER_ID = 'vigilserve-toast-center';

/* ── Toast 图标（2026-09-23）──
 *
 * 原来这里是 `✓ / ✕ / ! / ℹ` 四个**字符**，三个问题：
 * 1. 字形由系统字体决定 —— 不同 Windows / 浏览器里粗细、高宽比都不一样；
 * 2. `!` 和 `ℹ` 的视觉重量差得远，四个 toast 摆一起像两套；
 * 3. 字符在 20px 圆底里对不齐（基线对齐 vs 视觉居中）。
 * 全站图标统一成自绘 SVG 后，这里是**漏网的一处**，现在补齐。
 *
 * 图形真源在 `components/AppIcon.jsx`：`ui-check` / `ui-close` / `ui-warning` / `ui-info`。
 * 本文件是**纯 JS 模块（非 React），不能 import 那个组件**，所以按同一份 path 数据
 * 内联了一份 SVG 字符串（外壳参数 viewBox/stroke-width/圆头圆角与 `IconFrame` 逐项一致）。
 * 以后改 AppIcon 里这四个图形，务必同步改这里。 */
const ICON_FRAME = (body) =>
  '<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor"' +
  ' stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"' +
  ' aria-hidden="true" focusable="false">' +
  body +
  '</svg>';

const TOAST_ICONS = {
  success: ICON_FRAME('<path d="M2.8 8.6 6.2 12l7-7.4"/>'),
  error: ICON_FRAME('<path d="M3.6 3.6l8.8 8.8M12.4 3.6l-8.8 8.8"/>'),
  warning: ICON_FRAME(
    '<path d="M8 2.4 15 14.2H1z"/><path d="M8 6.6v3.2"/>' +
      '<circle cx="8" cy="12.2" r="0.65" fill="currentColor" stroke="none"/>',
  ),
  info: ICON_FRAME(
    '<circle cx="8" cy="8" r="6.2"/><path d="M8 7.4v4.1"/>' +
      '<circle cx="8" cy="5" r="0.65" fill="currentColor" stroke="none"/>',
  ),
};

function ensureContainer(id, positionClass) {
  let container = document.getElementById(id);
  if (!container) {
    container = document.createElement('div');
    container.id = id;
    container.className = positionClass;
    document.body.appendChild(container);
  }
  return container;
}

function iconFor(type) {
  return TOAST_ICONS[type] || TOAST_ICONS.info;
}

// 防 XSS：message 可能来自服务端/接口返回的任意文本，插入 innerHTML 前必须转义
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

export function showToast(message, type = 'info', duration = 3500, position = 'top-right') {
  const containerId = position === 'center' ? CENTER_CONTAINER_ID : CONTAINER_ID;
  const positionClass = position === 'center' ? 'vtoast-center-container' : 'vtoast-container';
  const container = ensureContainer(containerId, positionClass);
  const el = document.createElement('div');
  el.className = `vtoast vtoast-${type} ${position === 'center' ? 'vtoast-center' : ''}`;
  el.innerHTML = `<span class="vtoast-icon">${iconFor(type)}</span><span class="vtoast-message">${escapeHtml(message)}</span>`;
  container.appendChild(el);

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      el.classList.add('vtoast-visible');
    });
  });

  const remove = () => {
    el.classList.remove('vtoast-visible');
    el.addEventListener('transitionend', () => {
      if (el.parentNode) {
        el.parentNode.removeChild(el);
      }
    });
  };

  const timer = setTimeout(remove, duration);
  el.addEventListener('click', () => {
    clearTimeout(timer);
    remove();
  });
}

export function showCenterLoading(message) {
  const container = ensureContainer(CENTER_CONTAINER_ID, 'vtoast-center-container');
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }
  const el = document.createElement('div');
  el.className = 'vtoast vtoast-info vtoast-center vtoast-loading';
  el.innerHTML = `<span class="vtoast-spinner"></span><span class="vtoast-message">${escapeHtml(message)}</span>`;
  container.appendChild(el);

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      el.classList.add('vtoast-visible');
    });
  });

  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    el.classList.remove('vtoast-visible');
    el.addEventListener('transitionend', () => {
      if (el.parentNode) {
        el.parentNode.removeChild(el);
      }
    });
  };

  return close;
}

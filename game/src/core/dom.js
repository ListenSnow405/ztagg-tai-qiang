(() => {
'use strict';
// 文本统一通过 textContent 写入，剧情里不混入 HTML。
function el(tag, className = '', text = '') {
  const node = document.createElement(tag);
  node.className = className;
  node.textContent = text;
  return node;
}
function button(text, handler) {
  const node = el('button', '', text);
  node.type = 'button';
  node.addEventListener('click', handler);
  return node;
}

// ── 设备 / 输入能力检测（纯运行时，iframe 内也有效） ──
// 刻意不用 UA 字符串：UA 可伪造、手机与平板的 UA 又常常混在一起，
// 而媒体查询反映的是浏览器实测到的输入能力。
// 注意区分「有没有触摸屏」和「是不是手机/平板」——触摸屏笔记本属于前者、不属于后者。
const mq = q => typeof matchMedia === 'function' && matchMedia(q).matches;
const device = {
  coarse: () => mq('(pointer: coarse)'),                     // 主指针是手指（触摸屏）
  noHover: () => mq('(hover: none)'),                        // 没有悬停能力
  touch: () => (typeof navigator !== 'undefined' && navigator.maxTouchPoints > 0) || mq('(pointer: coarse)'),
  phone: () => mq('(pointer: coarse) and (hover: none)')     // 手机 / 平板；触摸屏笔记本不算
};

// ── 虚拟方向盘（手机 / 平板专用） ──
// 只做两件事：① 把按住状态映射成「按下的键」；② 把每个键交给调用方自己的 press/release。
// 方向键由调用方注入它本来就在用的那套输入（rpg 注入 keys 集合、walk 注入 moving 变量），
// 所以玩法代码不需要为手柄写任何分支；动作键（调查）直接调调用方传进来的函数。
// 只在「主指针是手指且没有悬停能力」(= 手机 / 平板) 上创建 DOM：电脑端连节点都不生成，
// 不会出现「透明的按钮挡住画布点击」这种副作用。
// 开关状态存 localStorage（主游戏与 winxp 小游戏窗口的 origin 相同，跨页面共用），
// 用户把方向盘收起来之后，后面每一幕都保持收起。
const TOUCH_PAD_KEY = 'ily-touch-pad';
const touchPadSaved = () => {
  try { return localStorage.getItem(TOUCH_PAD_KEY); } catch { return null; }
};
const touchPadSave = value => {
  try { localStorage.setItem(TOUCH_PAD_KEY, value); } catch {}
};
function createTouchPad({ label, hint, buttons = [] }) {
  if (!device.phone()) return null;
  const root = el('div', 'touch-pad');
  root.setAttribute('role', 'group');
  root.setAttribute('aria-label', label || '虚拟方向盘');
  const grid = el('div', 'touch-pad-grid');
  const held = new Set();                 // 正在被手指按住的按钮，复位时用来清干净
  const pairs = [];                       // [按钮, 配置]：复位时要按配置调 up()
  const unbind = [];
  for (const cfg of buttons) {
    const node = el('button', 'pad-btn pad-' + cfg.pos, cfg.text);
    node.type = 'button';
    node.setAttribute('aria-label', cfg.title);
    node.dataset.code = cfg.code || '';
    const stop = event => { event.preventDefault(); event.stopPropagation(); };
    const release = () => {
      if (!held.delete(node)) return;
      node.classList.remove('is-down');
      try { cfg.up?.(); } catch {}
    };
    const down = event => {
      if (node.disabled) return;
      stop(event);
      try { node.setPointerCapture(event.pointerId); } catch {}
      if (held.has(node)) return;
      held.add(node);
      node.classList.add('is-down');
      try { cfg.down?.(); } catch {}
    };
    node.addEventListener('contextmenu', stop);            // 长按不弹系统菜单
    node.addEventListener('pointerdown', down);
    for (const type of ['pointerup', 'pointercancel', 'lostpointercapture']) node.addEventListener(type, release);
    unbind.push([node, 'contextmenu', stop], [node, 'pointerdown', down],
      ...['pointerup', 'pointercancel', 'lostpointercapture'].map(type => [node, type, release]));
    pairs.push([node, cfg]);
    grid.append(node);
  }
  root.append(grid);
  if (hint) root.append(el('p', 'touch-pad-hint', hint));
  const toggle = el('button', 'touch-pad-toggle', '手柄');
  toggle.type = 'button';
  /* 收起 / dispose 时把还按着的键全部松开：否则「按住方向键的同一帧里收起方向盘」
     会让人物一直往那个方向走，直到下一次键盘事件。 */
  const releaseEvery = () => {
    for (const [node, cfg] of [...pairs].reverse()) {
      if (!held.delete(node)) continue;
      node.classList.remove('is-down');
      try { cfg.up?.(); } catch {}
    }
  };
  const apply = (value, persist) => {
    const hidden = value === false;
    if (hidden) releaseEvery();
    root.hidden = hidden;
    toggle.setAttribute('aria-pressed', String(hidden));
    toggle.setAttribute('aria-label', hidden ? '显示虚拟方向盘' : '隐藏虚拟方向盘');
    toggle.textContent = hidden ? '手柄＋' : '手柄－';
    if (persist) touchPadSave(hidden ? 'off' : 'on');
  };
  const toggleClick = event => { event.preventDefault(); apply(root.hidden, true); };
  const blur = () => releaseEvery();                       // 切后台 / 系统弹窗吞掉 pointerup 时兜底
  toggle.addEventListener('click', toggleClick);
  addEventListener('blur', blur);
  unbind.push([toggle, 'click', toggleClick], [window, 'blur', blur]);
  root.append(toggle);
  apply(touchPadSaved() !== 'off', false);                 // 默认显示；只有用户明确收起过才隐藏
  return {
    root,
    get visible() { return !root.hidden; },
    show: () => apply(true, true),
    hide: () => apply(false, true),
    toggle: () => apply(root.hidden, true),
    dispose() {
      releaseEvery();
      for (const [node, type, handler] of unbind) node.removeEventListener(type, handler);
      root.remove();
    }
  };
}

// ── 顶栏「隐藏」控制器 ──
// 隐藏 = 把传入的文字区（对白框 / 旁白面板…）连同左上章标题、右上整排按钮一起
// display:none —— 不加半透明，画面上只剩背景或 CG。
// 顶栏那颗「隐藏」按钮自己也属于右上那一排，所以隐藏后会一起消失；
// 复原靠点画面 / SPACE / 再按一次 H（各玩法在自己的输入处理里接 isHidden 即可）。
// 每个 mount 只在自己那一幕里持有控制器，cleanup 调 dispose() 复原并交还按钮。
function createHideChrome(targets = []) {
  const header = document.querySelector('.game-header');
  const actions = header?.querySelector('.game-header-actions') || null;
  const toggleBtn = actions?.querySelector('#hide-ui') || null;
  /* 隐藏的是整条 .game-header（含它的渐变底），不是只藏两个子元素——
     否则顶栏那条 linear-gradient 会留在画面上，做不到「只剩背景 / CG」。 */
  const parts = [...targets, header].filter(Boolean);
  let hidden = false;
  const apply = value => {
    hidden = value;
    for (const part of parts) part.hidden = value;
    if (toggleBtn) toggleBtn.setAttribute('aria-pressed', String(value));
    if (!value) return;
    /* 隐藏后排/widget 里那个刚被点掉的按钮已经消失，焦点会掉到 <body>，
       键盘操作（SPACE / H）随之失效。这里把焦点收回舞台，输入链路才不断。 */
    const stage = document.querySelector('#stage');
    const active = document.activeElement;
    if (!stage || !active) return;
    const lost = active === document.body || !active.isConnected || parts.some(part => part.contains?.(active));
    if (lost) stage.focus({ preventScroll: true });
  };
  const api = {
    get isHidden() { return hidden; },
    hide: () => apply(true),
    restore: () => apply(false),
    toggle: () => apply(!hidden),
    /* 切节点时必须交还按钮：下一幕可能 another 不支持隐藏（只能禁用，不能留着可点）。 */
    dispose: () => {
      apply(false);
      if (toggleBtn) { toggleBtn.disabled = true; toggleBtn.onclick = null; toggleBtn.setAttribute('aria-pressed', 'false'); }
    }
  };
  if (toggleBtn) {
    toggleBtn.disabled = false;
    toggleBtn.onclick = () => api.toggle();
  }
  return api;
}

Object.assign(ILY, { el, button, device, createHideChrome, createTouchPad });
})();

/* ============================================================================
   MODULE: CT.dom — minimal render layer + virtualized list
   ========================================================================= */
CT.dom = (function () {
  'use strict';

  const SVG_NS = 'http://www.w3.org/2000/svg';

  function parseTag(tag) {
    const parts = String(tag).split(/(?=[.#])/);
    const name = parts[0] || 'div';
    let id = null;
    const cls = [];
    for (let i = 1; i < parts.length; i++) {
      const p = parts[i];
      if (p[0] === '.') cls.push(p.slice(1));
      else if (p[0] === '#') id = p.slice(1);
    }
    return { name, id, cls };
  }

  function append(el, child) {
    if (child === null || child === undefined || child === false || child === true) return;
    if (Array.isArray(child)) { child.forEach((c) => append(el, c)); return; }
    if (child instanceof Node) { el.appendChild(child); return; }
    el.appendChild(document.createTextNode(String(child)));
  }

  /**
   * h('div.card', {props}, children)
   * Props: class/className, style (object|string), text, html, on:{event:fn},
   *        onClick, dataset:{}, plus any attribute name.
   */
  function h(tag, props, children) {
    const t = parseTag(tag);
    const el = document.createElement(t.name);
    if (t.id) el.id = t.id;
    if (t.cls.length) el.className = t.cls.join(' ');

    if (props && (props instanceof Node || Array.isArray(props) || typeof props === 'string' || typeof props === 'number')) {
      children = props; props = null;
    }

    if (props) {
      for (const k in props) {
        if (!Object.prototype.hasOwnProperty.call(props, k)) continue;
        const v = props[k];
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class' || k === 'className') {
          el.className = (el.className ? el.className + ' ' : '') + v;
        } else if (k === 'style') {
          if (typeof v === 'string') el.style.cssText += v;
          else for (const sk in v) el.style.setProperty(sk, v[sk]);
        } else if (k === 'text') {
          el.textContent = String(v);
        } else if (k === 'html') {
          el.innerHTML = v;
        } else if (k === 'dataset') {
          for (const dk in v) el.dataset[dk] = v[dk];
        } else if (k === 'on') {
          for (const ev in v) el.addEventListener(ev, v[ev]);
        } else if (k === 'onClick') {
          el.addEventListener('click', v);
        } else if (k === 'ref') {
          if (typeof v === 'function') v(el);
        } else if (v === true) {
          el.setAttribute(k, '');
        } else {
          el.setAttribute(k, String(v));
        }
      }
    }
    append(el, children);
    return el;
  }

  function frag(children) {
    const f = document.createDocumentFragment();
    append(f, children);
    return f;
  }

  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
  function mount(el, content) { clear(el); append(el, content); return el; }

  function icon(name, opts) { return CT.icons.svg(name, opts); }

  /* -- Common building blocks ---------------------------------------------- */
  function pill(text, kind, glyph) {
    return h('span.pill.' + (kind || 'neutral'), [
      glyph ? h('span.glyph', { 'aria-hidden': 'true' }, glyph) : null,
      h('span', text)
    ]);
  }

  function kv(label, value, opts) {
    const o = opts || {};
    return h('div.kv', [
      h('dt', label),
      h('dd', { class: o.mono ? 'mono' : null }, value === null || value === undefined || value === '' ? '—' : value)
    ]);
  }

  function card(children, cls) { return h('div.card' + (cls ? '.' + cls : ''), children); }

  function sectionLabel(text, right) {
    return h('div.section-label', [h('span', text), h('span.line'), right || null]);
  }

  function empty(opts) {
    return h('div.empty', [
      h('div.art', icon(opts.icon || 'inbox')),
      h('h3', opts.title),
      h('p', opts.body),
      opts.action ? h('button.btn.primary.mt8', { type: 'button', onClick: opts.action.onClick }, [
        opts.action.icon ? icon(opts.action.icon) : null, opts.action.label
      ]) : null,
      opts.secondary ? h('button.btn.quiet.sm', { type: 'button', onClick: opts.secondary.onClick }, opts.secondary.label) : null
    ]);
  }

  function notice(kind, title, body, action) {
    return h('div.notice' + (kind ? '.' + kind : ''), [
      icon(kind === 'err' ? 'alertCircle' : kind === 'warn' ? 'alert' : kind === 'ok' ? 'shieldCheck' : 'info'),
      h('div.grow', [
        title ? h('strong', title) : null,
        body ? h('span', body) : null,
        action ? h('div.mt8', h('button.btn.sm', { type: 'button', onClick: action.onClick }, action.label)) : null
      ])
    ]);
  }

  function bar(pct, kind) {
    return h('div.bar' + (kind ? '.' + kind : ''), h('i', { style: { width: CT.util.clamp(pct, 0, 100) + '%' } }));
  }

  function progressRing(pct, opts) {
    const o = opts || {};
    const size = o.size || 116, sw = o.stroke || 9;
    const r = (size - sw) / 2, c = 2 * Math.PI * r;
    const val = CT.util.clamp(pct, 0, 100);
    const el = document.createElementNS(SVG_NS, 'svg');
    el.setAttribute('width', size); el.setAttribute('height', size);
    el.setAttribute('aria-hidden', 'true');
    el.innerHTML =
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="var(--card-3)" stroke-width="' + sw + '"/>' +
      '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="' + (o.color || 'var(--accent)') +
      '" stroke-width="' + sw + '" stroke-linecap="round" stroke-dasharray="' + c +
      '" stroke-dashoffset="' + (c * (1 - val / 100)) + '"/>';
    return el;
  }

  /* -- Virtualized list -----------------------------------------------------
     Renders only the rows intersecting the viewport plus an overscan margin.
     Keeps large inventories (500+ assets, long finding lists) responsive.   */
  const liveLists = new Set();

  function VirtualList(opts) {
    this.scrollEl = opts.scrollEl;
    this.itemHeight = opts.itemHeight;
    this.renderItem = opts.renderItem;
    this.overscan = opts.overscan || 5;
    this.items = opts.items || [];
    this.threshold = opts.threshold || 40;

    this.root = h('div.vlist');
    this.spacer = h('div.vlist-spacer');
    this.window = h('div.vlist-window');
    this.window.style.setProperty('--vrow', this.itemHeight + 'px');
    this.root.appendChild(this.spacer);
    this.root.appendChild(this.window);
    this._range = [-1, -1];
    this._raf = null;
    this._attached = false;
    this._onScroll = this._schedule.bind(this);
  }
  VirtualList.prototype.attach = function () {
    if (this._attached) return;
    this.scrollEl.addEventListener('scroll', this._onScroll, { passive: true });
    window.addEventListener('resize', this._onScroll);
    this._attached = true;
    liveLists.add(this);
    this._update();
  };
  VirtualList.prototype.destroy = function () {
    if (!this._attached) return;
    this.scrollEl.removeEventListener('scroll', this._onScroll);
    window.removeEventListener('resize', this._onScroll);
    if (this._raf) { cancelAnimationFrame(this._raf); this._raf = null; }
    this._attached = false;
    liveLists.delete(this);
  };
  /** Called when the view is torn down so stale lists stop reacting to scroll. */
  function destroyLists() { Array.from(liveLists).forEach((l) => l.destroy()); }
  VirtualList.prototype._schedule = function () {
    if (this._raf) return;
    this._raf = requestAnimationFrame(() => { this._raf = null; this._update(); });
  };
  VirtualList.prototype.setItems = function (items) {
    this.items = items;
    this._range = [-1, -1];
    this._update();
  };
  VirtualList.prototype._update = function () {
    const n = this.items.length;
    // Below the threshold, plain rendering is cheaper than windowing.
    if (n <= this.threshold) {
      this.spacer.style.height = '0px';
      this.window.style.transform = 'none';
      this.window.style.position = 'static';
      this.window.removeAttribute('data-fixed');
      if (this._range[0] !== 0 || this._range[1] !== n) {
        clear(this.window);
        for (let i = 0; i < n; i++) this.window.appendChild(this.renderItem(this.items[i], i));
        this._range = [0, n];
      }
      return;
    }
    this.window.style.position = 'absolute';
    this.window.setAttribute('data-fixed', '1');
    this.spacer.style.height = (n * this.itemHeight) + 'px';
    const rootTop = this.root.getBoundingClientRect().top;
    const scrollTop = Math.max(0, -(rootTop - this.scrollEl.getBoundingClientRect().top));
    const viewH = this.scrollEl.clientHeight;
    let start = Math.max(0, Math.floor(scrollTop / this.itemHeight) - this.overscan);
    let end = Math.min(n, Math.ceil((scrollTop + viewH) / this.itemHeight) + this.overscan);
    if (start === this._range[0] && end === this._range[1]) return;
    this._range = [start, end];
    clear(this.window);
    const f = document.createDocumentFragment();
    for (let i = start; i < end; i++) f.appendChild(this.renderItem(this.items[i], i));
    this.window.appendChild(f);
    this.window.style.transform = 'translateY(' + (start * this.itemHeight) + 'px)';
  };

  return {
    h, frag, clear, mount, icon, pill, kv, card, sectionLabel,
    empty, notice, bar, progressRing, VirtualList, destroyLists, SVG_NS
  };
})();

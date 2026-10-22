(() => {
  'use strict';
  const root = new URL(document.body.dataset.root, location.href);
  const gate = document.querySelector('#gate');
  const frame = document.querySelector('#journal-frame');
  const form = document.querySelector('#unlock-form');
  const field = document.querySelector('#access-password');
  const button = document.querySelector('#unlock-button');
  const status = document.querySelector('#access-status');
  const lockButton = document.querySelector('#lock-button');
  const urls = new Map();
  let journal = null, busy = false, renderNumber = 0;
  function bytes(base64) { return Uint8Array.from(atob(base64), c => c.charCodeAt(0)); }
  function objectUrl(content, type) {
    const url = URL.createObjectURL(new Blob([content], {type}));
    urls.set(url, url); return url;
  }
  function routeFromAddress() {
    const relative = location.pathname.startsWith(root.pathname) ? location.pathname.slice(root.pathname.length) : '';
    return relative || 'index.html';
  }
  function resolveAsset(ref, route) {
    const target = new URL(ref, new URL(route, root));
    if (target.origin !== root.origin || !target.pathname.startsWith(root.pathname)) throw new Error('External asset rejected');
    const key = decodeURIComponent(target.pathname.slice(root.pathname.length));
    const found = journal.assetUrls.get(key);
    if (!found) throw new Error('Missing asset');
    return found;
  }
  function render(route = 'index.html', hash = '') {
    if (!journal || !Object.hasOwn(journal.pages, route)) route = 'index.html';
    const number = ++renderNumber;
    const doc = new DOMParser().parseFromString(journal.pages[route], 'text/html');
    doc.querySelectorAll('meta[http-equiv="Content-Security-Policy"],base').forEach(el => el.remove());
    const csp = doc.createElement('meta');
    csp.httpEquiv = 'Content-Security-Policy';
    csp.content = "default-src 'none';script-src blob:;style-src blob:;img-src blob: data:;connect-src 'none';object-src 'none';base-uri 'none';form-action 'none'";
    doc.head.prepend(csp);
    doc.documentElement.dataset.canonicalUrl = new URL(route, root).href;
    doc.querySelectorAll('img[src],script[src],link[href]').forEach(el => {
      const name = el.hasAttribute('src') ? 'src' : 'href';
      el.setAttribute(name, resolveAsset(el.getAttribute(name), route));
    });
    doc.querySelectorAll('[srcset]').forEach(el => {
      const candidates = el.getAttribute('srcset').split(',').map(candidate => {
        const [ref, descriptor] = candidate.trim().split(/\s+/);
        return resolveAsset(ref, route) + (descriptor ? ' ' + descriptor : '');
      });
      el.setAttribute('srcset', candidates.join(', '));
    });
    doc.querySelectorAll('[data-full]').forEach(el => el.dataset.full = resolveAsset(el.dataset.full, route));
    const bridge = `(() => {
      const route = ${JSON.stringify(route)};
      const targetOrigin = ${JSON.stringify(location.origin)};
      const send = message => parent.postMessage(message, targetOrigin);
      document.addEventListener('click', event => {
        const link = event.target.closest('a[href]');
        if (!link || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey || event.button > 0) return;
        const href = link.getAttribute('href');
        if (href.startsWith('#')) { event.preventDefault(); const target = document.getElementById(decodeURIComponent(href.slice(1))); if (target) target.scrollIntoView({block:'start',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'}); return; }
        event.preventDefault(); send({kind:'journal:navigate',href,route});
      });
      new MutationObserver(() => send({kind:'journal:modal',open:!!document.querySelector('dialog[open]')})).observe(document.body,{subtree:true,attributes:true,attributeFilter:['open']});
    })();`;
    const script = doc.createElement('script'); script.src = objectUrl(bridge, 'text/javascript'); script.defer = true; doc.body.append(script);
    frame.onload = () => {
      if (number !== renderNumber) return;
      const destination = hash ? frame.contentDocument.getElementById(decodeURIComponent(hash.slice(1))) : null;
      if (destination) destination.scrollIntoView({block:'start'});
    };
    frame.srcdoc = '<!doctype html>\n' + doc.documentElement.outerHTML;
    document.title = doc.title;
    gate.hidden = true; frame.hidden = false; lockButton.hidden = false;
  }
  document.querySelector('#show-password').addEventListener('click', event => {
    const reveal = field.type === 'password';
    field.type = reveal ? 'text' : 'password';
    const control = event.currentTarget;
    control.setAttribute('aria-pressed', String(reveal)); control.setAttribute('aria-label', reveal ? '隐藏密码' : '显示密码');
    field.focus();
  });
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return;
    if (!crypto.subtle) { status.textContent = '当前浏览器无法安全解锁，请使用新版浏览器。'; return; }
    busy = true; button.disabled = true; button.querySelector('span').textContent = '正在解锁…';
    status.textContent = '正在打开这一页日常。'; status.classList.add('is-working');
    try {
      const response = await fetch(new URL('vault.json', root), {cache:'no-store'});
      if (!response.ok) throw new Error('Network');
      const config = await response.json();
      if (config.enabled === false) { status.textContent = '这本手记暂时不开放访问。'; return; }
      if (config.version !== 1 || config.iterations < 200000 || config.iterations > 1000000 || config.file !== 'journal.bin') throw new Error('Invalid configuration');
      const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(field.value), 'PBKDF2', false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey({name:'PBKDF2',salt:bytes(config.salt),iterations:config.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
      const encrypted = await fetch(new URL(config.file, root), {cache:'no-store'});
      if (!encrypted.ok) throw new Error('Network');
      const plaintext = await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(config.iv),additionalData:new TextEncoder().encode('cloudscape-journal-v1'),tagLength:128},key,await encrypted.arrayBuffer());
      const payload = JSON.parse(new TextDecoder().decode(plaintext));
      if (payload.version !== 1 || !payload.pages?.['index.html']) throw new Error('Invalid payload');
      journal = {pages:payload.pages,assetUrls:new Map()};
      for (const [path, asset] of Object.entries(payload.assets)) {
        journal.assetUrls.set(path, objectUrl(bytes(asset.data), asset.type));
      }
      field.value = ''; status.textContent = '';
      render(routeFromAddress(), location.hash);
    } catch (error) {
      status.textContent = error.name === 'OperationError' ? '密码不正确，请重新输入。' : '暂时无法打开，请检查网络后重试。';
      field.focus(); field.select();
    } finally {
      busy = false; button.disabled = false; button.querySelector('span').textContent = '打开手记'; status.classList.remove('is-working');
    }
  });
  addEventListener('message', event => {
    if (!journal || event.source !== frame.contentWindow || event.origin !== location.origin) return;
    const message = event.data;
    if (message?.kind === 'journal:modal') { lockButton.hidden = !!message.open; return; }
    if (message?.kind !== 'journal:navigate' || typeof message.href !== 'string' || typeof message.route !== 'string') return;
    const next = new URL(message.href, new URL(message.route, root));
    if (next.origin !== root.origin || !next.pathname.startsWith(root.pathname)) return;
    const route = decodeURIComponent(next.pathname.slice(root.pathname.length)) || 'index.html';
    if (!Object.hasOwn(journal.pages, route)) return;
    history.pushState(null, '', next.pathname + next.hash); render(route, next.hash);
  });
  addEventListener('popstate', () => { if (journal) render(routeFromAddress(), location.hash); });
  lockButton.addEventListener('click', () => {
    ++renderNumber; frame.onload = null; frame.srcdoc = ''; frame.hidden = true; lockButton.hidden = true;
    for (const url of urls.keys()) URL.revokeObjectURL(url);
    urls.clear(); journal = null; gate.hidden = false; status.textContent = ''; field.value = '';
    document.title = '云景手记 · 访问密码'; field.focus();
  });
})();

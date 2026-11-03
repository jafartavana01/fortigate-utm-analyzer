// Dependency-free DOM harness for the actual embedded report program.
// This verifies state transitions, not browser rendering or platform permissions.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const page = fs.readFileSync(process.argv[2], 'utf8');
const data = JSON.parse(page.match(/type="application\/json">([\s\S]*?)<\/script>/)[1]);
const script = page.match(/<script>([\s\S]*?)<\/script>/)[1];
class Node {
  constructor(tag) {
    this.tagName = tag.toLowerCase(); this.children = []; this.dataset = {};
    this.style = {}; this.attributes = {}; this.listeners = {}; this.className = '';
    this.value = ''; this._text = ''; this._open = false;
    this.classList = {toggle: (name, flag) => {
      const names = new Set(this.className.split(' ').filter(Boolean));
      const add = flag === undefined ? !names.has(name) : flag;
      if (add) names.add(name); else names.delete(name);
      this.className = [...names].join(' ');
    }};
  }
  append(...items) {
    for (let n of items) {
      if (typeof n === 'string') n = Object.assign(new Node('#text'), {_text:n});
      if (n.tagName === '#fragment') { this.append(...n.children); continue; }
      this.children.push(n); n.parentElement = this;
    }
  }
  replaceChildren(...nodes) { this.children = []; this._text = ''; this.append(...nodes); }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(n=>n.textContent).join(''); }
  get firstChild() { return this.children[0] || null; }
  setAttribute(name, value) { this.attributes[name] = value; if (name === 'id') this.id = value; }
  addEventListener(type, callback) { (this.listeners[type] ||= []).push(callback); }
  async emit(type) { for (const callback of this.listeners[type] || []) await callback({target:this}); }
  set open(value) { const changed = value !== this._open; this._open = value; if (changed) void this.emit('toggle'); }
  get open() { return this._open; }
  querySelector(selector) { return descendants(this).find(n=>n.tagName===selector) || null; }
  remove() { if (this.parentElement) this.parentElement.children = this.parentElement.children.filter(n=>n!==this); }
  select() { selectionFallback = true; }
}
function descendants(root) { return root.children.flatMap(n=>[n,...descendants(n)]); }
let selectionFallback = false;
const body = new Node('body');
const document = {
  body, documentElement: new Node('html'),
  createElement: tag=>new Node(tag), createElementNS: (_,tag)=>new Node(tag),
  createTextNode: text=>Object.assign(new Node('#text'), {_text:text}),
  createDocumentFragment: ()=>new Node('#fragment'),
  getElementById: id=>descendants(body).find(n=>n.id===id),
  querySelectorAll: selector=>{
    const [id,tag] = selector.split(' ');
    const root = document.getElementById(id.slice(1));
    return descendants(root).filter(n=>n.tagName===tag.replace('[open]','')&&(!tag.endsWith('[open]')||n.open));
  },
  createRange: ()=>({selectNodeContents(){ selectionFallback = true; }}),
  execCommand: ()=>false
};
for (const [,id] of page.matchAll(/\bid="([^"]+)"/g)) {
  const n = new Node('div'); n.id = id; body.append(n);
}
const $=id=>document.getElementById(id);
$('report-data').textContent = JSON.stringify(data); $('sort').value='highest';
const events = {};
const window = {
  addEventListener(type,fn){(events[type] ||= []).push(fn);},
  getSelection: ()=>({removeAllRanges(){},addRange(){selectionFallback=true;}}),
  print(){}
};
const context = {
  document, window, navigator: {}, console,
  localStorage: {getItem(){throw Error('blocked');},setItem(){throw Error('blocked');}},
  matchMedia: ()=>({matches:false}),
  getComputedStyle: ()=>({getPropertyValue: ()=>'#123456'}),
  setTimeout: fn=>{fn();return 1;}, clearTimeout(){}
};
vm.runInNewContext(script,context,{timeout:5000});
(async()=>{
  assert.equal($('total').textContent, String(data.findings.length));
  assert.equal($('list').children.length,80);
  assert.equal(document.documentElement.dataset.theme,'dark');
  await $('theme').emit('click'); assert.equal(document.documentElement.dataset.theme,'light');
  $('severity').value='HIGH'; await $('severity').emit('change');
  assert.ok($('list').children.every(n=>n.textContent.includes('HIGH')));
  $('domain').value='LDAP'; await $('domain').emit('change');
  $('vdom').value='tenant-a'; await $('vdom').emit('change');
  assert.ok($('list').children.length>0);
  const expected=data.findings.filter(f=>f.severity==='HIGH'&&f.domain==='LDAP'&&f.vdom==='tenant-a').length;
  assert.equal($('list').children.length,expected);
  $('search').value='nothing-matches'; await $('search').emit('input');
  assert.equal($('list').children.length,0); assert.ok(!$('empty').className.includes('hidden'));
  await $('reset').emit('click'); assert.equal($('list').children.length,80);
  await $('more').emit('click'); assert.equal($('list').children.length,160);
  $('sort').value='lowest'; await $('sort').emit('change');
  assert.ok($('list').children[0].textContent.includes('INFO'));
  $('sort').value='original'; await $('sort').emit('change');
  const first=$('list').children[0];first.open=true;
  assert.ok(first.textContent.includes('Recommended remediation'));
  const copy=descendants(first).find(n=>n.tagName==='button');
  assert.ok(copy); await copy.emit('click'); assert.ok(selectionFallback);
  assert.ok($('status').textContent.includes('Clipboard unavailable'));
  for(const fn of events.beforeprint||[])fn();
  assert.equal($('list').children.length,data.findings.length);
  assert.ok($('list').children.every(n=>n.open));
  assert.ok($('reference-list').children.every(n=>n.open));
  for(const fn of events.afterprint||[])fn();
  assert.equal($('list').children.length,80);
  assert.equal(descendants(body).filter(n=>n.tagName==='img').length,0);
  console.log('Dashboard DOM harness: counters, pagination, combined filters, search, sorting, details, blocked storage/clipboard, themes and print transitions passed.');
})().catch(e=>{console.error(e);process.exitCode=1;});

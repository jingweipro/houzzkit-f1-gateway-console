// Exercise the shipped submit handlers with an in-memory DOM and HTTP transport.
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const elements = new Map();
const calls = [];
function element(id) {
  if (!elements.has(id)) elements.set(id, {
    value: "", classList: {toggle() {}, add() {}}, dataset: {},
    addEventListener(event, handler) { this[event] = handler; },
    querySelector(selector) { return element(selector); },
    closest() { return this; }
  });
  return elements.get(id);
}
const scope = {
  document: {getElementById: element}, confirm: () => true,
  setInterval() {}, setTimeout() {}, clearTimeout() {},
  fetch: async (path, options) => {
    calls.push({path, options});
    return {ok: false, json: async () => ({error: "测试错误"})};
  }
};
vm.runInNewContext(fs.readFileSync(require.resolve("../app/app.js"), "utf8"), scope);
(async () => {
  for (const [target, field, action] of [
    ["sub-form", "sub-url", "add"], ["sub-list", "input[name=url]", "update"]
  ]) {
    const url = "https://fake.example/private?token=unit-marker";
    element(field).value = url;
    let prevented = false;
    await element(target).submit({target: element(target), preventDefault() { prevented = true; }});
    assert.ok(prevented);
    const last = calls.at(-1);
    assert.equal(last.path, "/api/subscription/" + action);
    assert.equal(last.options.method, "POST");
    assert.equal(JSON.parse(last.options.body).url, url);
    assert.equal(element(field).value, "");
    for (const node of elements.values()) {
      assert.ok(!JSON.stringify(node).includes("unit-marker"));
    }
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

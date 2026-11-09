const assert = require("node:assert");
const test = require("node:test");
const { sum } = require("../src/sum");

test("adds every value", () => {
  assert.strictEqual(sum([2, 3, 4]), 9);
});

test("handles an empty list", () => {
  assert.strictEqual(sum([]), 0);
});

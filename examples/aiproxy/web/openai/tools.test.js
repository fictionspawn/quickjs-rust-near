import { test } from "node:test";
import { equal } from "assert";
import { toolImplementations, tools } from "./tools.js";

test("should run javascript tool", async () => {
  const result = await toolImplementations.run_javascript({
    script: `
    return "hello";    
  `,
  });
  equal(result, JSON.stringify("hello"));
});

test("should run script generated by model", async () => {
  const script = `function fibonacciUpTo(max) {
    let sequence = [0, 1];
    while (true) {
        let nextValue = sequence[sequence.length - 1] + sequence[sequence.length - 2];
        if (nextValue > max) break;
        sequence.push(nextValue);
    }
    return sequence;
}

let result = fibonacciUpTo(50);
return result;`;
  const result = await toolImplementations.run_javascript({ script });
  equal(result, JSON.stringify([0, 1, 1, 2, 3, 5, 8, 13, 21, 34]));
});

test("run javascript in web4 contract", async () => {
  const args = JSON.parse(
    '{"script": "export function web4_get() {\\n    const request = JSON.parse(env.input()).request;\\n\\n    let response;\\n\\n    if (request.path === \'/\') {\\n        response = {\\n            contentType: \\"text/html; charset=UTF-8\\",\\n            body: env.base64_encode(`<!DOCTYPE html>\\\\n<html>\\\\n<head>\\\\n</head>\\\\n<body>\\\\n<h1>Hello World</h1>\\\\n</body>\\\\n<html>`)\\n        };\\n    }\\n    env.value_return(JSON.stringify(response));\\n}"}',
  );
  const result =
    await toolImplementations.run_javascript_in_web4_simulator(args);
  equal(
    result,
    `<!DOCTYPE html>
<html>
<head>
</head>
<body>
<h1>Hello World</h1>
</body>
<html>`,
  );
});

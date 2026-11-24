// npm test – unit tests that need no database or network
const { execFileSync } = require('child_process');
for (const f of ['scope.test.js', 'prices.test.js']) execFileSync(process.execPath, [require('path').join(__dirname, f)], { stdio: 'inherit' });

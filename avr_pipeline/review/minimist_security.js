// Isolated fixture assertions for the historical constructor-property defect.
// No network, files, commands, or persisted prototype changes.
const parse = require(require('path').resolve(process.argv[2], 'index.js'));
const checks = [];
function check(name, passed, category='security') { checks.push({name, passed:!!passed, category}); }
let a = parse(['--constructor.prototype.avrFixture', 'value']);
check('Object constructor not exposed by parse', a.constructor === Object || !Object.prototype.hasOwnProperty.call(a, 'constructor'));
check('Object prototype unchanged', ({}).avrFixture === undefined);
a = parse(['--_.constructor.prototype.avrFixture', 'value']);
check('Array constructor not modified', Array.avrFixture === undefined);
a = parse(['--_.constructor.avrFixture', 'value']);
check('Array constructor property unchanged', Array.avrFixture === undefined);
delete Array.avrFixture;
a = parse(['--group.name','fixture','--count','3','--no-color']);
check('nested normal property works', a.group.name === 'fixture', 'functionality');
check('numeric normal argument works', a.count === 3, 'functionality');
check('boolean normal argument works', a.color === false, 'functionality');
check('alias works', parse(['-v'], {alias:{v:'verbose'}}).verbose === true, 'functionality');
check('prototype fixture cleaned', ({}).avrFixture === undefined && Array.avrFixture === undefined, 'functionality');
const security = checks.filter(c=>c.category==='security');
console.log(JSON.stringify({case:'minimist-constructor', checks, security_passed:security.filter(c=>c.passed).length,
 security_total:security.length, functionality_passed:checks.filter(c=>c.category==='functionality').every(c=>c.passed), passed:checks.every(c=>c.passed)}));
process.exitCode = checks.every(c=>c.passed) ? 0 : 1;

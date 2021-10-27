const glob = require('glob');
const fs = require('fs');
const path = require('path');
const {promisify} = require('util');
const exec = promisify(require('child_process').exec);

const outputDir = './output';

glob('../dist/**/*.js', async (err, matches) => {
  for (const match of matches) {
    try {
      const {stdout, stderr} = await exec(
        `check-side-effects "${match}" --warnings true`,
      );
      const cleanedOutput = stdout.replace(/(^[ \t]*\n)/gm, '').trim();

      if (cleanedOutput) {
        const filePath = match.replace('../dist', outputDir);
        fs.mkdirSync(path.dirname(filePath), {recursive: true});
        fs.writeFileSync(filePath, cleanedOutput);
      }
    } catch (e) {
      console.error(e);
    }
  }
});

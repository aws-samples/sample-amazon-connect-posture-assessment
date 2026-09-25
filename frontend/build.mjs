// Bundles the report UI into the two files ReportGenerator inlines into every
// HTML report. Output is committed so installing the Python package never needs
// Node; CI rebuilds and fails if the committed bundle is stale (`npm run check`).
import { execFileSync } from 'node:child_process';
import * as esbuild from 'esbuild';

const OUT_DIR = '../amazon_connect_assessment/templates/app';

await esbuild.build({
  entryPoints: { 'report-app': 'src/index.jsx' },
  outdir: OUT_DIR,
  bundle: true,
  minify: true,
  format: 'iife',
  target: ['es2020'],
  jsx: 'automatic',
  // Fonts/icons referenced from Cloudscape CSS are inlined so the report stays
  // a single self-contained file that works offline.
  loader: { '.woff': 'dataurl', '.woff2': 'dataurl', '.svg': 'dataurl', '.png': 'dataurl' },
  define: { 'process.env.NODE_ENV': '"production"' },
  // Keep third-party licence notices with the redistributed code.
  legalComments: 'eof',
  logLevel: 'warning',
});

if (process.argv.includes('--check')) {
  // `git status` (unlike `git diff`) also reports untracked output, so a bundle
  // that was never committed fails the check too.
  const status = execFileSync('git', ['status', '--porcelain', '--', OUT_DIR], { encoding: 'utf8' });
  if (status.trim()) {
    console.error(`The committed report UI bundle is stale. Run \`npm run build\` and commit ${OUT_DIR}:\n${status}`);
    process.exit(1);
  }
}

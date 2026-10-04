// Bundles the report UI into the two files ReportGenerator inlines into every
// HTML report. Output is committed so installing the Python package never needs
// Node; CI rebuilds and fails if the committed bundle is stale (`npm run check`).
import { readFile } from 'node:fs/promises';
import * as esbuild from 'esbuild';

const OUT_DIR = '../amazon_connect_assessment/templates/app';
const OUTPUT_FILES = [`${OUT_DIR}/report-app.js`, `${OUT_DIR}/report-app.css`];
const checking = process.argv.includes('--check');

async function readOutputs() {
  return Promise.all(
    OUTPUT_FILES.map(async (path) => {
      try {
        return await readFile(path);
      } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
      }
    }),
  );
}

const previousOutputs = checking ? await readOutputs() : null;

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

if (checking) {
  const currentOutputs = await readOutputs();
  const stale = currentOutputs.some(
    (output, index) =>
      previousOutputs[index] === null || output === null || !previousOutputs[index].equals(output),
  );
  if (stale) {
    console.error(
      `The committed report UI bundle is stale. Run \`npm run build\` and commit ${OUTPUT_FILES.join(', ')}.`,
    );
    process.exit(1);
  }
}

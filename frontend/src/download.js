// Browser-local downloads. Nothing leaves the reader's machine.

export function downloadBlob(blob, filename) {
  if (!window.URL || !window.URL.createObjectURL) {
    throw new Error('This browser does not support local file downloads.');
  }
  const url = window.URL.createObjectURL(blob);
  try {
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.hidden = true;
    document.body.appendChild(link);
    link.click();
    link.remove();
  } finally {
    window.setTimeout(() => window.URL.revokeObjectURL(url), 1000);
  }
}

export function downloadText(filename, content, mediaType) {
  downloadBlob(new Blob([content], { type: mediaType || 'text/plain;charset=utf-8' }), filename);
}

// Reduce flow names/IDs to a portable filename component.
export function safeFilenamePart(value) {
  let text = String(value || '');
  if (text.normalize) text = text.normalize('NFKD');
  text = text
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[._-]+|[._-]+$/g, '')
    .slice(0, 80);
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(text)) text = '';
  return text || 'journey';
}

const CSV_COLUMNS = [
  ['check_id', 'Check ID'],
  ['check_name', 'Check Name'],
  ['pillar', 'Pillar'],
  ['severity', 'Severity'],
  ['status', 'Status'],
  ['resource_type', 'Resource Type'],
  ['resource_id', 'Resource ID'],
  ['instance', 'Instance'],
  ['description', 'Description'],
];

export function findingsCsv(findings) {
  // Prefix formula-leading cells so spreadsheet apps treat them as text.
  const cell = (value) => {
    let text = String(value ?? '');
    if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  const header = CSV_COLUMNS.map(([, label]) => cell(label)).join(',');
  const rows = findings.map((f) => CSV_COLUMNS.map(([key]) => cell(f[key])).join(','));
  return [header, ...rows].join('\n');
}

// PNG exports are rasterized from the SVG export, capped so a huge flow can't
// exhaust browser canvas memory.
const MAX_PNG_DIMENSION = 8192;
const MAX_PNG_PIXELS = 32000000;

// Output size for a PNG rendered from an SVG of the given size, or null when the
// size is unusable. Never upscales; downscales to stay within both caps.
export function pngOutputSize(width, height) {
  const w = Number(width);
  const h = Number(height);
  if (!Number.isFinite(w) || !Number.isFinite(h) || w <= 0 || h <= 0) return null;
  const scale = Math.min(1, MAX_PNG_DIMENSION / w, MAX_PNG_DIMENSION / h, Math.sqrt(MAX_PNG_PIXELS / (w * h)));
  return { width: Math.max(1, Math.floor(w * scale)), height: Math.max(1, Math.floor(h * scale)) };
}

export function downloadSvgAsPng(svg, filename) {
  return new Promise((resolve, reject) => {
    const size = svg && svg.content ? pngOutputSize(svg.width, svg.height) : null;
    if (!size) {
      reject(new Error(svg && svg.content ? 'PNG dimensions are invalid.' : 'PNG export is unavailable.'));
      return;
    }
    const { width: outW, height: outH } = size;
    const sourceUrl = window.URL.createObjectURL(new Blob([svg.content], { type: 'image/svg+xml;charset=utf-8' }));
    const image = new Image();
    const finish = (error) => {
      window.URL.revokeObjectURL(sourceUrl);
      if (error) reject(error);
      else resolve();
    };
    image.onload = () => {
      try {
        const canvas = document.createElement('canvas');
        canvas.width = outW;
        canvas.height = outH;
        const context = canvas.getContext('2d');
        if (!context) throw new Error('Canvas rendering is unavailable.');
        context.fillStyle = '#ffffff';
        context.fillRect(0, 0, outW, outH);
        context.drawImage(image, 0, 0, outW, outH);
        canvas.toBlob((blob) => {
          if (!blob) {
            finish(new Error('Could not create the PNG image.'));
            return;
          }
          try {
            downloadBlob(blob, filename);
            finish();
          } catch (error) {
            finish(error);
          }
        }, 'image/png');
      } catch (error) {
        finish(error);
      }
    };
    image.onerror = () => finish(new Error('Could not read the SVG for PNG conversion.'));
    image.src = sourceUrl;
  });
}

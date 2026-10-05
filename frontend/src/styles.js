// Styling for server-rendered finding markdown (the one place the report shows
// markup it didn't build from Cloudscape components) and the print-only findings
// table. Values are Cloudscape design tokens, so they follow light/dark mode.
import {
  borderRadiusItem,
  colorBackgroundCodeView,
  colorBorderDividerDefault,
  colorTextLinkDefault,
  fontFamilyBase,
  fontFamilyMonospace,
  spaceScaledS,
  spaceScaledXs,
} from '@cloudscape-design/design-tokens';

const MARKDOWN_CSS = `
.acr-markdown > :first-child { margin-top: 0; }
.acr-markdown > :last-child { margin-bottom: 0; }
.acr-markdown p, .acr-markdown ul, .acr-markdown ol { margin: 0 0 ${spaceScaledS}; }
.acr-markdown ul, .acr-markdown ol { padding-inline-start: 20px; }
.acr-markdown li + li { margin-top: ${spaceScaledXs}; }
.acr-markdown a { color: ${colorTextLinkDefault}; }
.acr-markdown code {
  font-family: ${fontFamilyMonospace}; font-size: 0.92em;
  background: ${colorBackgroundCodeView}; border-radius: 4px; padding: 1px 4px;
}
.acr-markdown pre {
  background: ${colorBackgroundCodeView}; border: 1px solid ${colorBorderDividerDefault};
  border-radius: ${borderRadiusItem}; padding: ${spaceScaledS}; overflow: auto; margin: 0 0 ${spaceScaledS};
}
.acr-markdown pre code { background: none; padding: 0; }
.acr-metric-link {
  appearance: none; background: none; border: 0; color: inherit; cursor: pointer;
  display: inline-block; font: inherit; margin: 0; padding: 0; text-align: start;
}
.acr-metric-link:hover { text-decoration: underline; text-underline-offset: 3px; }
.acr-metric-link:focus-visible {
  border-radius: ${borderRadiusItem}; outline: 2px solid ${colorTextLinkDefault}; outline-offset: 2px;
}
.acr-evidence-value { display: inline-flex; align-items: flex-start; gap: ${spaceScaledXs}; max-width: 100%; overflow-wrap: anywhere; white-space: pre-wrap; }
.acr-print-finding-list { font-family: ${fontFamilyBase}; font-size: 11px; }
.acr-print-finding { border-top: 2px solid ${colorBorderDividerDefault}; padding-top: ${spaceScaledS}; margin-top: ${spaceScaledS}; break-inside: auto; }
.acr-print-finding h3, .acr-print-finding h4 { margin: ${spaceScaledS} 0 ${spaceScaledXs}; break-after: avoid; }
.acr-print-record { display: grid; grid-template-columns: minmax(130px, 0.28fr) minmax(0, 1fr); gap: ${spaceScaledXs} ${spaceScaledS}; margin: 0; }
.acr-print-record dt { font-weight: bold; }
.acr-print-record dd { margin: 0; min-width: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
.acr-print-evidence { break-inside: auto; }
.acr-print-remediation ol, .acr-print-remediation ul { margin: 0; padding-inline-start: 20px; }
.acr-print-remediation li, .acr-print-remediation pre { break-inside: avoid; }
.acr-print-remediation pre { overflow-wrap: anywhere; white-space: pre-wrap; }
@media print { .acr-no-print { display: none !important; } }
`;

// A constructed stylesheet is applied through the CSSOM, which the report's
// hash-based style-src CSP permits (a runtime <style> element would be blocked).
export function injectStyles() {
  if (typeof CSSStyleSheet === 'undefined' || !('adoptedStyleSheets' in document)) return;
  const sheet = new CSSStyleSheet();
  sheet.replaceSync(MARKDOWN_CSS);
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
}

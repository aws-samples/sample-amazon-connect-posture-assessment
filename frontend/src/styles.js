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
table.acr-print-findings { width: 100%; border-collapse: collapse; font-family: ${fontFamilyBase}; font-size: 11px; }
.acr-print-findings th, .acr-print-findings td {
  border: 1px solid ${colorBorderDividerDefault}; padding: ${spaceScaledXs}; text-align: start; vertical-align: top;
}
.acr-print-findings tr { break-inside: avoid; }
@media print { .acr-no-print { display: none !important; } }
`;

export function injectStyles() {
  const style = document.createElement('style');
  style.textContent = MARKDOWN_CSS;
  document.head.appendChild(style);
}

import React from 'react';
import { createRoot } from 'react-dom/client';
import '@cloudscape-design/global-styles/index.css';
import { I18nProvider } from '@cloudscape-design/components/i18n';
import enMessages from '@cloudscape-design/components/i18n/messages/all.en';
import App from './App';
import { loadReportData } from './data';
import { ReportErrorAlert, ReportErrorBoundary } from './ReportError';
import { injectStyles } from './styles';

injectStyles();
// Built-in English strings supply accessible labels for icon-only controls
// (filter token dismiss, pagination, tab scrolling, ...).
let content;
try {
  content = <App data={loadReportData()} />;
} catch (error) {
  console.error(error);
  content = <ReportErrorAlert error={error} />;
}
createRoot(document.getElementById('root')).render(
  <I18nProvider locale="en" messages={[enMessages]}>
    <ReportErrorBoundary>{content}</ReportErrorBoundary>
  </I18nProvider>,
);

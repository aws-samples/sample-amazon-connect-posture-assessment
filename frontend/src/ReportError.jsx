import React from 'react';
import { Alert, Box, ContentLayout, Header } from '@cloudscape-design/components';

export function ReportErrorAlert({ error }) {
  return (
    <Box padding="l">
      <ContentLayout header={<Header variant="h1">Amazon Connect Assessment Report</Header>}>
        <Alert type="error" header="This report could not be displayed">
          {error?.message || String(error)}
          <Box variant="p" padding={{ top: 's' }}>
            Re-generate the report with the assessment tool. The same findings are available in its JSON and CSV
            outputs.
          </Box>
        </Alert>
      </ContentLayout>
    </Box>
  );
}

// Render-time failures (e.g. data that passes the schema check but is malformed)
// show an Alert instead of unmounting the whole page.
export class ReportErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('Report UI failed to render:', error, info?.componentStack);
  }

  render() {
    return this.state.error ? <ReportErrorAlert error={this.state.error} /> : this.props.children;
  }
}

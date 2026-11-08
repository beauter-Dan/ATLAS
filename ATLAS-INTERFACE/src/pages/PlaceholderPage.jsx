import PageHeader from '../components/PageHeader.jsx';
import Panel from '../components/Panel.jsx';
import { EmptyState } from '../components/States.jsx';

export default function PlaceholderPage({ item }) {
  return (
    <>
      <PageHeader title={item.title} description={item.description} />
      <Panel>
        <EmptyState title="Not built yet" hint={`Planned for milestone ${item.milestone}.`} />
      </Panel>
    </>
  );
}

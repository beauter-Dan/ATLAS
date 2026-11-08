import { Link } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import { EmptyState } from '../components/States.jsx';

export default function NotFoundPage() {
  return (
    <>
      <PageHeader title="Page not found" />
      <EmptyState title="That address does not exist." action={<Link className="btn" to="/">Go to dashboard</Link>} />
    </>
  );
}

import { Routes, Route } from 'react-router-dom';
import AppLayout from './layouts/AppLayout.jsx';
import DashboardPage from './pages/DashboardPage.jsx';
import TargetsPage from './pages/TargetsPage.jsx';
import TargetDetailPage from './pages/TargetDetailPage.jsx';
import TargetFormPage from './pages/TargetFormPage.jsx';
import AssessmentsPage from './pages/AssessmentsPage.jsx';
import AssessmentDetailPage from './pages/AssessmentDetailPage.jsx';
import AssessmentFormPage from './pages/AssessmentFormPage.jsx';
import PlaceholderPage from './pages/PlaceholderPage.jsx';
import NotFoundPage from './pages/NotFoundPage.jsx';
import LoginPage from './pages/LoginPage.jsx';
import { useAuth } from './auth/AuthContext.jsx';
import { NAV_ITEMS } from './config/navigation.js';

// Sections that have a real page. Everything else renders a placeholder.
const BUILT = new Set(['/', '/targets', '/assessments']);

export default function App() {
  const { status } = useAuth();
  if (status !== 'authenticated') return <LoginPage />;     // no page (and no API call) renders without a session
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="targets" element={<TargetsPage />} />
        <Route path="targets/new" element={<TargetFormPage />} />
        <Route path="targets/:id" element={<TargetDetailPage />} />
        <Route path="targets/:id/edit" element={<TargetFormPage />} />
        <Route path="assessments" element={<AssessmentsPage />} />
        <Route path="assessments/new" element={<AssessmentFormPage />} />
        <Route path="assessments/:id" element={<AssessmentDetailPage />} />
        {NAV_ITEMS.filter((i) => !BUILT.has(i.path)).map((item) => (
          <Route key={item.path} path={item.path.slice(1)} element={<PlaceholderPage item={item} />} />
        ))}
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

import { Routes, Route } from 'react-router-dom';
import AppLayout from './layouts/AppLayout.jsx';
import DashboardPage from './pages/DashboardPage.jsx';
import TargetsPage from './pages/TargetsPage.jsx';
import TargetDetailPage from './pages/TargetDetailPage.jsx';
import TargetFormPage from './pages/TargetFormPage.jsx';
import PlaceholderPage from './pages/PlaceholderPage.jsx';
import NotFoundPage from './pages/NotFoundPage.jsx';
import { NAV_ITEMS } from './config/navigation.js';

// Sections that have a real page. Everything else renders a placeholder.
const BUILT = new Set(['/', '/targets']);

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="targets" element={<TargetsPage />} />
        <Route path="targets/new" element={<TargetFormPage />} />
        <Route path="targets/:id" element={<TargetDetailPage />} />
        <Route path="targets/:id/edit" element={<TargetFormPage />} />
        {NAV_ITEMS.filter((i) => !BUILT.has(i.path)).map((item) => (
          <Route key={item.path} path={item.path.slice(1)} element={<PlaceholderPage item={item} />} />
        ))}
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}

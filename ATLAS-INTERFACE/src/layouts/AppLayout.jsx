import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { NAV_GROUPS } from '../config/navigation.js';
import { env } from '../config/env.js';

export default function AppLayout() {
  const [open, setOpen] = useState(false);
  const { pathname } = useLocation();
  useEffect(() => setOpen(false), [pathname]);

  return (
    <div className="shell">
      <a className="skip-link" href="#main">Skip to content</a>
      <aside className={`sidebar ${open ? 'sidebar--open' : ''}`} aria-label="Primary">
        <div className="brand">
          <span className="brand__mark" aria-hidden="true" />
          <span className="brand__name">ATLAS</span>
        </div>
        <nav>
          {NAV_GROUPS.map((group) => (
            <div className="nav-group" key={group.label}>
              <p className="nav-group__label">{group.label}</p>
              {group.items.map((item) => (
                <NavLink key={item.path} to={item.path} end={item.path === '/'}
                  className={({ isActive }) => `nav-link ${isActive ? 'nav-link--active' : ''}`}>
                  {item.title}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
      </aside>
      {open && <button className="scrim" aria-label="Close menu" onClick={() => setOpen(false)} />}

      <div className="content">
        <header className="topbar">
          <button className="menu-btn" onClick={() => setOpen(true)} aria-label="Open menu">Menu</button>
          <div className="topbar__spacer" />
          {env.useMock
            ? <span className="chip chip--warn" title="Synthetic data, not connected to a backend">Demo data</span>
            : <span className="chip chip--ok" title={env.apiBaseUrl}>Live API</span>}
        </header>
        <main id="main" className="main"><Outlet /></main>
      </div>
    </div>
  );
}

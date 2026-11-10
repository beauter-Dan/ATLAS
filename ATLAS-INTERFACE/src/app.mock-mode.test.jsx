// Full app in demo mode (VITE_USE_MOCK default): exercises the mock handler, mappers, services and pages together.
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import App from './App.jsx';
import { AuthProvider } from './auth/AuthContext.jsx';

const mount = (path = '/') => render(<MemoryRouter initialEntries={[path]}><AuthProvider><App /></AuthProvider></MemoryRouter>);

describe('demo mode', () => {
  it('dashboard renders counts, progress and activity from the contract shape', async () => {
    mount('/');
    expect(await screen.findByText('Spring review', { selector: '*' }, { timeout: 5000 })).toBeTruthy();
    expect(screen.getByText(/Data collection ran/)).toBeTruthy();
  });

  it('lists targets with derived authorization, then opens a detail page with per-assessment scope', async () => {
    const u = userEvent.setup();
    mount('/targets');
    const table = await screen.findByRole('table', {}, { timeout: 5000 });
    expect(within(table).getByText('Demo Retail')).toBeTruthy();
    const rows = within(table).getAllByRole('row');
    const status = (name) => within(rows.find((r) => r.textContent.includes(name))).getByText(/^(Authorized|Pending authorization|Authorization expired)$/).textContent;
    expect([status('Demo Retail'), status('Demo Logistics'), status('Demo Media')]).toEqual(['Authorized', 'Pending authorization', 'Authorization expired']);
    await u.click(within(table).getByRole('link', { name: 'Demo Retail' }));
    expect(await screen.findByText('payments.retail.example', {}, { timeout: 5000 })).toBeTruthy();
    expect(screen.getByText('shop.retail.example')).toBeTruthy();
  });

  it('registers a target through the form (create payload accepted by the mock backend)', async () => {
    const u = userEvent.setup();
    mount('/targets/new');
    await u.type(await screen.findByLabelText('Name'), 'Synthetic Corp');
    await u.type(screen.getByLabelText('Organization'), 'Synthetic Org');
    await u.type(screen.getByLabelText('Base domain'), 'synthetic.test');
    await u.type(screen.getByLabelText('Authorization reference'), 'REF-9');
    await u.type(screen.getByLabelText('Granted by'), 'Synthetic CISO');
    await u.type(screen.getByLabelText('Valid from'), '2026-01-01');
    await u.type(screen.getByLabelText('Valid until'), '2099-01-01');
    await u.click(screen.getByRole('button', { name: 'Register target' }));
    expect(await screen.findByRole('heading', { name: 'Synthetic Corp' }, { timeout: 5000 })).toBeTruthy();
  });

  it('assessment workflow: create -> activation refused without scope -> add rule -> activate -> pause', async () => {
    const u = userEvent.setup();
    mount('/assessments/new?target=t1');
    await u.type(await screen.findByLabelText('Name'), 'Workflow demo');
    await u.click(screen.getByRole('button', { name: 'Create assessment' }));
    expect(await screen.findByRole('heading', { name: 'Workflow demo' }, { timeout: 5000 })).toBeTruthy();
    await u.click(await screen.findByRole('button', { name: 'Activate' }));
    expect((await screen.findByRole('alert', {}, { timeout: 5000 })).textContent).toMatch(/at least one permitted scope rule/);
    await u.type(screen.getByLabelText('Value'), 'shop.retail.example');
    await u.click(screen.getByRole('button', { name: 'Add rule' }));
    expect(await screen.findByText('shop.retail.example', {}, { timeout: 5000 })).toBeTruthy();
    await u.click(screen.getByRole('button', { name: 'Activate' }));
    expect(await screen.findByRole('button', { name: 'Pause' }, { timeout: 5000 })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Activate' })).toBeNull();
  });

  it('lists seeded assessments and opens one with its scope and members', async () => {
    const u = userEvent.setup();
    mount('/assessments');
    const table = await screen.findByRole('table', {}, { timeout: 5000 });
    expect(within(table).getByText('Spring review')).toBeTruthy();
    await u.click(within(table).getByRole('link', { name: 'Spring review' }));
    expect(await screen.findByText('payments.retail.example', {}, { timeout: 5000 })).toBeTruthy();
    expect(screen.getByText('demo.viewer')).toBeTruthy();
    expect(screen.getByText('owner')).toBeTruthy();
  });
});

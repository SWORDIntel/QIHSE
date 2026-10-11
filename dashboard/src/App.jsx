import { useCallback, useEffect, useState } from 'react';
import {
  Database, Globe2, LogOut, ScrollText, Server,
  ShieldCheck, Activity, Gauge, Terminal,
} from 'lucide-react';
import { apiGet, apiPost } from './api.js';
import LoginView from './views/LoginView.jsx';
import FleetView from './views/FleetView.jsx';
import ClusterView from './views/ClusterView.jsx';
import FederationView from './views/FederationView.jsx';
import JournalView from './views/JournalView.jsx';
import KeyspaceView from './views/KeyspaceView.jsx';
import ActionsView from './views/ActionsView.jsx';
import LogView from './views/LogView.jsx';
import FabricView from './views/FabricView.jsx';
import RecordsView from './views/RecordsView.jsx';
import TasksView from './views/TasksView.jsx';
import TelemetryView from './views/TelemetryView.jsx';

const Frame = () => (
  <>
    <div className="corner tl" /><div className="corner tr" />
    <div className="corner bl" /><div className="corner br" />
    <div className="foot-tag">QIHSE OPERATOR BROWSER</div>
  </>
);

export default function App() {
  const [me, setMe] = useState(null);        // whoami payload or 'login'
  const [checking, setChecking] = useState(true);
  const [activeTab, setActiveTab] = useState('fleet');

  const check = useCallback(async () => {
    setChecking(true);
    const { status, body } = await apiGet('/whoami');
    setChecking(false);
    setMe(status === 200 ? body : 'login');
  }, []);

  useEffect(() => { check(); }, [check]);

  const logout = async () => {
    if (me && me !== 'login') await apiPost('/logout', {}, me.csrf);
    setMe('login');
    check();
  };

  const tabs = [
    ['fleet', Activity, 'Overview', 'cyan'],
    ['cluster', Server, 'Cluster', 'chartreuse'],
    ['federation', Globe2, 'Federation', 'periwinkle'],
    ['journal', ScrollText, 'Journal', 'blue'],
    ['keyspace', Database, 'Keyspace', 'green'],
    ['records', null, 'Records', 'chartreuse'],
    ['actions', ShieldCheck, 'Actions', 'coral'],
    ['fabric', null, 'Fabric', 'amber'],
    ['tasks', null, 'Tasks', 'periwinkle'],
    ['log', Terminal, 'Log', 'cyan'],
    ['telemetry', Gauge, 'Telemetry', 'dim'],
  ];

  if (checking) {
    return <div className="login-wrap"><div className="card login-card">Checking bridge…</div></div>;
  }

  // Login wall exists only in --require-login mode; the default
  // operator-context bridge serves the dashboard straight away.
  if (me === 'login') {
    return (
      <>
        <Frame />
        <LoginView onLoggedIn={check} />
      </>
    );
  }

  const csrf = me.csrf || '';

  return (
    <>
      <Frame />
      <nav className="topnav">
        <div className="topnav-inner">
          <div className="brand"><img src="/sword-logo.png" alt="SWORD" />QIHSE <em>browser</em></div>
          <ul className="topnav-links">
            {tabs.map(([id, , label, accent]) => (
              <li key={id}
                  className={`topnav-item ${activeTab === id ? 'active' : ''}`}
                  data-accent={accent}
                  onClick={() => setActiveTab(id)}>
                {label}
              </li>
            ))}
          </ul>
          <div className="topnav-meta">
            <span className="who">
              {me.mode === 'operator-context'
                ? 'operator context'
                : `${me.username} · ${me.factor >= 2 ? 'two-factor' : 'single-factor'}`}
            </span>
            {me.mode === 'operator-context'
              ? <span className="status-badge"><span className="status-dot" /> live</span>
              : <button className="ghost-btn logout-btn" onClick={logout}>
                  <LogOut size={13} /> Log out
                </button>}
          </div>
        </div>
      </nav>

      <main className="main-content">
        <header className="header">
          <div className="eyebrow">QIHSE OPERATOR BROWSER</div>
          <h1 data-accent={tabs.find(([id]) => id === activeTab)?.[3] || 'cyan'}>
            {tabs.find(([id]) => id === activeTab)?.[2] || 'Overview'}
          </h1>
          <p>
            Every value on this screen came over the wire under an
            authenticated principal — refusals render as refusals, never as
            emptiness.
          </p>
        </header>

        {activeTab === 'fleet' && <FleetView />}
        {activeTab === 'cluster' && <ClusterView />}
        {activeTab === 'federation' && <FederationView />}
        {activeTab === 'journal' && <JournalView />}
        {activeTab === 'keyspace' && <KeyspaceView />}
        {activeTab === 'actions' && <ActionsView me={me} csrf={csrf} />}
        {activeTab === 'records' && <RecordsView />}
        {activeTab === 'fabric' && <FabricView />}
        {activeTab === 'tasks' && <TasksView />}
        {activeTab === 'log' && <LogView />}
        {activeTab === 'telemetry' && <TelemetryView />}
      </main>
    </>
  );
}

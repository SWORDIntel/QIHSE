import { useState } from 'react';
import { useSignalR } from './hooks/useSignalR';
import { Header } from './components/Header';
import { TelemetryView } from './views/TelemetryView';
import { ClusterMeshView } from './views/ClusterMeshView';
import { VectorHnswView } from './views/VectorHnswView';

export default function App() {
  const [apiToken, setApiToken] = useState('');
  const [tokenInput, setTokenInput] = useState('');
  const { telemetry, isConnected } = useSignalR(apiToken);
  const [activeTab, setActiveTab] = useState<string>('telemetry');

  if (!apiToken) return (
    <main className="min-h-screen bg-[#0a0c10] text-slate-100 flex items-center justify-center p-6">
      <form className="max-w-md w-full space-y-4" onSubmit={e => {
        e.preventDefault();
        if (tokenInput.length >= 32) { setApiToken(tokenInput); setTokenInput(''); }
      }}>
        <h1 className="text-lg font-bold">QIHSE Studio authorization</h1>
        <p className="text-sm text-slate-400">Enter the local QIHSE_STUDIO_API_TOKEN. It is held in memory only.</p>
        <input type="password" autoComplete="off" aria-label="Studio API token" value={tokenInput}
          onChange={e => setTokenInput(e.target.value)} className="w-full p-3 bg-slate-900 border border-slate-600 rounded" />
        <button type="submit" className="px-4 py-2 bg-cyan-700 rounded" disabled={tokenInput.length < 32}>Connect</button>
      </form>
    </main>
  );

  return (
    <div className="min-h-screen bg-[#0a0c10] text-slate-100 flex flex-col">
      <Header
        telemetry={telemetry}
        isConnected={isConnected}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-6">
        {activeTab === 'telemetry' && <TelemetryView telemetry={telemetry} />}
        {activeTab === 'cluster' && <ClusterMeshView telemetry={telemetry} apiToken={apiToken} />}
        {activeTab === 'vectors' && <VectorHnswView apiToken={apiToken} />}
      </main>

      <footer className="border-t border-slate-900 bg-[#07090d] py-3 px-6 text-center text-xs text-slate-500 font-mono">
        QIHSE Studio v2.0 · ASP.NET Core 8 Kestrel + React 18 SPA · Native Hardware Accelerated Memory Fabric
      </footer>
    </div>
  );
}

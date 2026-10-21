import { useState } from 'react';
import { useSignalR } from './hooks/useSignalR';
import { Header } from './components/Header';
import { TelemetryView } from './views/TelemetryView';
import { ClusterMeshView } from './views/ClusterMeshView';
import { VectorHnswView } from './views/VectorHnswView';

export default function App() {
  // No embedded default: the operator supplies the token at runtime
  // (localStorage key `qihse_studio_token`). Empty means LAN read-only access.
  const [apiToken] = useState<string>(() => {
    return localStorage.getItem('qihse_studio_token') || '';
  });
  const { telemetry, isConnected } = useSignalR(apiToken);
  const [activeTab, setActiveTab] = useState<string>('telemetry');

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

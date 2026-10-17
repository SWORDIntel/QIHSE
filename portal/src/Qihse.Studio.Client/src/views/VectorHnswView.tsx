import { useState } from 'react';
import { Database, Search, Cpu, Zap } from 'lucide-react';
import type { VectorSearchResult } from '../types';

export const VectorHnswView: React.FC = () => {
  const [topK, setTopK] = useState<number>(10);
  const [metric, setMetric] = useState<string>('cosine');
  const [precision, setPrecision] = useState<string>('int8');
  const [loading, setLoading] = useState<boolean>(false);
  const [results, setResults] = useState<VectorSearchResult[]>([]);

  const handleSearch = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/vector/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ topK, metric, precision }),
      });
      const data = await res.json();
      setResults(data);
    } catch (err) {
      console.error('Vector search failed', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Query Control Card */}
      <div className="p-5 rounded-lg bg-[#12151d] border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Database size={18} className="text-purple-400" />
            <h2 className="text-sm font-bold tracking-wider text-slate-200 uppercase">
              Vector DB & Multi-Precision HNSW Search Engine
            </h2>
          </div>
          <div className="text-xs text-slate-400">
            Broad Oak Engine · 100,000 Vectors (128 Dimensions)
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          {/* Top-K */}
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">CANDIDATES (Top-K)</label>
            <select
              value={topK}
              onChange={(e) => setTopK(Number(e.target.value))}
              className="w-full bg-[#0d1017] border border-slate-700 text-slate-200 text-xs rounded px-3 py-2 outline-none focus:border-purple-500 font-mono"
            >
              <option value={5}>Top-5 Candidates</option>
              <option value={10}>Top-10 Candidates</option>
              <option value={20}>Top-20 Candidates</option>
            </select>
          </div>

          {/* Metric */}
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">DISTANCE METRIC</label>
            <select
              value={metric}
              onChange={(e) => setMetric(e.target.value)}
              className="w-full bg-[#0d1017] border border-slate-700 text-slate-200 text-xs rounded px-3 py-2 outline-none focus:border-purple-500 font-mono"
            >
              <option value="cosine">Cosine Distance (Normalized)</option>
              <option value="euclidean">Euclidean Distance (L2)</option>
              <option value="dot">Dot Product (Inner Product)</option>
            </select>
          </div>

          {/* Precision Tiering */}
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">PRECISION TIERING</label>
            <select
              value={precision}
              onChange={(e) => setPrecision(e.target.value)}
              className="w-full bg-[#0d1017] border border-slate-700 text-slate-200 text-xs rounded px-3 py-2 outline-none focus:border-purple-500 font-mono"
            >
              <option value="int8">INT8 Quantized (AVX-512 VNNI / AVX2)</option>
              <option value="fp16">FP16 Layer-0 (Fused F16C+FMA)</option>
              <option value="fp32">FP32 Master (4-Way AVX2 ILP)</option>
            </select>
          </div>

          {/* Execute Button */}
          <div>
            <button
              onClick={handleSearch}
              disabled={loading}
              className="w-full py-2 px-4 rounded bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
            >
              <Search size={14} />
              {loading ? 'Searching SIMD...' : 'Run Query Benchmark'}
            </button>
          </div>
        </div>
      </div>

      {/* Latency Comparison Across Precision Modes */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-lg bg-[#12151d] border border-slate-800">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>INT8 SCALAR QUANTIZATION</span>
            <span className="text-purple-400 font-bold font-mono">AVX-512 VNNI</span>
          </div>
          <div className="text-xl font-bold text-slate-100 mt-2 font-mono">
            3.89 ms <span className="text-xs text-emerald-400 font-normal">p50 @ 100K vecs</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            64 MACs/cycle via <code className="text-purple-300">vpdpbusd</code> on Zen 4 & Broadwell 4-way unroll.
          </p>
        </div>

        <div className="p-4 rounded-lg bg-[#12151d] border border-slate-800">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>HNSW GRAPH LAYER-0 TRAVERSAL</span>
            <span className="text-cyan-400 font-bold font-mono">F16C + FMA</span>
          </div>
          <div className="text-xl font-bold text-slate-100 mt-2 font-mono">
            176 µs <span className="text-xs text-emerald-400 font-normal">p50 @ 10K vecs (5.96x)</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            50% reduced bus bandwidth promoting top-M candidates for exact FP32 re-ranking.
          </p>
        </div>

        <div className="p-4 rounded-lg bg-[#12151d] border border-slate-800">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>BINARY HAMMING PRE-FILTER</span>
            <span className="text-amber-400 font-bold font-mono">AVX-512 VPOPCNTDQ</span>
          </div>
          <div className="text-xl font-bold text-slate-100 mt-2 font-mono">
            512 dims/cycle <span className="text-xs text-amber-400 font-normal">8x speedup</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Hardware 512-bit vector popcount (<code className="text-amber-300">_mm512_popcnt_epi64</code>).
          </p>
        </div>
      </div>

      {/* Query Results */}
      {results.length > 0 && (
        <div className="p-5 rounded-lg bg-[#12151d] border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Zap size={14} className="text-purple-400" />
              Retrieved Nearest Neighbors ({results.length} Candidates)
            </h3>
            <span className="text-xs font-mono text-cyan-400 font-bold">
              Latency: {results[0]?.latencyUs.toFixed(1)} µs
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0d1017] text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">RANK</th>
                  <th className="py-2.5 px-3">VECTOR ID</th>
                  <th className="py-2.5 px-3">DISTANCE SCORE</th>
                  <th className="py-2.5 px-3">PRECISION</th>
                  <th className="py-2.5 px-3">ACCELERATION PIPELINE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-200">
                {results.map((r, idx) => (
                  <tr key={r.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2 px-3 text-slate-400">#{idx + 1}</td>
                    <td className="py-2 px-3 font-bold text-slate-100">vec_{r.id}</td>
                    <td className="py-2 px-3 text-cyan-400">{r.distance.toFixed(4)}</td>
                    <td className="py-2 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px]">
                        {r.precisionUsed}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-400 flex items-center gap-2">
                      <Cpu size={12} className="text-emerald-400" />
                      <span>{r.acceleratorUsed}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

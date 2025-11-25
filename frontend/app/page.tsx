"use client";

import React, { useState, useEffect } from "react";
import axios from "axios";
import { Shield, AlertTriangle, CheckCircle, Search, Terminal, Image as ImageIcon, XCircle, Activity, Clock, ArrowRight } from "lucide-react";

export default function ThreatScanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [error, setError] = useState("");

  // Fetch history on load
  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await axios.get("http://localhost:8000/api/v1/history");
      setHistory(res.data);
    } catch (err) {
      console.error("Failed to load history", err);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    setError("");

    try {
      const response = await axios.post("http://localhost:8000/api/v1/scan/url", {
        url: url,
        client_ip: "127.0.0.1",
      });
      setResult(response.data);
      fetchHistory(); // Refresh history after scan
    } catch (err) {
      setError("Connection Failed: Is the Docker Backend running?");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (verdict: string) => {
    if (verdict === "Safe") return "text-green-500 border-green-500 bg-green-500/10";
    if (verdict === "Suspicious") return "text-yellow-500 border-yellow-500 bg-yellow-500/10";
    return "text-red-500 border-red-500 bg-red-500/10";
  };

  return (
    <div className="min-h-screen bg-black text-gray-200 p-8 font-mono">
      <div className="max-w-5xl mx-auto space-y-8">
        
        {/* Header */}
        <div className="flex items-center space-x-4 border-b border-gray-800 pb-6">
          <Shield className="w-12 h-12 text-blue-500" />
          <div>
            <h1 className="text-3xl font-bold text-white tracking-wider">AEGIS SCANNER</h1>
            <p className="text-gray-500">AI Threat Intelligence & Malware Detection</p>
          </div>
        </div>

        {/* Input Section */}
        <form onSubmit={handleScan} className="relative">
          <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
            <Search className="h-5 w-5 text-gray-500" />
          </div>
          <input
            type="url"
            required
            placeholder="Enter target URL (e.g., https://google.com)"
            className="w-full bg-gray-900 border border-gray-700 text-white rounded-lg pl-12 pr-4 py-4 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button
            type="submit"
            disabled={loading}
            className={`absolute right-2 top-2 bottom-2 px-6 rounded-md font-bold transition-colors ${
              loading ? "bg-gray-700 cursor-not-allowed" : "bg-blue-600 hover:bg-blue-500 text-white"
            }`}
          >
            {loading ? "SCANNING..." : "SCAN TARGET"}
          </button>
        </form>

        {/* Error Message */}
        {error && (
          <div className="p-4 bg-red-900/20 border border-red-500/50 rounded-lg flex items-center text-red-400">
            <XCircle className="w-5 h-5 mr-3" />
            {error}
          </div>
        )}

        {/* Active Result Section */}
        {result && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className={`p-6 rounded-xl border-2 flex items-center justify-between ${getStatusColor(result.final_verdict)}`}>
              <div className="flex items-center space-x-4">
                {result.final_verdict === "Safe" ? <CheckCircle className="w-10 h-10" /> : <AlertTriangle className="w-10 h-10" />}
                <div>
                  <h2 className="text-2xl font-bold uppercase">{result.final_verdict}</h2>
                  <p className="opacity-80">Risk Score: {result.risk_score}/100</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-xs uppercase tracking-widest opacity-60">Analysis Complete</p>
                <p className="font-mono">{new Date().toLocaleTimeString()}</p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Screenshot */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                <div className="p-3 border-b border-gray-800 bg-gray-950 flex items-center space-x-2">
                  <ImageIcon className="w-4 h-4 text-gray-500" />
                  <span className="text-xs font-bold text-gray-400">VISUAL EVIDENCE</span>
                </div>
                <div className="aspect-video bg-black relative flex items-center justify-center">
                  {result.sandbox_report?.screenshot_path ? (
                    <img src={result.sandbox_report.screenshot_path} alt="Scan Evidence" className="w-full h-full object-cover" />
                  ) : (
                    <p className="text-gray-600">No visual evidence captured</p>
                  )}
                </div>
              </div>

              {/* Logs */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col">
                <div className="p-3 border-b border-gray-800 bg-gray-950 flex items-center space-x-2">
                  <Terminal className="w-4 h-4 text-gray-500" />
                  <span className="text-xs font-bold text-gray-400">DETECTION LOG</span>
                </div>
                <div className="p-4 space-y-3 overflow-y-auto flex-1 font-mono text-sm">
                  {result.heuristic_results.map((h: any, i: number) => (
                    <div key={i} className={`flex justify-between items-start p-2 rounded ${h.is_triggered ? "bg-red-500/10 text-red-400" : "text-gray-500"}`}>
                      <span>{h.name}</span>
                      <span className={h.is_triggered ? "text-red-500 font-bold" : "text-green-600"}>{h.is_triggered ? "DETECTED" : "PASS"}</span>
                    </div>
                  ))}
                  <div className="border-t border-gray-800 pt-3 mt-3">
                    <div className="flex items-center space-x-2 mb-2">
                        <Activity className="w-3 h-3 text-blue-500" />
                        <span className="text-xs font-bold text-gray-400">EXTERNAL INTELLIGENCE</span>
                    </div>
                    {result.external_reports.map((r: any, i: number) => (
                        <div key={i} className="flex justify-between items-start text-xs mb-1">
                            <span className="text-gray-400">{r.source}</span>
                            <span className={r.data.malicious > 0 ? "text-red-500 font-bold" : "text-gray-500"}>
                                {r.status === 'ok' 
                                    ? `Malicious: ${r.data.malicious || 0} / Suspicious: ${r.data.suspicious || 0}` 
                                    : `Status: ${r.status}`}
                            </span>
                        </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* History Section */}
        <div className="border-t border-gray-800 pt-8">
          <div className="flex items-center space-x-2 mb-4">
            <Clock className="w-5 h-5 text-gray-500" />
            <h3 className="text-lg font-bold text-gray-300">RECENT SCANS</h3>
          </div>
          <div className="grid gap-4">
            {history.length === 0 ? (
                <p className="text-gray-600 italic">No scan history found.</p>
            ) : (
                history.map((scan: any) => (
                    <div key={scan.id} className="bg-gray-900/50 border border-gray-800 p-4 rounded-lg flex items-center justify-between hover:bg-gray-900 transition-colors">
                        <div className="flex items-center space-x-4 overflow-hidden">
                            <div className={`w-2 h-2 rounded-full ${scan.verdict === 'Safe' ? 'bg-green-500' : 'bg-red-500'}`} />
                            <div className="truncate">
                                <p className="text-white font-medium truncate max-w-md">{scan.url}</p>
                                <p className="text-xs text-gray-500">{new Date(scan.scanned_at).toLocaleString()}</p>
                            </div>
                        </div>
                        <div className="flex items-center space-x-6">
                            <span className={`text-sm font-bold ${scan.verdict === 'Safe' ? 'text-green-500' : 'text-red-500'}`}>{scan.verdict}</span>
                            <span className="text-xs text-gray-600 font-mono">Score: {scan.risk_score}</span>
                        </div>
                    </div>
                ))
            )}
          </div>
        </div>

      </div>
    </div>
  );
}

"use client";

import React, { useState, useEffect } from "react";
import axios from "axios";
import { Shield, AlertTriangle, CheckCircle, Search, Upload, Terminal, Image as ImageIcon, XCircle, Activity, Clock, FileText } from "lucide-react";

export default function ThreatScanner() {
  const [mode, setMode] = useState<"url" | "file">("url");
  const [input, setInput] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [error, setError] = useState("");

  // Use localhost for local testing
  const API_BASE_URL = "http://localhost:8000";

  useEffect(() => { fetchHistory(); }, []);

  const fetchHistory = async () => {
    try {
      const res = await axios.get(`${API_BASE_URL}/api/v1/history`);
      setHistory(res.data);
    } catch (err) { console.error("Failed to load history", err); }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    setError("");

    try {
      let response;
      if (mode === "url") {
        response = await axios.post(`${API_BASE_URL}/api/v1/scan/url`, { url: input, client_ip: "127.0.0.1" });
      } else {
        if (!selectedFile) return;
        const formData = new FormData();
        formData.append("file", selectedFile);
        response = await axios.post(`${API_BASE_URL}/api/v1/scan/file`, formData, {
            headers: { "Content-Type": "multipart/form-data" }
        });
      }
      setResult(response.data);
      fetchHistory();
    } catch (err) {
      setError("Scan Failed. Check Backend Connection.");
      console.error(err);
    } finally { setLoading(false); }
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
            <h1 className="text-3xl font-bold text-white tracking-wider">AEGIS SCANNER V3</h1>
            <p className="text-gray-500">Multi-Vector Threat Intelligence (URL & File)</p>
          </div>
        </div>

        {/* Mode Switcher */}
        <div className="flex space-x-4">
            <button onClick={() => setMode("url")} className={`flex items-center px-4 py-2 rounded border ${mode === "url" ? "bg-blue-600 border-blue-500 text-white" : "border-gray-700 text-gray-500"}`}>
                <Search className="w-4 h-4 mr-2"/> URL Scan
            </button>
            <button onClick={() => setMode("file")} className={`flex items-center px-4 py-2 rounded border ${mode === "file" ? "bg-blue-600 border-blue-500 text-white" : "border-gray-700 text-gray-500"}`}>
                <Upload className="w-4 h-4 mr-2"/> File Scan
            </button>
        </div>

        {/* Input Section */}
        <form onSubmit={handleScan} className="relative">
          {mode === "url" ? (
              <input type="url" required placeholder="Enter target URL..." className="w-full bg-gray-900 border border-gray-700 text-white rounded-lg p-4 focus:ring-2 focus:ring-blue-500 outline-none" value={input} onChange={(e) => setInput(e.target.value)} />
          ) : (
              <div className="w-full bg-gray-900 border border-dashed border-gray-700 rounded-lg p-8 text-center cursor-pointer hover:border-blue-500 transition-colors relative">
                  <input type="file" required className="absolute inset-0 w-full h-full opacity-0 cursor-pointer" onChange={(e) => setSelectedFile(e.target.files?.[0] || null)} />
                  <p className="text-gray-400">{selectedFile ? selectedFile.name : "Click to Upload or Drag & Drop File"}</p>
              </div>
          )}
          <button type="submit" disabled={loading} className="mt-4 w-full bg-blue-600 hover:bg-blue-500 text-white py-3 rounded font-bold disabled:bg-gray-700">
            {loading ? "ANALYZING..." : `SCAN ${mode.toUpperCase()}`}
          </button>
        </form>

        {/* Error Message */}
        {error && (<div className="p-4 bg-red-900/20 border border-red-500/50 rounded-lg flex items-center text-red-400"><XCircle className="w-5 h-5 mr-3" />{error}</div>)}

        {/* Results Section */}
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
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Info Box */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden p-6 flex items-center justify-center">
                  {mode === "url" && result.sandbox_report?.screenshot_path ? (
                      <img src={result.sandbox_report.screenshot_path} alt="Evidence" className="w-full h-full object-cover rounded" />
                  ) : (
                      <div className="text-center text-gray-500">
                          <FileText className="w-16 h-16 mx-auto mb-2 opacity-50" />
                          <p>File Analysis Complete</p>
                          <p className="text-xs">Hash verification performed</p>
                      </div>
                  )}
              </div>

              {/* Logs */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden p-4 space-y-3 text-sm font-mono">
                  <div className="flex items-center space-x-2 pb-2 border-b border-gray-800">
                      <Terminal className="w-4 h-4 text-gray-500" />
                      <span className="font-bold text-gray-400">INTELLIGENCE LOG</span>
                  </div>
                  {result.heuristic_results.map((h: any, i: number) => (
                    <div key={i} className="flex justify-between"><span className="text-gray-400">{h.name}</span><span className="text-gray-200">{h.description}</span></div>
                  ))}
                  {result.external_reports.map((r: any, i: number) => (
                    <div key={i} className="flex justify-between">
                        <span className="text-gray-400">{r.source}</span>
                        <span className={r.data.malicious > 0 ? "text-red-500 font-bold" : "text-gray-500"}>
                            {r.status === 'ok' ? `Malicious: ${r.data.malicious}` : r.status}
                        </span>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        )}
        
        {/* History */}
        <div className="border-t border-gray-800 pt-8">
            <h3 className="text-lg font-bold text-gray-300 mb-4 flex items-center"><Clock className="w-5 h-5 mr-2"/> RECENT SCANS</h3>
            <div className="grid gap-4">
                {history.map((scan: any) => (
                    <div key={scan.id} className="bg-gray-900/50 border border-gray-800 p-4 rounded-lg flex justify-between">
                        <div className="truncate max-w-md text-gray-300">{scan.url}</div>
                        <div className={`font-bold ${scan.verdict === 'Safe' ? 'text-green-500' : 'text-red-500'}`}>{scan.verdict}</div>
                    </div>
                ))}
            </div>
        </div>
      </div>
    </div>
  );
}

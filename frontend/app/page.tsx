"use client";

import React, { useState, useEffect } from "react";
import axios from "axios";
import { 
  Shield, Search, Upload, Terminal, Image as ImageIcon, 
  XCircle, Activity, Clock, FileText, Plus, Menu, X 
} from "lucide-react";

export default function ThreatScanner() {
  const [mode, setMode] = useState<"url" | "file">("url");
  const [input, setInput] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [error, setError] = useState("");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // LIVE BACKEND URL
  const API_BASE_URL = "https://aegis-scanner.onrender.com";

  useEffect(() => { fetchHistory(); }, []);

  const fetchHistory = async () => {
    try {
      const res = await axios.get(`${API_BASE_URL}/api/v1/history`);
      setHistory(res.data);
    } catch (err) { console.error("Failed to load history", err); }
  };

  const startNewScan = () => {
    setResult(null);
    setInput("");
    setSelectedFile(null);
    setError("");
    setMobileMenuOpen(false);
  };

  const loadHistoryItem = (scan: any) => {
    // Reconstruct the 'result' object from the history item
    setResult({
      final_verdict: scan.verdict,
      risk_score: scan.risk_score,
      sandbox_report: { screenshot_path: scan.screenshot_path, status: 'ok' },
      heuristic_results: scan.heuristic_data || [],
      external_reports: scan.external_data || []
    });
    setMobileMenuOpen(false);
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
      fetchHistory(); // Refresh sidebar
    } catch (err) {
      setError("Scan Failed. Backend may be waking up (Free Tier takes 50s).");
      console.error(err);
    } finally { setLoading(false); }
  };

  const getStatusColor = (verdict: string) => {
    if (verdict === "Safe") return "text-green-500 border-green-500 bg-green-500/10";
    if (verdict === "Suspicious") return "text-yellow-500 border-yellow-500 bg-yellow-500/10";
    return "text-red-500 border-red-500 bg-red-500/10";
  };

  return (
    <div className="flex h-screen bg-black text-gray-200 font-mono overflow-hidden">
      
      {/* SIDEBAR (Desktop: Always visible, Mobile: Toggle) */}
      <div className={`fixed inset-0 z-50 bg-black/90 md:relative md:flex md:w-72 md:flex-col md:border-r md:border-gray-800 transition-transform duration-300 ${mobileMenuOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"}`}>
        <div className="p-4 border-b border-gray-800 flex items-center justify-between">
          <div className="flex items-center space-x-2 text-blue-500 font-bold tracking-wider">
            <Shield className="w-6 h-6" />
            <span>AEGIS V3</span>
          </div>
          {/* Close button for mobile */}
          <button onClick={() => setMobileMenuOpen(false)} className="md:hidden text-gray-400">
            <X className="w-6 h-6" />
          </button>
        </div>

        <div className="p-4">
          <button onClick={startNewScan} className="w-full flex items-center justify-center space-x-2 bg-blue-600 hover:bg-blue-500 text-white py-3 rounded-lg font-bold transition-colors">
            <Plus className="w-4 h-4" />
            <span>NEW SCAN</span>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <div className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">Recent History</div>
          {history.length === 0 && <p className="text-gray-600 text-sm italic">No scans yet.</p>}
          {history.map((scan) => (
            <div 
              key={scan.id} 
              onClick={() => loadHistoryItem(scan)}
              className="p-3 rounded-lg border border-gray-800 bg-gray-900/50 hover:bg-gray-800 cursor-pointer transition-all group"
            >
              <div className="flex items-center justify-between mb-1">
                <span className={`text-xs font-bold ${scan.verdict === 'Safe' ? 'text-green-500' : 'text-red-500'}`}>{scan.verdict}</span>
                <span className="text-[10px] text-gray-600">{new Date(scan.scanned_at).toLocaleDateString()}</span>
              </div>
              <div className="text-sm text-gray-300 truncate group-hover:text-white">{scan.url.replace("File: ", "")}</div>
            </div>
          ))}
        </div>
      </div>

      {/* MAIN CONTENT */}
      <div className="flex-1 flex flex-col h-full overflow-hidden relative">
        
        {/* Mobile Header */}
        <div className="md:hidden p-4 border-b border-gray-800 flex items-center justify-between bg-black">
          <div className="flex items-center space-x-2 text-blue-500 font-bold">
            <Shield className="w-5 h-5" />
            <span>AEGIS</span>
          </div>
          <button onClick={() => setMobileMenuOpen(true)} className="text-gray-400">
            <Menu className="w-6 h-6" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 md:p-8 scrollbar-hide">
          <div className="max-w-4xl mx-auto">
            
            {!result ? (
              // --- INPUT VIEW ---
              <div className="animate-in fade-in zoom-in duration-300 mt-10 md:mt-20">
                <div className="text-center mb-12">
                  <h1 className="text-4xl md:text-5xl font-bold text-white mb-4 tracking-tight">Threat Intelligence</h1>
                  <p className="text-gray-500 text-lg">AI-Powered Malware & Phishing Detection</p>
                </div>

                <div className="flex justify-center space-x-4 mb-6">
                    <button onClick={() => setMode("url")} className={`flex items-center px-6 py-2 rounded-full border transition-all ${mode === "url" ? "bg-blue-600 border-blue-500 text-white shadow-lg shadow-blue-900/20" : "border-gray-700 text-gray-500 hover:border-gray-500"}`}>
                        <Search className="w-4 h-4 mr-2"/> URL
                    </button>
                    <button onClick={() => setMode("file")} className={`flex items-center px-6 py-2 rounded-full border transition-all ${mode === "file" ? "bg-blue-600 border-blue-500 text-white shadow-lg shadow-blue-900/20" : "border-gray-700 text-gray-500 hover:border-gray-500"}`}>
                        <Upload className="w-4 h-4 mr-2"/> File
                    </button>
                </div>

                <form onSubmit={handleScan} className="relative max-w-2xl mx-auto">
                  {mode === "url" ? (
                      <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none"><Search className="h-5 w-5 text-gray-500" /></div>
                        <input type="url" required placeholder="Paste suspicious link here..." className="w-full bg-gray-900/50 border border-gray-700 text-white rounded-xl pl-12 pr-4 py-5 text-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all placeholder-gray-600" value={input} onChange={(e) => setInput(e.target.value)} />
                      </div>
                  ) : (
                      <div className="w-full bg-gray-900/50 border-2 border-dashed border-gray-700 rounded-xl p-10 text-center cursor-pointer hover:border-blue-500 hover:bg-gray-900 transition-all relative group">
                          <input type="file" required className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10" onChange={(e) => setSelectedFile(e.target.files?.[0] || null)} />
                          <div className="flex flex-col items-center">
                            <div className="p-4 bg-gray-800 rounded-full mb-4 group-hover:scale-110 transition-transform">
                              <Upload className="w-8 h-8 text-blue-400" />
                            </div>
                            <p className="text-gray-300 font-medium">{selectedFile ? selectedFile.name : "Click to upload file"}</p>
                            <p className="text-xs text-gray-500 mt-2">Supports PDF, EXE, ZIP</p>
                          </div>
                      </div>
                  )}
                  
                  <button type="submit" disabled={loading} className="mt-6 w-full bg-white text-black hover:bg-gray-200 py-4 rounded-xl font-bold text-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors shadow-lg">
                    {loading ? "ANALYZING THREAT..." : `SCAN TARGET`}
                  </button>
                </form>

                {error && (<div className="mt-6 p-4 bg-red-900/20 border border-red-500/50 rounded-lg flex items-center text-red-400 max-w-2xl mx-auto"><XCircle className="w-5 h-5 mr-3 flex-shrink-0" />{error}</div>)}
              </div>
            ) : (
              // --- RESULT VIEW ---
              <div className="space-y-6 animate-in fade-in slide-in-from-bottom-8 duration-500">
                
                <div className={`p-8 rounded-2xl border-2 flex flex-col md:flex-row items-center justify-between ${getStatusColor(result.final_verdict)}`}>
                  <div className="flex items-center space-x-6">
                    {result.final_verdict === "Safe" ? <CheckCircle className="w-16 h-16" /> : <AlertTriangle className="w-16 h-16" />}
                    <div className="text-center md:text-left">
                      <h2 className="text-3xl font-black uppercase tracking-tight">{result.final_verdict}</h2>
                      <p className="opacity-90 text-lg">Risk Score: <span className="font-mono font-bold">{result.risk_score}/100</span></p>
                    </div>
                  </div>
                  <div className="mt-4 md:mt-0 text-center md:text-right">
                    <div className="inline-flex items-center bg-black/20 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-widest mb-1">
                      <Activity className="w-3 h-3 mr-2" /> Analysis Complete
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Info Box */}
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden flex flex-col h-full">
                      <div className="p-4 border-b border-gray-800 bg-gray-950 flex items-center space-x-2">
                          <ImageIcon className="w-4 h-4 text-gray-500" />
                          <span className="text-xs font-bold text-gray-400 uppercase">Target Evidence</span>
                      </div>
                      <div className="flex-1 bg-black relative flex items-center justify-center p-4 min-h-[200px]">
                          {result.sandbox_report?.screenshot_path ? (
                              <img src={result.sandbox_report.screenshot_path} alt="Evidence" className="w-full h-full object-contain rounded border border-gray-800" />
                          ) : (
                              <div className="text-center text-gray-600">
                                  <FileText className="w-12 h-12 mx-auto mb-3 opacity-30" />
                                  <p>No visual evidence available</p>
                                  <p className="text-xs opacity-60">File scan or Lite mode active</p>
                              </div>
                          )}
                      </div>
                  </div>

                  {/* Logs */}
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden p-5 space-y-4 text-sm font-mono">
                      <div className="flex items-center space-x-2 pb-3 border-b border-gray-800">
                          <Terminal className="w-4 h-4 text-gray-500" />
                          <span className="font-bold text-gray-400 uppercase">Intelligence Log</span>
                      </div>
                      
                      <div className="space-y-3 max-h-[300px] overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-gray-700">
                        {result.heuristic_results?.map((h: any, i: number) => (
                          <div key={i} className="flex justify-between items-start border-b border-gray-800/50 pb-2 last:border-0">
                            <span className="text-gray-400">{h.name}</span>
                            <span className={`text-right max-w-[60%] ${h.is_triggered ? "text-red-400 font-bold" : "text-gray-600"}`}>{h.description || (h.is_triggered ? "DETECTED" : "PASS")}</span>
                          </div>
                        ))}
                        
                        <div className="pt-2">
                          <div className="text-xs font-bold text-gray-500 mb-2 uppercase">External Sources</div>
                          {result.external_reports?.map((r: any, i: number) => (
                            <div key={i} className="flex justify-between items-center mb-1">
                                <span className="text-gray-300">{r.source}</span>
                                <span className={r.data.malicious > 0 ? "text-red-500 font-bold" : "text-gray-500"}>
                                    {r.status === 'ok' ? `Malicious: ${r.data.malicious}` : r.status}
                                </span>
                            </div>
                          ))}
                        </div>
                      </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

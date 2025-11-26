"use client";

import React, { useState, useEffect } from "react";
import axios from "axios";
import { 
  Shield, CheckCircle, AlertTriangle, Search, Upload, Terminal, 
  Image as ImageIcon, XCircle, Activity, Clock, FileText, Plus, Menu, X, ChevronRight 
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
    // Reconstruct result from history
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
      setError("Scan Failed. Backend may be sleeping (Free Tier). Try again in 30s.");
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
      
      {/* SIDEBAR */}
      <div className={`fixed inset-0 z-50 bg-gray-950/95 backdrop-blur md:relative md:flex md:w-80 md:flex-col md:border-r md:border-gray-800 transition-transform duration-300 ${mobileMenuOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"}`}>
        <div className="p-6 border-b border-gray-800 flex items-center justify-between">
          <div className="flex items-center space-x-3 text-blue-500 font-bold tracking-wider">
            <Shield className="w-6 h-6" />
            <span className="text-lg">AEGIS V3</span>
          </div>
          <button onClick={() => setMobileMenuOpen(false)} className="md:hidden text-gray-400 hover:text-white">
            <X className="w-6 h-6" />
          </button>
        </div>

        <div className="p-6">
          <button onClick={startNewScan} className="w-full flex items-center justify-center space-x-2 bg-blue-600 hover:bg-blue-500 text-white py-3 rounded-lg font-bold transition-all shadow-lg shadow-blue-900/20 active:scale-95">
            <Plus className="w-5 h-5" />
            <span>NEW SCAN</span>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-4 pb-4 space-y-2">
          <div className="px-2 text-xs font-bold text-gray-500 uppercase tracking-widest mb-3 mt-2">Recent Investigations</div>
          {history.length === 0 && <p className="px-2 text-gray-600 text-sm italic">No scan history found.</p>}
          {history.map((scan) => (
            <button 
              key={scan.id} 
              onClick={() => loadHistoryItem(scan)}
              className="w-full text-left p-3 rounded-lg border border-transparent hover:border-gray-700 hover:bg-gray-900 transition-all group relative overflow-hidden"
            >
              <div className="flex items-center justify-between mb-1">
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${scan.verdict === 'Safe' ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}`}>{scan.verdict}</span>
                <span className="text-[10px] text-gray-600">{new Date(scan.scanned_at).toLocaleDateString()}</span>
              </div>
              <div className="text-sm text-gray-400 truncate font-medium group-hover:text-white transition-colors">
                {scan.url.replace("File: ", "")}
              </div>
              {/* Hover Arrow */}
              <ChevronRight className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-600 opacity-0 group-hover:opacity-100 transition-opacity" />
            </button>
          ))}
        </div>
      </div>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col h-full overflow-hidden relative bg-black">
        
        {/* Mobile Header */}
        <div className="md:hidden p-4 border-b border-gray-800 flex items-center justify-between bg-gray-950">
          <div className="flex items-center space-x-2 text-blue-500 font-bold">
            <Shield className="w-5 h-5" />
            <span>AEGIS SCANNER</span>
          </div>
          <button onClick={() => setMobileMenuOpen(true)} className="text-gray-400">
            <Menu className="w-6 h-6" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 md:p-10 scrollbar-thin scrollbar-thumb-gray-800">
          <div className="max-w-5xl mx-auto">
            
            {!result ? (
              // --- EMPTY STATE / INPUT VIEW ---
              <div className="animate-in fade-in zoom-in duration-500 mt-10 md:mt-20 flex flex-col items-center">
                <div className="w-20 h-20 bg-blue-500/10 rounded-full flex items-center justify-center mb-8 border border-blue-500/20 animate-pulse">
                    <Shield className="w-10 h-10 text-blue-500" />
                </div>
                <h1 className="text-3xl md:text-5xl font-bold text-white mb-4 tracking-tight text-center">Threat Intelligence Platform</h1>
                <p className="text-gray-500 text-lg text-center max-w-xl mb-12">
                  Advanced malware analysis, phishing detection, and deep file inspection powered by AI.
                </p>

                {/* Toggle Switch */}
                <div className="bg-gray-900 p-1 rounded-lg inline-flex mb-8 border border-gray-800">
                    <button onClick={() => setMode("url")} className={`px-6 py-2 rounded-md text-sm font-bold transition-all ${mode === "url" ? "bg-gray-800 text-white shadow" : "text-gray-500 hover:text-gray-300"}`}>URL Scan</button>
                    <button onClick={() => setMode("file")} className={`px-6 py-2 rounded-md text-sm font-bold transition-all ${mode === "file" ? "bg-gray-800 text-white shadow" : "text-gray-500 hover:text-gray-300"}`}>File Analysis</button>
                </div>

                <form onSubmit={handleScan} className="w-full max-w-2xl relative">
                  {mode === "url" ? (
                      <div className="relative group">
                        <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none"><Search className="h-5 w-5 text-gray-500 group-focus-within:text-blue-500 transition-colors" /></div>
                        <input type="url" required placeholder="Enter suspicious URL (e.g., http://malware.site)..." className="w-full bg-gray-900/50 border border-gray-800 text-white rounded-2xl pl-14 pr-4 py-6 text-lg focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 outline-none transition-all placeholder-gray-600 shadow-2xl" value={input} onChange={(e) => setInput(e.target.value)} />
                      </div>
                  ) : (
                      <div className="w-full bg-gray-900/30 border-2 border-dashed border-gray-800 rounded-2xl p-12 text-center cursor-pointer hover:border-blue-500/50 hover:bg-gray-900/50 transition-all relative group">
                          <input type="file" required className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10" onChange={(e) => setSelectedFile(e.target.files?.[0] || null)} />
                          <div className="flex flex-col items-center pointer-events-none">
                            <div className="p-4 bg-gray-800 rounded-full mb-4 group-hover:scale-110 transition-transform border border-gray-700 group-hover:border-blue-500/30">
                              <Upload className="w-8 h-8 text-gray-400 group-hover:text-blue-400 transition-colors" />
                            </div>
                            <p className="text-gray-300 font-medium text-lg">{selectedFile ? selectedFile.name : "Drop file to scan"}</p>
                            <p className="text-sm text-gray-500 mt-2">PDF, EXE, ZIP, DOCX supported</p>
                          </div>
                      </div>
                  )}
                  
                  <button type="submit" disabled={loading} className="mt-8 w-full bg-blue-600 hover:bg-blue-500 text-white py-4 rounded-xl font-bold text-lg tracking-wide disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-blue-900/20 hover:shadow-blue-900/40">
                    {loading ? "INITIALIZING SCAN..." : "START ANALYSIS"}
                  </button>
                </form>

                {error && (<div className="mt-6 p-4 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center text-red-400 max-w-2xl w-full"><XCircle className="w-5 h-5 mr-3 flex-shrink-0" />{error}</div>)}
              </div>
            ) : (
              // --- RESULT VIEW ---
              <div className="space-y-6 animate-in fade-in slide-in-from-bottom-8 duration-500">
                
                {/* Verdict Banner */}
                <div className={`p-8 rounded-2xl border flex flex-col md:flex-row items-center justify-between relative overflow-hidden ${getStatusColor(result.final_verdict)}`}>
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/5 to-transparent opacity-20" />
                  <div className="flex items-center space-x-6 relative z-10">
                    {result.final_verdict === "Safe" ? <CheckCircle className="w-16 h-16" /> : <AlertTriangle className="w-16 h-16 animate-pulse" />}
                    <div className="text-center md:text-left">
                      <h2 className="text-4xl font-black uppercase tracking-tight">{result.final_verdict}</h2>
                      <p className="opacity-90 text-lg mt-1">Risk Score: <span className="font-mono font-bold text-xl">{result.risk_score}/100</span></p>
                    </div>
                  </div>
                  <div className="mt-6 md:mt-0 text-center md:text-right relative z-10">
                    <div className="inline-flex items-center bg-black/30 backdrop-blur px-4 py-2 rounded-full text-xs font-bold uppercase tracking-widest border border-white/10">
                      <Activity className="w-3 h-3 mr-2" /> Analysis Complete
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Evidence Box */}
                  <div className="bg-gray-900/50 border border-gray-800 rounded-2xl overflow-hidden flex flex-col h-full">
                      <div className="p-4 border-b border-gray-800 bg-gray-900/80 flex items-center space-x-2">
                          <ImageIcon className="w-4 h-4 text-gray-500" />
                          <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Target Evidence</span>
                      </div>
                      <div className="flex-1 bg-black/50 relative flex items-center justify-center p-6 min-h-[250px]">
                          {result.sandbox_report?.screenshot_path ? (
                              <img src={result.sandbox_report.screenshot_path} alt="Evidence" className="w-full h-full object-contain rounded border border-gray-800 shadow-2xl" />
                          ) : (
                              <div className="text-center text-gray-600">
                                  <FileText className="w-16 h-16 mx-auto mb-4 opacity-20" />
                                  <p className="font-medium">No visual evidence available</p>
                                  <p className="text-xs opacity-60 mt-1">File scan or Lite mode active</p>
                              </div>
                          )}
                      </div>
                  </div>

                  {/* Intelligence Logs */}
                  <div className="bg-gray-900/50 border border-gray-800 rounded-2xl overflow-hidden flex flex-col">
                      <div className="p-4 border-b border-gray-800 bg-gray-900/80 flex items-center space-x-2">
                          <Terminal className="w-4 h-4 text-gray-500" />
                          <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Intelligence Log</span>
                      </div>
                      
                      <div className="p-5 space-y-4 overflow-y-auto max-h-[400px] text-sm font-mono scrollbar-thin scrollbar-thumb-gray-700">
                        {result.heuristic_results?.map((h: any, i: number) => (
                          <div key={i} className="flex justify-between items-start border-b border-gray-800/50 pb-3 last:border-0">
                            <span className="text-gray-400 font-medium">{h.name}</span>
                            <span className={`text-right max-w-[60%] ${h.is_triggered ? "text-red-400 font-bold" : "text-green-500"}`}>{h.description || (h.is_triggered ? "DETECTED" : "PASS")}</span>
                          </div>
                        ))}
                        
                        <div className="pt-2 mt-2 border-t border-gray-800">
                          <div className="text-xs font-bold text-gray-500 mb-3 uppercase tracking-wider">External Sources</div>
                          {result.external_reports?.map((r: any, i: number) => (
                            <div key={i} className="flex justify-between items-center mb-2 p-2 rounded bg-black/20">
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

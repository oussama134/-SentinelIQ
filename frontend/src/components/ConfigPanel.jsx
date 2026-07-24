import React, { useState, useEffect } from 'react';
import { Settings, Sliders, Info, CheckCircle, AlertTriangle, ArrowLeft } from 'lucide-react';
import { API as API_BASE, apiFetch } from '../api';

export default function ConfigPanel() {
  const [threshold, setThreshold] = useState(0.75);
  const [diagnostic, setDiagnostic] = useState(null);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [iface, setIface] = useState('');
  const [ifaceLoading, setIfaceLoading] = useState(false);

  useEffect(() => {
    fetchDiagnostic();
  }, []);

  const fetchDiagnostic = async () => {
    try {
      const response = await apiFetch(`${API_BASE}/api/diagnostic`);
      if (!response.ok) throw new Error('Failed to fetch diagnostic');
      const data = await response.json();
      setDiagnostic(data);
      
      // Set current threshold from diagnostic if available
      if (data.model_info?.threshold) {
        setThreshold(data.model_info.threshold);
      }
      if (data.interface) {
        setIface(data.interface);
      }
    } catch (error) {
      console.error('Error fetching diagnostic:', error);
      setStatus({ type: 'error', message: 'Failed to connect to backend' });
    }
  };

  const updateThreshold = async (newThreshold) => {
    setLoading(true);
    try {
      const response = await apiFetch(`${API_BASE}/api/set-threshold?threshold=${newThreshold}`, {
        method: 'POST'
      });
      const data = await response.json();
      
      if (data.status === 'success') {
        setStatus({ type: 'success', message: `Threshold updated to ${newThreshold.toFixed(2)}` });
        setThreshold(newThreshold);
      } else {
        setStatus({ type: 'error', message: data.error || 'Failed to update threshold' });
      }
      
      setTimeout(() => setStatus(null), 3000);
    } catch (error) {
      setStatus({ type: 'error', message: 'Network error' });
      setTimeout(() => setStatus(null), 3000);
    }
    setLoading(false);
  };

  const updateInterface = async (newIface) => {
    if (!newIface.trim()) return;
    setIfaceLoading(true);
    try {
      const response = await apiFetch(`${API_BASE}/api/set-interface?interface=${encodeURIComponent(newIface.trim())}`, {
        method: 'POST'
      });
      const data = await response.json();
      if (data.status === 'success') {
        setStatus({ type: 'success', message: `Capture interface set to "${data.interface}"` });
        setIface(data.interface);
      } else {
        setStatus({ type: 'error', message: data.error || 'Failed to update interface' });
      }
      setTimeout(() => setStatus(null), 3000);
    } catch {
      setStatus({ type: 'error', message: 'Network error' });
      setTimeout(() => setStatus(null), 3000);
    }
    setIfaceLoading(false);
  };

  const getThresholdInfo = (value) => {
    if (value >= 0.85) return {
      label: 'Very Strict',
      color: '#3b82f6',
      description: 'Minimal false positives, may miss some attacks'
    };
    if (value >= 0.75) return {
      label: 'Strict',
      color: '#10b981',
      description: 'Balanced - Recommended for production'
    };
    if (value >= 0.65) return {
      label: 'Balanced',
      color: '#f59e0b',
      description: 'Good detection, moderate false positives'
    };
    if (value >= 0.50) return {
      label: 'Permissive',
      color: '#ef4444',
      description: 'Maximum detection, more false positives'
    };
    return {
      label: 'Very Permissive',
      color: '#dc2626',
      description: 'High false positive rate - Not recommended'
    };
  };

  const thresholdInfo = getThresholdInfo(threshold);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 p-6">
      {/* Header */}
      <div className="mb-8">
        <button
          onClick={() => window.location.href = '/'}
          className="mb-4 text-white flex items-center gap-2 hover:text-blue-400 transition-colors"
        >
          <ArrowLeft size={20} />
          Back to Dashboard
        </button>
        <div className="flex items-center gap-3 mb-2">
          <Settings className="text-white" size={32} />
          <h1 className="text-4xl font-bold text-white">IDS Configuration</h1>
        </div>
        <p className="text-gray-400">Adjust detection sensitivity and view system status</p>
      </div>

      {/* Status Alert */}
      {status && (
        <div className={`mb-6 p-4 rounded-lg flex items-center gap-3 ${
          status.type === 'success' ? 'bg-green-500/20 border border-green-500' : 'bg-red-500/20 border border-red-500'
        }`}>
          {status.type === 'success' ? (
            <CheckCircle className="text-green-500" size={24} />
          ) : (
            <AlertTriangle className="text-red-500" size={24} />
          )}
          <span className="text-white">{status.message}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Capture Interface Control — always visible, independent of diagnostic */}
        <div className="bg-white rounded-lg shadow-lg p-6 lg:col-span-2">
          <div className="flex items-center gap-2 mb-4">
            <Info className="text-purple-600" size={24} />
            <h2 className="text-xl font-bold text-gray-800">Capture Interface</h2>
          </div>
          <div className="flex gap-3 items-end">
            <div className="flex-1">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Interface number or name
              </label>
              <input
                type="text"
                value={iface}
                onChange={(e) => setIface(e.target.value)}
                placeholder="e.g. 4 or Ethernet 2"
                className="w-full border border-gray-300 rounded px-3 py-2 text-sm text-gray-800 focus:outline-none focus:border-purple-500"
              />
              <p className="text-xs text-gray-400 mt-1">
                Run <code className="bg-gray-100 px-1 rounded">tshark -D</code> in a terminal to list available interfaces
              </p>
            </div>
            <button
              onClick={() => updateInterface(iface)}
              disabled={ifaceLoading}
              className="bg-purple-600 hover:bg-purple-700 text-white font-semibold px-6 py-2 rounded-lg transition-colors disabled:opacity-50"
            >
              {ifaceLoading ? 'Applying...' : 'Apply'}
            </button>
          </div>
        </div>

        {/* Confidence Threshold Control */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center gap-2 mb-4">
            <Sliders className="text-blue-600" size={24} />
            <h2 className="text-xl font-bold text-gray-800">Detection Sensitivity</h2>
          </div>

          <div className="space-y-6">
            {/* Threshold Slider */}
            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="text-sm font-medium text-gray-700">
                  Confidence Threshold
                </label>
                <span className="text-2xl font-bold" style={{ color: thresholdInfo.color }}>
                  {threshold.toFixed(2)}
                </span>
              </div>
              
              <input
                type="range"
                min="0.5"
                max="0.95"
                step="0.05"
                value={threshold}
                onChange={(e) => {
                  const newValue = parseFloat(e.target.value);
                  setThreshold(newValue);
                }}
                className="w-full h-3 bg-gray-200 rounded-lg appearance-none cursor-pointer"
                style={{
                  background: `linear-gradient(to right, #dc2626 0%, #f59e0b 25%, #10b981 50%, #3b82f6 100%)`
                }}
              />
              
              <div className="flex justify-between text-xs text-gray-500 mt-1">
                <span>0.50</span>
                <span>0.65</span>
                <span>0.75</span>
                <span>0.85</span>
                <span>0.95</span>
              </div>
            </div>

            {/* Current Level Info */}
            <div 
              className="p-4 rounded-lg border-l-4"
              style={{ 
                backgroundColor: `${thresholdInfo.color}10`,
                borderColor: thresholdInfo.color
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <div 
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: thresholdInfo.color }}
                ></div>
                <span className="font-semibold text-gray-800">{thresholdInfo.label}</span>
              </div>
              <p className="text-sm text-gray-600">{thresholdInfo.description}</p>
            </div>

            {/* Apply Button */}
            <button
              onClick={() => updateThreshold(threshold)}
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-6 rounded-lg transition-all shadow-lg hover:shadow-xl disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  Applying...
                </span>
              ) : (
                'Apply Changes'
              )}
            </button>

            {/* Explanation */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <div className="flex items-start gap-2">
                <Info className="text-blue-600 flex-shrink-0 mt-0.5" size={18} />
                <div className="text-sm text-gray-700">
                  <p className="font-semibold mb-1">How it works:</p>
                  <p>Higher threshold = Only report attacks with high confidence (fewer false alarms)</p>
                  <p>Lower threshold = Report more potential attacks (may include normal traffic)</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* System Diagnostic */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold text-gray-800">System Status</h2>
            <button
              onClick={fetchDiagnostic}
              className="text-blue-600 hover:text-blue-700 text-sm font-medium"
            >
              Refresh
            </button>
          </div>

          {diagnostic ? (
            <div className="space-y-4">
              {/* Model Files */}
              {diagnostic.model_files && (
                <div>
                  <h3 className="font-semibold text-gray-700 mb-2">Model Files</h3>
                  <div className="space-y-2">
                    {Object.entries(diagnostic.model_files).map(([file, exists]) => (
                      <div key={file} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                        <span className="text-sm text-gray-600 capitalize">{file}</span>
                        {exists ? (
                          <CheckCircle className="text-green-500" size={18} />
                        ) : (
                          <AlertTriangle className="text-red-500" size={18} />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Model Info */}
              {diagnostic.model_info && (
                <div>
                  <h3 className="font-semibold text-gray-700 mb-2">Model Information</h3>
                  <div className="bg-gray-50 rounded p-3 space-y-1 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-600">Features:</span>
                      <span className="font-medium">{diagnostic.model_info.expected_features || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Attack Types:</span>
                      <span className="font-medium">{diagnostic.model_info.num_classes || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600">Current Threshold:</span>
                      <span className="font-medium">{diagnostic.model_info.threshold?.toFixed(2) || 'N/A'}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Capture Stats */}
              {diagnostic.capture_stats && (
                <div>
                  <h3 className="font-semibold text-gray-700 mb-2">Capture Statistics</h3>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="bg-blue-50 rounded p-3">
                      <div className="text-2xl font-bold text-blue-600">
                        {diagnostic.capture_stats.total_captures || 0}
                      </div>
                      <div className="text-xs text-gray-600">Total Captures</div>
                    </div>
                    <div className="bg-green-50 rounded p-3">
                      <div className="text-2xl font-bold text-green-600">
                        {diagnostic.capture_stats.total_flows || 0}
                      </div>
                      <div className="text-xs text-gray-600">Flows Analyzed</div>
                    </div>
                    <div className="bg-purple-50 rounded p-3">
                      <div className="text-2xl font-bold text-purple-600">
                        {diagnostic.capture_stats.total_predictions || 0}
                      </div>
                      <div className="text-xs text-gray-600">Predictions</div>
                    </div>
                    <div className="bg-red-50 rounded p-3">
                      <div className="text-2xl font-bold text-red-600">
                        {diagnostic.capture_stats.detection_rate?.malicious || 0}
                      </div>
                      <div className="text-xs text-gray-600">Threats Detected</div>
                    </div>
                  </div>
                </div>
              )}

              {/* Tshark Status */}
              <div className="flex items-center justify-between p-3 bg-gray-50 rounded">
                <span className="text-sm text-gray-600">Tshark Available:</span>
                {diagnostic.tshark_available ? (
                  <span className="text-green-600 font-medium flex items-center gap-1">
                    <CheckCircle size={16} />
                    Active
                  </span>
                ) : (
                  <span className="text-red-600 font-medium flex items-center gap-1">
                    <AlertTriangle size={16} />
                    Not Found
                  </span>
                )}
              </div>

            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
              Loading diagnostic data...
            </div>
          )}
        </div>
      </div>

      {/* Recommended Settings */}
      <div className="mt-6 bg-white rounded-lg shadow-lg p-6">
        <h2 className="text-xl font-bold text-gray-800 mb-4">Recommended Settings by Scenario</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="border-2 border-blue-200 rounded-lg p-4 hover:border-blue-400 transition-colors cursor-pointer"
               onClick={() => updateThreshold(0.75)}>
            <div className="flex items-center gap-2 mb-2">
              <div className="w-3 h-3 rounded-full bg-blue-500"></div>
              <h3 className="font-semibold text-gray-800">Production (0.75)</h3>
            </div>
            <p className="text-sm text-gray-600">Balanced detection with acceptable false positive rate. Recommended for most use cases.</p>
          </div>
          
          <div className="border-2 border-green-200 rounded-lg p-4 hover:border-green-400 transition-colors cursor-pointer"
               onClick={() => updateThreshold(0.85)}>
            <div className="flex items-center gap-2 mb-2">
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
              <h3 className="font-semibold text-gray-800">High Security (0.85)</h3>
            </div>
            <p className="text-sm text-gray-600">Strict filtering, only high-confidence threats. Use when false positives are costly.</p>
          </div>
          
          <div className="border-2 border-orange-200 rounded-lg p-4 hover:border-orange-400 transition-colors cursor-pointer"
               onClick={() => updateThreshold(0.65)}>
            <div className="flex items-center gap-2 mb-2">
              <div className="w-3 h-3 rounded-full bg-orange-500"></div>
              <h3 className="font-semibold text-gray-800">Testing/Dev (0.65)</h3>
            </div>
            <p className="text-sm text-gray-600">More permissive detection for testing. Expect more false positives from normal traffic.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
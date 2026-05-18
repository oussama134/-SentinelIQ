import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts';
import { AlertTriangle, Shield, Activity, TrendingUp, RefreshCw, Settings, Download, Filter, X, Calendar, Search } from 'lucide-react';
import { API as API_BASE, apiFetch } from '../api';

const ATTACK_COLORS = {
  'BENIGN': '#10b981',
  'DoS GoldenEye': '#ef4444',
  'DoS Slowhttptest': '#dc2626',
  'DoS Hulk': '#f97316',
  'DDoS': '#dc2626',
  'PortScan': '#f59e0b',
  'Bot': '#8b5cf6',
  'Infiltration': '#ec4899',
  'Web Attack': '#06b6d4',
  'default': '#6b7280'
};

export default function AdvancedDashboard() {
  const [data, setData] = useState({ predictions: [], alerts: [] });
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [statsDays, setStatsDays] = useState(7);
  
  // Helper function to get period label
  const getPeriodLabel = (days) => {
    const numDays = parseFloat(days);
    if (numDays < 0.01) {  // Less than ~15 minutes
      return `${Math.round(numDays * 24 * 60)} minutes`;
    } else if (numDays < 0.5) {  // Less than 12 hours
      return `${(numDays * 24).toFixed(1)} hours`;
    } else if (numDays === 1) {
      return "24 hours";
    } else {
      return `${Math.round(numDays)} days`;
    }
  };
  
  // Filters
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState({
    label: '',
    src_ip: '',
    dst_ip: '',
    min_score: '',
    max_score: '',
    severity: '',
    start_date: '',
    end_date: ''
  });

  const fetchDashboard = async () => {
    try {
      const response = await apiFetch(`${API_BASE}/api/dashboard`);
      const result = await response.json();
      setData(result);
      setLastUpdate(new Date());
      setLoading(false);
    } catch (error) {
      console.error('Error fetching dashboard:', error);
      setLoading(false);
    }
  };

  const fetchStats = async (days = statsDays) => {
    try {
      const response = await apiFetch(`${API_BASE}/api/stats?days=${days}`);
      const result = await response.json();
      setStats(result);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const fetchFilteredAlerts = async () => {
    try {
      const params = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        if (value) params.append(key, value);
      });
      
      const response = await apiFetch(`${API_BASE}/api/alerts?${params}`);
      const result = await response.json();
      setData(prev => ({ ...prev, alerts: result.alerts || [] }));
      setShowFilters(false);
    } catch (error) {
      console.error('Error fetching filtered alerts:', error);
    }
  };

  const handleExport = async (format, table = 'alerts') => {
    try {
      const params = new URLSearchParams();
      if (filters.start_date) params.append('start_date', filters.start_date);
      if (filters.end_date) params.append('end_date', filters.end_date);
      params.append('table', table);
      
      const url = `${API_BASE}/api/export/${format}?${params}`;
      window.open(url, '_blank');
    } catch (error) {
      console.error('Error exporting data:', error);
      alert('Export failed. Check console for details.');
    }
  };

  const acknowledgeAlert = async (alertId) => {
    try {
      await apiFetch(`${API_BASE}/api/alerts/${alertId}/acknowledge`, { method: 'POST' });
      fetchDashboard();
    } catch (error) {
      console.error('Error acknowledging alert:', error);
    }
  };

  useEffect(() => {
    fetchDashboard();
    fetchStats();
    
    if (autoRefresh) {
      const interval = setInterval(() => {
        fetchDashboard();
        fetchStats();
      }, 10000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh, statsDays]);

  const StatCard = ({ title, value, icon: Icon, color, subtitle, onClick }) => (
    <div 
      className={`bg-white rounded-lg shadow-md p-6 border-l-4 ${onClick ? 'cursor-pointer hover:shadow-lg transition-shadow' : ''}`}
      style={{ borderColor: color }}
      onClick={onClick}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-500 text-sm font-medium">{title}</p>
          <p className="text-3xl font-bold mt-2" style={{ color }}>{value}</p>
          {subtitle && <p className="text-xs text-gray-400 mt-1">{subtitle}</p>}
        </div>
        <div className="p-3 rounded-full" style={{ backgroundColor: `${color}20` }}>
          <Icon size={28} style={{ color }} />
        </div>
      </div>
    </div>
  );

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center">
        <div className="text-white text-xl flex items-center gap-3">
          <RefreshCw className="animate-spin" />
          Loading Dashboard...
        </div>
      </div>
    );
  }

  const predictions = data.predictions || [];
  const alerts = data.alerts || [];
  const displayStats = stats || { total: 0, benign: 0, malicious: 0, attack_types: {} };

  // Prepare chart data
  const timeSeriesData = predictions.slice(-50).map((p) => ({
    sequence: `#${p.sequence}`,
    score: p.score,
    label: p.label
  }));

  const pieData = Object.entries(displayStats.attack_types || {}).map(([name, value]) => ({
    name,
    value,
    color: ATTACK_COLORS[name] || ATTACK_COLORS.default
  }));

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold text-white mb-2">
              Network Anomaly Detector Pro
            </h1>
            <p className="text-gray-400">LSTM-based IDS • Database Persistence • Advanced Filtering</p>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => window.location.href = '/config'}
              className="bg-slate-700 hover:bg-slate-600 text-white px-6 py-3 rounded-lg flex items-center gap-2 transition-all shadow-lg hover:shadow-xl"
            >
              <Settings size={18} />
              Settings
            </button>
            <button
              onClick={() => { fetchDashboard(); fetchStats(); }}
              className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg flex items-center gap-2 transition-all shadow-lg hover:shadow-xl"
            >
              <RefreshCw size={18} />
              Refresh
            </button>
          </div>
        </div>
        {lastUpdate && (
          <p className="text-gray-500 text-sm mt-2">
            Last updated: {lastUpdate.toLocaleTimeString()}
          </p>
        )}
      </div>

      {/* Stats Period Selector */}
      <div className="mb-6 flex items-center gap-4 flex-wrap">
        <label className="text-white font-medium flex items-center gap-2">
          <Calendar size={18} />
          Statistics Period:
        </label>
        <select
          value={statsDays}
          onChange={(e) => {
            const value = e.target.value;
            setStatsDays(value);
            fetchStats(value);
          }}
          className="bg-white px-4 py-2 rounded-lg border-2 border-gray-300 focus:border-blue-500 outline-none font-medium"
        >
          <optgroup label="Real-Time">
            <option value="0.003">Last 5 Minutes</option>
            <option value="0.021">Last 30 Minutes</option>
            <option value="0.042">Last 1 Hour</option>
            <option value="0.125">Last 3 Hours</option>
            <option value="0.25">Last 6 Hours</option>
            <option value="0.5">Last 12 Hours</option>
          </optgroup>
          <optgroup label="Historical">
            <option value="1">Last 24 Hours</option>
            <option value="7">Last 7 Days</option>
            <option value="14">Last 14 Days</option>
            <option value="30">Last 30 Days</option>
          </optgroup>
        </select>
        
        <label className="flex items-center gap-2 text-white bg-slate-700 px-4 py-2 rounded-lg cursor-pointer ml-auto">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
            className="w-5 h-5"
          />
          Auto-refresh (10s)
        </label>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard
          title="Total Flows"
          value={displayStats.total || 0}
          icon={Activity}
          color="#3b82f6"
          subtitle={`Over ${statsDays} day${statsDays > 1 ? 's' : ''}`}
        />
        <StatCard
          title="Benign Traffic"
          value={displayStats.benign || 0}
          icon={Shield}
          color="#10b981"
          subtitle={`${displayStats.total > 0 ? ((displayStats.benign/displayStats.total)*100).toFixed(1) : 0}% of total`}
        />
        <StatCard
          title="Malicious Traffic"
          value={displayStats.malicious || 0}
          icon={AlertTriangle}
          color="#ef4444"
          subtitle={`${displayStats.total > 0 ? ((displayStats.malicious/displayStats.total)*100).toFixed(1) : 0}% of total`}
        />
        <StatCard
          title="Active Alerts"
          value={alerts.length}
          icon={TrendingUp}
          color="#f59e0b"
          subtitle="Unacknowledged"
        />
      </div>

      {/* Action Buttons */}
      <div className="mb-8 grid grid-cols-1 md:grid-cols-3 gap-4">
        <button
          onClick={() => setShowFilters(!showFilters)}
          className="bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-700 hover:to-purple-800 text-white px-6 py-4 rounded-lg flex items-center justify-center gap-3 transition-all shadow-lg hover:shadow-xl"
        >
          <Filter size={20} />
          <span className="font-semibold">Filter Alerts</span>
        </button>
        
        <button
          onClick={() => handleExport('csv', 'alerts')}
          className="bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white px-6 py-4 rounded-lg flex items-center justify-center gap-3 transition-all shadow-lg hover:shadow-xl"
        >
          <Download size={20} />
          <span className="font-semibold">Export Alerts (CSV)</span>
        </button>
        
        <button
          onClick={() => handleExport('json', 'alerts')}
          className="bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white px-6 py-4 rounded-lg flex items-center justify-center gap-3 transition-all shadow-lg hover:shadow-xl"
        >
          <Download size={20} />
          <span className="font-semibold">Export Alerts (JSON)</span>
        </button>
      </div>

      {/* Filter Panel */}
      {showFilters && (
        <div className="mb-8 bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
              <Filter size={24} />
              Advanced Filters
            </h2>
            <button
              onClick={() => setShowFilters(false)}
              className="text-gray-500 hover:text-gray-700"
            >
              <X size={24} />
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Attack Type</label>
              <select
                value={filters.label}
                onChange={(e) => setFilters({...filters, label: e.target.value})}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
              >
                <option value="">All Types</option>
                <option value="DoS GoldenEye">DoS GoldenEye</option>
                <option value="DoS Slowhttptest">DoS Slowhttptest</option>
                <option value="DoS Hulk">DoS Hulk</option>
                <option value="DDoS">DDoS</option>
                <option value="PortScan">PortScan</option>
                <option value="Bot">Bot</option>
                <option value="Web Attack">Web Attack</option>
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Severity</label>
              <select
                value={filters.severity}
                onChange={(e) => setFilters({...filters, severity: e.target.value})}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
              >
                <option value="">All Severities</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Min Score</label>
              <input
                type="number"
                min="0"
                max="1"
                step="0.1"
                value={filters.min_score}
                onChange={(e) => setFilters({...filters, min_score: e.target.value})}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
                placeholder="0.0 - 1.0"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Max Score</label>
              <input
                type="number"
                min="0"
                max="1"
                step="0.1"
                value={filters.max_score}
                onChange={(e) => setFilters({...filters, max_score: e.target.value})}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
                placeholder="0.0 - 1.0"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Source IP</label>
              <input
                type="text"
                value={filters.src_ip}
                onChange={(e) => setFilters({...filters, src_ip: e.target.value})}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
                placeholder="e.g., 192.168.1.100"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Destination IP</label>
              <input
                type="text"
                value={filters.dst_ip}
                onChange={(e) => setFilters({...filters, dst_ip: e.target.value})}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
                placeholder="e.g., 8.8.8.8"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Start Date</label>
              <input
                type="datetime-local"
                value={filters.start_date}
                onChange={(e) => setFilters({...filters, start_date: e.target.value})}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">End Date</label>
              <input
                type="datetime-local"
                value={filters.end_date}
                onChange={(e) => setFilters({...filters, end_date: e.target.value})}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none"
              />
            </div>
          </div>
          
          <div className="flex gap-4">
            <button
              onClick={fetchFilteredAlerts}
              className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg flex items-center gap-2 transition-all"
            >
              <Search size={18} />
              Apply Filters
            </button>
            <button
              onClick={() => {
                setFilters({
                  label: '', src_ip: '', dst_ip: '', min_score: '', 
                  max_score: '', severity: '', start_date: '', end_date: ''
                });
                fetchDashboard();
              }}
              className="bg-gray-500 hover:bg-gray-600 text-white px-6 py-3 rounded-lg flex items-center gap-2 transition-all"
            >
              <X size={18} />
              Clear Filters
            </button>
          </div>
        </div>
      )}

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Time Series */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h2 className="text-xl font-bold mb-4 text-gray-800">Anomaly Score Timeline (Last 50)</h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timeSeriesData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="sequence" />
              <YAxis domain={[0, 1]} />
              <Tooltip />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="score" 
                stroke="#3b82f6" 
                strokeWidth={2}
                dot={{ r: 3 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Attack Distribution */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h2 className="text-xl font-bold mb-4 text-gray-800">Attack Type Distribution</h2>
          <ResponsiveContainer width="100%" height={300}>
            {pieData.length > 0 ? (
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            ) : (
              <div className="flex items-center justify-center h-full text-gray-500">
                No attack data to display
              </div>
            )}
          </ResponsiveContainer>
        </div>
      </div>

      {/* Alerts Section */}
      <div className="bg-white rounded-lg shadow-lg p-6 mb-8">
        <h2 className="text-xl font-bold mb-4 text-gray-800 flex items-center gap-2">
          <AlertTriangle className="text-red-500" />
          Active Alerts ({alerts.length})
        </h2>
        
        {alerts.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Shield className="mx-auto mb-3 text-green-500" size={48} />
            <p className="text-lg font-medium">No threats detected</p>
            <p className="text-sm">Your network appears to be secure</p>
          </div>
        ) : (
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {alerts.map((alert, idx) => (
              <div
                key={idx}
                className={`border-l-4 p-4 rounded-r-lg flex items-start gap-3 hover:bg-opacity-70 transition-colors ${
                  alert.severity === 'high' ? 'border-red-500 bg-red-50' :
                  alert.severity === 'medium' ? 'border-orange-500 bg-orange-50' :
                  'border-yellow-500 bg-yellow-50'
                }`}
              >
                <AlertTriangle 
                  className={`flex-shrink-0 mt-1 ${
                    alert.severity === 'high' ? 'text-red-500' :
                    alert.severity === 'medium' ? 'text-orange-500' :
                    'text-yellow-500'
                  }`}
                  size={20} 
                />
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <p className="font-semibold text-gray-800">Sequence #{alert.sequence}</p>
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${
                      alert.severity === 'high' ? 'bg-red-200 text-red-800' :
                      alert.severity === 'medium' ? 'bg-orange-200 text-orange-800' :
                      'bg-yellow-200 text-yellow-800'
                    }`}>
                      {alert.severity?.toUpperCase()}
                    </span>
                    <span className="px-2 py-1 rounded text-xs font-semibold bg-gray-200 text-gray-800">
                      Score: {alert.score?.toFixed(3)}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 mb-2">{alert.message}</p>
                  {alert.src_ip && (
                    <div className="text-xs text-gray-500 space-y-1">
                      <p>5-Tuple: {alert.src_ip}:{alert.src_port} → {alert.dst_ip}:{alert.dst_port} ({alert.protocol})</p>
                    </div>
                  )}
                  <div className="flex items-center gap-4 mt-2">
                    <p className="text-xs text-gray-400">
                      {new Date(alert.timestamp).toLocaleString()}
                    </p>
                    {!alert.acknowledged && (
                      <button
                        onClick={() => acknowledgeAlert(alert.id)}
                        className="text-xs text-blue-600 hover:text-blue-800 font-medium"
                      >
                        Acknowledge
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Top Source IPs */}
      {stats?.top_source_ips && stats.top_source_ips.length > 0 && (
        <div className="bg-white rounded-lg shadow-lg p-6 mb-8">
          <h2 className="text-xl font-bold mb-4 text-gray-800">Top Attack Source IPs</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={stats.top_source_ips.map(([ip, count]) => ({ ip, count }))}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="ip" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" fill="#ef4444" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
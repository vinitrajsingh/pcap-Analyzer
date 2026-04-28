import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import Header from '../components/Header';
import PacketTable from '../components/PacketTable';
import PacketFilters from '../components/PacketFilters';
import ReportButton from '../components/ReportButton';
import { getPackets, getAnalysis } from '../services/api';
import Plot from 'react-plotly.js';

const DashboardPage = () => {
    const navigate = useNavigate();

    const [sessionId, setSessionId] = useState(null);
    const [summary, setSummary] = useState(null);
    const [analysis, setAnalysis] = useState(null);
    const [packets, setPackets] = useState([]);
    const [loading, setLoading] = useState(false);
    const [analysisLoading, setAnalysisLoading] = useState(true);
    const [page, setPage] = useState(1);
    const [perPage, setPerPage] = useState(50);
    const [totalPages, setTotalPages] = useState(0);
    const [totalPackets, setTotalPackets] = useState(0);
    const [hasNext, setHasNext] = useState(false);
    const [hasPrev, setHasPrev] = useState(false);
    const [filters, setFilters] = useState({ protocol: '', ip: '' });
    const [sortBy, setSortBy] = useState('timestamp');
    const [sortOrder, setSortOrder] = useState('asc');

    // Load session data from localStorage on mount
    useEffect(() => {
        const storedSessionId = localStorage.getItem('current_session_id');
        const storedSummary = localStorage.getItem('upload_summary');
        const storedAnalysis = localStorage.getItem('upload_analysis');

        if (!storedSessionId) {
            // No session found, redirect to upload page
            navigate('/analyze');
            return;
        }

        setSessionId(storedSessionId);
        if (storedSummary) {
            try {
                setSummary(JSON.parse(storedSummary));
            } catch (e) {
                console.error('Failed to parse summary:', e);
            }
        }

        // Load analysis from localStorage if available
        if (storedAnalysis) {
            try {
                setAnalysis(JSON.parse(storedAnalysis));
                setAnalysisLoading(false);
            } catch (e) {
                console.error('Failed to parse analysis:', e);
            }
        } else {
            // Fetch analysis if not in localStorage
            fetchAnalysis(storedSessionId);
        }
    }, [navigate]);

    // Fetch analysis from API
    const fetchAnalysis = async (sid) => {
        try {
            const data = await getAnalysis(sid);
            if (data.analysis) {
                setAnalysis(data.analysis);
                localStorage.setItem('upload_analysis', JSON.stringify(data.analysis));
            }
        } catch (error) {
            console.error('Error fetching analysis:', error);
        } finally {
            setAnalysisLoading(false);
        }
    };

    // Fetch packets when filters, page, or perPage changes
    useEffect(() => {
        if (sessionId) {
            fetchPackets();
        }
    }, [sessionId, page, perPage, filters, sortBy, sortOrder]);

    const fetchPackets = async () => {
        if (!sessionId) return;

        setLoading(true);
        try {
            const data = await getPackets(sessionId, page, perPage, filters, sortBy, sortOrder);
            setPackets(data.packets || []);
            setTotalPackets(data.total_packets || 0);
            setTotalPages(data.total_pages || 0);
            setHasNext(data.has_next || false);
            setHasPrev(data.has_prev || false);
        } catch (error) {
            console.error('Error fetching packets:', error);
            // If session expired, redirect to upload
            if (error.message.includes('not found')) {
                navigate('/analyze');
            }
        } finally {
            setLoading(false);
        }
    };

    const handlePageChange = (newPage) => {
        if (newPage >= 1 && newPage <= totalPages) {
            setPage(newPage);
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    };

    const handlePerPageChange = (newPerPage) => {
        setPerPage(newPerPage);
        setPage(1); // Reset to first page when changing per page
    };

    const handleFilterChange = (newFilters) => {
        setFilters(newFilters);
        setPage(1); // Reset to first page when filtering
    };

    const handleResetFilters = () => {
        setFilters({ protocol: '', ip: '' });
        setPage(1);
    };

    // Helper functions
    const formatBytes = (bytes) => {
        if (!bytes) return '0 B';
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
        if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
        return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    };

    const getScoreColor = (score) => {
        if (score >= 90) return 'text-green-500';
        if (score >= 80) return 'text-blue-500';
        if (score >= 70) return 'text-yellow-500';
        if (score >= 60) return 'text-orange-500';
        return 'text-red-500';
    };

    const getSeverityColor = (severity) => {
        const colors = {
            low: 'bg-green-100 text-green-800 border-green-300',
            medium: 'bg-yellow-100 text-yellow-800 border-yellow-300',
            high: 'bg-orange-100 text-orange-800 border-orange-300',
            critical: 'bg-red-100 text-red-800 border-red-300'
        };
        return colors[severity] || 'bg-gray-100 text-gray-800 border-gray-300';
    };

    const { traffic, tcp } = analysis || {};

    // Debug: Log analysis data structure (must be before any conditional returns)
    useEffect(() => {
        if (analysis) {
            console.log('=== Analysis Debug ===');
            console.log('Full analysis:', analysis);
            console.log('Traffic object:', traffic);
            console.log('Traffic timeline:', traffic?.traffic_timeline, 'Length:', traffic?.traffic_timeline?.length);
            console.log('Top talkers:', traffic?.top_talkers);
            console.log('Top talkers src:', traffic?.top_talkers?.by_packets?.src);
            console.log('Port analysis:', traffic?.port_analysis, 'Length:', traffic?.port_analysis?.length);
            console.log('Connection pairs:', traffic?.connection_pairs, 'Length:', traffic?.connection_pairs?.length);
            console.log('====================');
        }
    }, [analysis, traffic]);

    // If no session, show loading or redirect
    if (!sessionId) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-slate-50">
                <Header />
                <div className="container mx-auto px-6 py-12">
                    <div className="text-center">
                        <p className="text-gray-600">Loading...</p>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-slate-50">
            <Header />
            <div className="container mx-auto px-6 py-12">
                <div className="max-w-7xl mx-auto">
                    {/* Header with Report Button */}
                    <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-8">
                        <div>
                            <h1 className="text-4xl font-bold text-gray-900 mb-2">Network Analysis Dashboard</h1>
                            <p className="text-lg text-gray-600">
                                Comprehensive network traffic analysis for {summary?.filename || 'your capture'}
                            </p>
                        </div>
                        <div className="flex flex-wrap gap-3 mt-4 md:mt-0">
                            <Link
                                to="/geolocation"
                                className="inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg font-medium hover:from-blue-600 hover:to-blue-700 transition-all duration-200 shadow-md hover:shadow-lg"
                            >
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                View Geolocation
                            </Link>
                            <ReportButton sessionId={sessionId} />
                        </div>
                    </div>

                    {/* Summary Cards */}
                    {summary && (
                        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
                            <SummaryCard
                                title="Total Packets"
                                value={summary.total_packets?.toLocaleString() || 0}
                                icon="📦"
                            />
                            <SummaryCard
                                title="Total Bytes"
                                value={formatBytes(summary.total_bytes)}
                                icon="💾"
                            />
                            <SummaryCard
                                title="Duration"
                                value={`${summary.capture_duration?.toFixed(2) || 0}s`}
                                icon="⏱️"
                            />
                            <SummaryCard
                                title="Packets/sec"
                                value={summary.packets_per_second?.toFixed(2) || 0}
                                icon="📈"
                            />
                            <SummaryCard
                                title="Source IPs"
                                value={summary.unique_src_ips || 0}
                                icon="🖥️"
                            />
                            <SummaryCard
                                title="Dest IPs"
                                value={summary.unique_dst_ips || 0}
                                icon="🌐"
                            />
                        </div>
                    )}

                    {/* TCP Health Score Section */}
                    {analysisLoading ? (
                        <div className="bg-white rounded-lg shadow p-12 text-center mb-8">
                            <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
                            <p className="mt-4 text-gray-600">Loading analysis...</p>
                        </div>
                    ) : analysis && tcp && (
                        <div className="bg-white rounded-lg shadow p-6 mb-8">
                            <h2 className="text-xl font-semibold mb-4">TCP Health Score</h2>
                            <div className="flex flex-col md:flex-row items-center gap-8">
                                <div className="text-center">
                                    <div className={`text-6xl font-bold ${getScoreColor(tcp.health_score?.score || 0)}`}>
                                        {tcp.health_score?.score || 0}
                                    </div>
                                    <div className="text-2xl font-semibold mt-2">
                                        Grade: {tcp.health_score?.grade || 'N/A'}
                                    </div>
                                </div>
                                <div className="flex-1 grid grid-cols-1 md:grid-cols-3 gap-4">
                                    <IssueCard
                                        title="Retransmissions"
                                        count={tcp.issues_summary?.issues?.retransmissions?.count || 0}
                                        severity={tcp.issues_summary?.issues?.retransmissions?.severity || 'low'}
                                    />
                                    <IssueCard
                                        title="Connection Resets"
                                        count={tcp.issues_summary?.issues?.resets?.count || 0}
                                        severity={tcp.issues_summary?.issues?.resets?.severity || 'low'}
                                    />
                                    <IssueCard
                                        title="Failed Connections"
                                        count={tcp.issues_summary?.issues?.failed_connections?.count || 0}
                                        severity={tcp.issues_summary?.issues?.failed_connections?.severity || 'low'}
                                    />
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Charts Row 1 - Protocol Distribution & Traffic Timeline */}
                    {analysis && traffic && (
                        <>
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                                {/* Protocol Distribution Pie Chart */}
                                <div className="bg-white rounded-lg shadow p-4">
                                    <h3 className="text-lg font-semibold mb-4">Protocol Distribution</h3>
                                    {traffic.protocol_distribution && Object.keys(traffic.protocol_distribution).length > 0 ? (
                                        <Plot
                                            data={[{
                                                values: Object.values(traffic.protocol_distribution).map(p => p.count),
                                                labels: Object.keys(traffic.protocol_distribution),
                                                type: 'pie',
                                                hole: 0.4,
                                                textinfo: 'percent',
                                                textposition: 'inside'
                                            }]}
                                            layout={{
                                                height: 350,
                                                margin: { t: 30, b: 30, l: 180, r: 30 },
                                                showlegend: true,
                                                legend: {
                                                    x: -0.1,
                                                    y: 0.5,
                                                    xanchor: 'right',
                                                    yanchor: 'middle',
                                                    orientation: 'v'
                                                }
                                            }}
                                            config={{ responsive: true, displayModeBar: false }}
                                        />
                                    ) : (
                                        <div className="h-[350px] flex items-center justify-center text-gray-500">
                                            No protocol data available
                                        </div>
                                    )}
                                </div>

                                {/* Traffic Timeline */}
                                <div className="bg-white rounded-lg shadow p-4">
                                    <h3 className="text-lg font-semibold mb-4">Traffic Over Time</h3>
                                    {traffic.traffic_timeline && traffic.traffic_timeline.length > 0 ? (
                                        <Plot
                                            data={[{
                                                x: traffic.traffic_timeline.map(t => t.time),
                                                y: traffic.traffic_timeline.map(t => t.packets),
                                                type: 'scatter',
                                                mode: 'lines+markers',
                                                fill: 'tozeroy',
                                                line: { color: '#3b82f6' },
                                                marker: { size: 4 }
                                            }]}
                                            layout={{
                                                height: 350,
                                                margin: { t: 30, b: 50, l: 50, r: 30 },
                                                xaxis: { title: 'Time' },
                                                yaxis: { title: 'Packets' }
                                            }}
                                            config={{ responsive: true, displayModeBar: false }}
                                        />
                                    ) : (
                                        <div className="h-[350px] flex items-center justify-center text-gray-500">
                                            No timeline data available
                                        </div>
                                    )}
                                </div>
                            </div>

                            {/* Charts Row 2 - Top Talkers & Port Analysis (Stacked Vertically) */}
                            <div className="grid grid-cols-1 gap-6 mb-6">
                                {/* Top Talkers by Packets */}
                                <div className="bg-white rounded-lg shadow p-4">
                                    <h3 className="text-lg font-semibold mb-4">Top Talkers (by Packets)</h3>
                                    {traffic.top_talkers?.by_packets?.src && traffic.top_talkers.by_packets.src.length > 0 ? (
                                        <div className="overflow-x-auto">
                                            <Plot
                                                data={[{
                                                    x: traffic.top_talkers.by_packets.src.slice(0, 10).map(t => t[1]),
                                                    y: traffic.top_talkers.by_packets.src.slice(0, 10).map(t => t[0]),
                                                    type: 'bar',
                                                    orientation: 'h',
                                                    marker: { color: '#3b82f6' },
                                                    text: traffic.top_talkers.by_packets.src.slice(0, 10).map(t => t[0]),
                                                    textposition: 'outside'
                                                }]}
                                                layout={{
                                                    height: 400,
                                                    margin: { l: 200, r: 50, t: 30, b: 50 },
                                                    xaxis: { title: 'Packet Count' },
                                                    yaxis: {
                                                        title: 'Source IP',
                                                        automargin: true,
                                                        tickmode: 'linear',
                                                        tickangle: 0
                                                    },
                                                    autosize: true
                                                }}
                                                config={{ responsive: true, displayModeBar: false }}
                                                style={{ width: '100%', minWidth: '600px' }}
                                            />
                                        </div>
                                    ) : (
                                        <div className="h-[400px] flex items-center justify-center text-gray-500">
                                            No top talkers data available
                                        </div>
                                    )}
                                </div>

                                {/* Port Analysis */}
                                <div className="bg-white rounded-lg shadow p-4">
                                    <h3 className="text-lg font-semibold mb-4">Top Ports</h3>
                                    {traffic.port_analysis && traffic.port_analysis.length > 0 ? (
                                        <div className="w-full">
                                            <Plot
                                                data={[{
                                                    x: traffic.port_analysis.slice(0, 10).map(p => p.count),
                                                    y: traffic.port_analysis.slice(0, 10).map(p => `${p.port} (${p.service})`),
                                                    type: 'bar',
                                                    orientation: 'h',
                                                    marker: { color: '#10b981' }
                                                }]}
                                                layout={{
                                                    height: 400,
                                                    margin: { l: 150, r: 30, t: 30, b: 50 },
                                                    xaxis: { title: 'Packet Count' },
                                                    yaxis: {
                                                        title: 'Port (Service)',
                                                        automargin: true
                                                    },
                                                    autosize: true
                                                }}
                                                config={{ responsive: true, displayModeBar: false }}
                                                style={{ width: '100%', minWidth: '100%' }}
                                            />
                                        </div>
                                    ) : (
                                        <div className="h-[400px] flex items-center justify-center text-gray-500">
                                            No port analysis data available
                                        </div>
                                    )}
                                </div>
                            </div>

                            {/* IPv4 vs IPv6 Distribution */}
                            {traffic.ip_version_distribution && (
                                <div className="bg-white rounded-lg shadow p-4 mb-6">
                                    <h3 className="text-lg font-semibold mb-4">IP Version Distribution</h3>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="text-center p-4 bg-blue-50 rounded-lg">
                                            <div className="text-3xl font-bold text-blue-600">
                                                {traffic.ip_version_distribution.IPv4?.count || 0}
                                            </div>
                                            <div className="text-sm text-gray-600 mt-1">
                                                IPv4 ({traffic.ip_version_distribution.IPv4?.percentage || 0}%)
                                            </div>
                                        </div>
                                        <div className="text-center p-4 bg-green-50 rounded-lg">
                                            <div className="text-3xl font-bold text-green-600">
                                                {traffic.ip_version_distribution.IPv6?.count || 0}
                                            </div>
                                            <div className="text-sm text-gray-600 mt-1">
                                                IPv6 ({traffic.ip_version_distribution.IPv6?.percentage || 0}%)
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Connection Pairs Table */}
                            <div className="bg-white rounded-lg shadow p-4 mb-6">
                                <h3 className="text-lg font-semibold mb-4">Top Connection Pairs</h3>
                                {traffic.connection_pairs && traffic.connection_pairs.length > 0 ? (
                                    <div className="overflow-x-auto">
                                        <table className="min-w-full divide-y divide-gray-200">
                                            <thead className="bg-gray-50">
                                                <tr>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source IP</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Destination IP</th>
                                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Packets</th>
                                                </tr>
                                            </thead>
                                            <tbody className="bg-white divide-y divide-gray-200">
                                                {traffic.connection_pairs.slice(0, 10).map((pair, idx) => (
                                                    <tr key={idx} className="hover:bg-gray-50">
                                                        <td className="px-4 py-3 text-sm font-mono">{pair.src}</td>
                                                        <td className="px-4 py-3 text-sm font-mono">{pair.dst}</td>
                                                        <td className="px-4 py-3 text-sm">{pair.packets.toLocaleString()}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                ) : (
                                    <div className="py-8 text-center text-gray-500">
                                        No connection pairs data available
                                    </div>
                                )}
                            </div>
                        </>
                    )}

                    {/* Filters */}
                    <PacketFilters
                        filters={filters}
                        onFilterChange={handleFilterChange}
                        onReset={handleResetFilters}
                    />

                    {/* Packet Table */}
                    <PacketTable
                        packets={packets}
                        loading={loading}
                        page={page}
                        perPage={perPage}
                        totalPages={totalPages}
                        totalPackets={totalPackets}
                        hasNext={hasNext}
                        hasPrev={hasPrev}
                        onPageChange={handlePageChange}
                        onPerPageChange={handlePerPageChange}
                    />
                </div>
            </div>
        </div>
    );
};

// Helper Components
const SummaryCard = ({ title, value, icon }) => (
    <div className="bg-white rounded-lg shadow p-4">
        <div className="text-2xl mb-1">{icon}</div>
        <div className="text-sm text-gray-500 mb-1">{title}</div>
        <div className="text-xl font-bold text-gray-900">{value}</div>
    </div>
);

const IssueCard = ({ title, count, severity }) => {
    const colors = {
        low: 'bg-green-100 text-green-800 border-green-300',
        medium: 'bg-yellow-100 text-yellow-800 border-yellow-300',
        high: 'bg-orange-100 text-orange-800 border-orange-300',
        critical: 'bg-red-100 text-red-800 border-red-300'
    };

    const colorClass = colors[severity] || 'bg-gray-100 text-gray-800 border-gray-300';

    return (
        <div className={`rounded-lg p-4 border-2 ${colorClass}`}>
            <div className="text-sm font-medium mb-1">{title}</div>
            <div className="text-3xl font-bold">{count}</div>
            <div className="text-xs uppercase font-semibold mt-1">{severity}</div>
        </div>
    );
};

export default DashboardPage;

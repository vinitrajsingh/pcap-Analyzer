import { useState } from 'react';

const getProtocolColor = (protocol) => {
    const colors = {
        'TCP': 'bg-blue-100 text-blue-800',
        'UDP': 'bg-green-100 text-green-800',
        'HTTP': 'bg-purple-100 text-purple-800',
        'HTTPS': 'bg-indigo-100 text-indigo-800',
        'DNS': 'bg-yellow-100 text-yellow-800',
        'QUIC': 'bg-pink-100 text-pink-800',
        'ICMP': 'bg-red-100 text-red-800',
        'TLS': 'bg-cyan-100 text-cyan-800',
    };
    return colors[protocol?.toUpperCase()] || 'bg-gray-100 text-gray-800';
};

const formatTimestamp = (timestamp) => {
    if (!timestamp) return '-';
    try {
        const date = new Date(timestamp * 1000);
        return date.toLocaleTimeString('en-US', { 
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            fractionalSecondDigits: 3
        });
    } catch {
        return '-';
    }
};

const formatEndpoint = (ip, port) => {
    if (!ip) return '-';
    if (port) {
        return `${ip}:${port}`;
    }
    return ip;
};

const PacketTable = ({ 
    packets = [], 
    loading = false,
    page = 1,
    perPage = 50,
    totalPages = 0,
    totalPackets = 0,
    hasNext = false,
    hasPrev = false,
    onPageChange,
    onPerPageChange,
    onRowClick
}) => {
    const [expandedRow, setExpandedRow] = useState(null);

    const handleRowClick = (index) => {
        if (onRowClick) {
            onRowClick(packets[index]);
        }
        setExpandedRow(expandedRow === index ? null : index);
    };

    const startIndex = (page - 1) * perPage;

    if (loading) {
        return (
            <div className="bg-white rounded-lg shadow p-12 text-center">
                <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
                <p className="mt-4 text-gray-600">Loading packets...</p>
            </div>
        );
    }

    if (packets.length === 0) {
        return (
            <div className="bg-white rounded-lg shadow p-12 text-center">
                <p className="text-gray-600">No packets found</p>
            </div>
        );
    }

    return (
        <div className="bg-white rounded-lg shadow overflow-hidden">
            {/* Table */}
            <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                        <tr>
                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                #
                            </th>
                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Time
                            </th>
                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Source
                            </th>
                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Destination
                            </th>
                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Protocol
                            </th>
                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Length
                            </th>
                            <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Info
                            </th>
                        </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                        {packets.map((pkt, idx) => (
                            <>
                                <tr
                                    key={idx}
                                    onClick={() => handleRowClick(idx)}
                                    className="hover:bg-gray-50 cursor-pointer transition-colors"
                                >
                                    <td className="px-4 py-3 text-sm text-gray-500">
                                        {startIndex + idx + 1}
                                    </td>
                                    <td className="px-4 py-3 text-sm font-mono text-gray-600">
                                        {formatTimestamp(pkt.timestamp)}
                                    </td>
                                    <td className="px-4 py-3 text-sm font-mono">
                                        {formatEndpoint(pkt.src_ip, pkt.src_port)}
                                    </td>
                                    <td className="px-4 py-3 text-sm font-mono">
                                        {formatEndpoint(pkt.dst_ip, pkt.dst_port)}
                                    </td>
                                    <td className="px-4 py-3 text-sm">
                                        <span className={`inline-flex px-2 py-1 rounded text-xs font-medium ${getProtocolColor(pkt.protocol)}`}>
                                            {pkt.protocol || 'Unknown'}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3 text-sm text-gray-600">
                                        {pkt.length || '-'}
                                    </td>
                                    <td className="px-4 py-3 text-sm text-gray-500">
                                        {pkt.tcp_flags || '-'}
                                    </td>
                                </tr>
                                {expandedRow === idx && (
                                    <tr className="bg-gray-50">
                                        <td colSpan="7" className="px-4 py-4">
                                            <div className="grid grid-cols-2 gap-4 text-sm">
                                                <div>
                                                    <strong>Sequence:</strong> {pkt.seq_num || '-'}
                                                </div>
                                                <div>
                                                    <strong>Acknowledgment:</strong> {pkt.ack_num || '-'}
                                                </div>
                                                <div>
                                                    <strong>TTL:</strong> {pkt.ttl || '-'}
                                                </div>
                                                <div>
                                                    <strong>IP Version:</strong> {pkt.ip_version || '-'}
                                                </div>
                                                {pkt.tcp_flags_raw && (
                                                    <div>
                                                        <strong>TCP Flags (Raw):</strong> {pkt.tcp_flags_raw}
                                                    </div>
                                                )}
                                                {pkt.datetime && (
                                                    <div>
                                                        <strong>Date/Time:</strong> {new Date(pkt.datetime).toLocaleString()}
                                                    </div>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                )}
                            </>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Pagination Controls */}
            <div className="bg-gray-50 px-4 py-3 flex items-center justify-between border-t border-gray-200">
                <div className="flex items-center space-x-4">
                    <span className="text-sm text-gray-700">
                        Showing <strong>{startIndex + 1}</strong> to <strong>{Math.min(startIndex + perPage, totalPackets)}</strong> of <strong>{totalPackets}</strong> packets
                    </span>
                    <select
                        value={perPage}
                        onChange={(e) => onPerPageChange(Number(e.target.value))}
                        className="ml-4 border border-gray-300 rounded-md px-3 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                        <option value={25}>25 per page</option>
                        <option value={50}>50 per page</option>
                        <option value={100}>100 per page</option>
                    </select>
                </div>
                <div className="flex items-center space-x-2">
                    <button
                        onClick={() => onPageChange(page - 1)}
                        disabled={!hasPrev}
                        className={`px-3 py-1 rounded-md text-sm font-medium ${
                            hasPrev
                                ? 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'
                                : 'bg-gray-100 text-gray-400 cursor-not-allowed'
                        }`}
                    >
                        <svg className="w-5 h-5 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                        </svg>
                        Previous
                    </button>
                    <span className="px-4 py-1 text-sm text-gray-700">
                        Page {page} of {totalPages || 1}
                    </span>
                    <button
                        onClick={() => onPageChange(page + 1)}
                        disabled={!hasNext}
                        className={`px-3 py-1 rounded-md text-sm font-medium ${
                            hasNext
                                ? 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'
                                : 'bg-gray-100 text-gray-400 cursor-not-allowed'
                        }`}
                    >
                        Next
                        <svg className="w-5 h-5 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                    </button>
                </div>
            </div>
        </div>
    );
};

export default PacketTable;

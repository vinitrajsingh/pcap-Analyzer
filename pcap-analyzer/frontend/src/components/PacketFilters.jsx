const PacketFilters = ({ filters, onFilterChange, onReset }) => {
    const commonProtocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'QUIC', 'ICMP', 'TLS'];

    return (
        <div className="bg-white rounded-lg shadow p-4 mb-6">
            <div className="flex flex-wrap items-center gap-4">
                <div className="flex-1 min-w-[200px]">
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                        Protocol
                    </label>
                    <select
                        value={filters.protocol || ''}
                        onChange={(e) => onFilterChange({ ...filters, protocol: e.target.value })}
                        className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                        <option value="">All Protocols</option>
                        {commonProtocols.map((proto) => (
                            <option key={proto} value={proto}>
                                {proto}
                            </option>
                        ))}
                    </select>
                </div>

                <div className="flex-1 min-w-[200px]">
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                        IP Address
                    </label>
                    <div className="relative">
                        <svg className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                        </svg>
                        <input
                            type="text"
                            value={filters.ip || ''}
                            onChange={(e) => onFilterChange({ ...filters, ip: e.target.value })}
                            placeholder="Search by IP address..."
                            className="w-full pl-10 pr-10 border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                        {filters.ip && (
                            <button
                                onClick={() => onFilterChange({ ...filters, ip: '' })}
                                className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                            >
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </button>
                        )}
                    </div>
                </div>

                {(filters.protocol || filters.ip) && (
                    <div className="flex items-end">
                        <button
                            onClick={onReset}
                            className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors"
                        >
                            Reset Filters
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default PacketFilters;

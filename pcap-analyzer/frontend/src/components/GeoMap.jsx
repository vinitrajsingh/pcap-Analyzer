import React from 'react';
import Plot from 'react-plotly.js';

const GeoMap = ({ geolocation }) => {
    // Handle unavailable or error state
    if (!geolocation) {
        return (
            <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4">Geographic Distribution</h3>
                <p className="text-gray-500">Loading geolocation data...</p>
            </div>
        );
    }

    if (!geolocation.available) {
        return (
            <div className="bg-white rounded-lg shadow p-6">
                <h3 className="text-lg font-semibold mb-4">Geographic Distribution</h3>
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                    <p className="text-yellow-800 font-medium">Geolocation Database Not Available</p>
                    <p className="text-yellow-700 text-sm mt-2">
                        {geolocation.error || "Please download GeoLite2-City.mmdb from MaxMind."}
                    </p>
                    {geolocation.download_url && (
                        <a 
                            href={geolocation.download_url} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-blue-600 hover:underline text-sm mt-2 inline-block"
                        >
                            Download from MaxMind →
                        </a>
                    )}
                </div>
            </div>
        );
    }

    const { 
        src_map_points = [], 
        dst_map_points = [], 
        connection_lines = [], 
        country_distribution = [],
        city_distribution = [],
        total_unique_ips = 0,
        total_countries = 0,
        total_cities = 0,
        public_ips = 0,
        private_ips = 0
    } = geolocation;

    // Filter points
    const uniqueSrcPoints = src_map_points.filter(p => !p.is_private);
    const uniqueDstPoints = dst_map_points.filter(p => !p.is_private);

    // Prepare map data - ORDER MATTERS FOR LAYERING
    const mapData = [];

    // LAYER 1: Connection lines (bottom layer)
    if (connection_lines && connection_lines.length > 0) {
        const maxPackets = Math.max(...connection_lines.map(l => l.packet_count));
        
        connection_lines.forEach((line, idx) => {
            const normalizedWidth = 1 + (line.packet_count / maxPackets) * 3;
            
            mapData.push({
                type: 'scattergeo',
                mode: 'lines',
                lat: [line.src_lat, line.dst_lat],
                lon: [line.src_lon, line.dst_lon],
                line: {
                    width: normalizedWidth,
                    color: 'rgba(239, 68, 68, 0.6)'
                },
                hoverinfo: 'text',
                text: `${line.src_ip} → ${line.dst_ip}<br>${line.src_city}, ${line.src_country} → ${line.dst_city}, ${line.dst_country}<br>Packets: ${line.packet_count}`,
                showlegend: idx === 0,
                name: 'Connections',
                legendgroup: 'connections'
            });
        });
    }

    // LAYER 2: Destination IPs (green diamonds) - rendered SECOND
    if (uniqueDstPoints.length > 0) {
        mapData.push({
            type: 'scattergeo',
            mode: 'markers',
            lat: uniqueDstPoints.map(p => p.lat),
            lon: uniqueDstPoints.map(p => p.lon),
            text: uniqueDstPoints.map(p => `Destination: ${p.ip}<br>${p.city}, ${p.country}`),
            hoverinfo: 'text',
            marker: {
                size: 10,
                color: '#10b981',
                opacity: 0.8,
                line: { width: 2, color: 'white' },
                symbol: 'diamond'
            },
            name: 'Destination IPs',
            legendgroup: 'destination'
        });
    }

    // LAYER 3: Source IPs (blue circles) - rendered LAST (on top)
    if (uniqueSrcPoints.length > 0) {
        mapData.push({
            type: 'scattergeo',
            mode: 'markers',
            lat: uniqueSrcPoints.map(p => p.lat),
            lon: uniqueSrcPoints.map(p => p.lon),
            text: uniqueSrcPoints.map(p => `Source: ${p.ip}<br>${p.city}, ${p.country}`),
            hoverinfo: 'text',
            marker: {
                size: 11,
                color: '#3b82f6',
                opacity: 0.9,
                line: { width: 2, color: 'white' },
                symbol: 'circle'
            },
            name: 'Source IPs',
            legendgroup: 'source'
        });
    }

    const hasMapData = mapData.length > 0;

    return (
        <div className="space-y-6">
            {/* Stats Cards */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="bg-white rounded-lg shadow p-4 text-center">
                    <div className="text-3xl font-bold text-blue-600">
                        {total_unique_ips}
                    </div>
                    <div className="text-sm text-gray-500">Total IPs</div>
                </div>
                <div className="bg-white rounded-lg shadow p-4 text-center">
                    <div className="text-3xl font-bold text-green-600">
                        {public_ips}
                    </div>
                    <div className="text-sm text-gray-500">Public IPs</div>
                </div>
                <div className="bg-white rounded-lg shadow p-4 text-center">
                    <div className="text-3xl font-bold text-gray-600">
                        {private_ips}
                    </div>
                    <div className="text-sm text-gray-500">Private IPs</div>
                </div>
                <div className="bg-white rounded-lg shadow p-4 text-center">
                    <div className="text-3xl font-bold text-purple-600">
                        {total_countries}
                    </div>
                    <div className="text-sm text-gray-500">Countries</div>
                </div>
                <div className="bg-white rounded-lg shadow p-4 text-center">
                    <div className="text-3xl font-bold text-orange-600">
                        {total_cities}
                    </div>
                    <div className="text-sm text-gray-500">Cities</div>
                </div>
            </div>

            {/* World Map */}
            <div className="bg-white rounded-lg shadow p-4">
                <h3 className="text-lg font-semibold mb-4">IP Geolocation Map</h3>
                <div className="flex items-center gap-6 mb-4 text-sm">
                    <div className="flex items-center gap-2">
                        <span className="w-3 h-3 rounded-full bg-blue-500 border-2 border-white shadow"></span>
                        <span className="text-gray-700">Source IPs ({uniqueSrcPoints.length})</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="w-3 h-3 bg-green-500 border-2 border-white shadow" style={{ clipPath: 'polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%)' }}></span>
                        <span className="text-gray-700">Destination IPs ({uniqueDstPoints.length})</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="w-6 h-0.5 bg-red-400 rounded"></span>
                        <span className="text-gray-700">Connections ({connection_lines.length})</span>
                    </div>
                </div>
                
                {hasMapData ? (
                    <Plot
                        data={mapData}
                        layout={{
                            geo: {
                                projection: { type: 'natural earth' },
                                showland: true,
                                landcolor: '#f3f4f6',
                                showocean: true,
                                oceancolor: '#dbeafe',
                                showcoastlines: true,
                                coastlinecolor: '#9ca3af',
                                showcountries: true,
                                countrycolor: '#d1d5db',
                                showlakes: true,
                                lakecolor: '#dbeafe',
                                resolution: 110
                            },
                            height: 500,
                            margin: { t: 10, b: 10, l: 10, r: 10 },
                            showlegend: true,
                            legend: {
                                x: 0,
                                y: 1,
                                bgcolor: 'rgba(255,255,255,0.8)'
                            }
                        }}
                        config={{ 
                            responsive: true, 
                            displayModeBar: true,
                            modeBarButtonsToRemove: ['select2d', 'lasso2d']
                        }}
                        style={{ width: '100%' }}
                    />
                ) : (
                    <div className="h-64 flex items-center justify-center bg-gray-50 rounded">
                        <p className="text-gray-500">No public IP locations to display on map</p>
                    </div>
                )}
            </div>

            {/* Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Country Distribution */}
                {country_distribution && country_distribution.length > 0 && (
                    <div className="bg-white rounded-lg shadow p-4">
                        <h3 className="text-lg font-semibold mb-4">IPs by Country</h3>
                        <Plot
                            data={[{
                                x: country_distribution.slice(0, 10).map(c => c.unique_ips),
                                y: country_distribution.slice(0, 10).map(c => c.country),
                                type: 'bar',
                                orientation: 'h',
                                marker: { 
                                    color: '#3b82f6',
                                    line: { color: '#1d4ed8', width: 1 }
                                }
                            }]}
                            layout={{
                                height: 350,
                                margin: { l: 120, r: 30, t: 10, b: 40 },
                                xaxis: { title: 'Unique IPs' },
                                yaxis: { 
                                    title: '',
                                    autorange: 'reversed'
                                }
                            }}
                            config={{ responsive: true, displayModeBar: false }}
                        />
                    </div>
                )}

                {/* City Distribution */}
                {city_distribution && city_distribution.length > 0 && (
                    <div className="bg-white rounded-lg shadow p-4">
                        <h3 className="text-lg font-semibold mb-4">IPs by City</h3>
                        <Plot
                            data={[{
                                x: city_distribution.slice(0, 10).map(c => c.unique_ips),
                                y: city_distribution.slice(0, 10).map(c => c.city),
                                type: 'bar',
                                orientation: 'h',
                                marker: { 
                                    color: '#10b981',
                                    line: { color: '#047857', width: 1 }
                                }
                            }]}
                            layout={{
                                height: 350,
                                margin: { l: 150, r: 30, t: 10, b: 40 },
                                xaxis: { title: 'Unique IPs' },
                                yaxis: { 
                                    title: '',
                                    autorange: 'reversed'
                                }
                            }}
                            config={{ responsive: true, displayModeBar: false }}
                        />
                    </div>
                )}
            </div>

            {/* Connection Lines Table */}
            {connection_lines && connection_lines.length > 0 && (
                <div className="bg-white rounded-lg shadow p-4">
                    <h3 className="text-lg font-semibold mb-4">Top Geographic Connections</h3>
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Destination</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Packets</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-200">
                                {connection_lines.slice(0, 10).map((line, idx) => (
                                    <tr key={idx} className="hover:bg-gray-50">
                                        <td className="px-4 py-3 text-sm">
                                            <div className="font-mono text-blue-600">{line.src_ip}</div>
                                            <div className="text-gray-500 text-xs">{line.src_city}, {line.src_country}</div>
                                        </td>
                                        <td className="px-4 py-3 text-sm">
                                            <div className="font-mono text-green-600">{line.dst_ip}</div>
                                            <div className="text-gray-500 text-xs">{line.dst_city}, {line.dst_country}</div>
                                        </td>
                                        <td className="px-4 py-3 text-sm font-semibold">{line.packet_count.toLocaleString()}</td>
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

export default GeoMap;
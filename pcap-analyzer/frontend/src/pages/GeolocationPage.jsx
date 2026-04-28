import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Header from '../components/Header';
import GeoMap from '../components/GeoMap';
import { getGeolocation } from '../services/api';

const GeolocationPage = () => {
    const navigate = useNavigate();

    const [sessionId, setSessionId] = useState(null);
    const [geolocation, setGeolocation] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    // Load session data and geolocation from localStorage or API
    useEffect(() => {
        const storedSessionId = localStorage.getItem('current_session_id');
        const storedGeolocation = localStorage.getItem('upload_geolocation');

        if (!storedSessionId) {
            navigate('/analyze');
            return;
        }

        setSessionId(storedSessionId);

        // Load geolocation from localStorage if available
        if (storedGeolocation) {
            try {
                setGeolocation(JSON.parse(storedGeolocation));
                setLoading(false);
            } catch (e) {
                console.error('Failed to parse geolocation from localStorage:', e);
                fetchGeolocation(storedSessionId);
            }
        } else {
            // Fetch geolocation if not in localStorage
            fetchGeolocation(storedSessionId);
        }
    }, [navigate]);

    // Fetch geolocation from API
    const fetchGeolocation = async (id) => {
        setLoading(true);
        setError(null);
        try {
            const data = await getGeolocation(id);
            if (data.geolocation) {
                setGeolocation(data.geolocation);
                localStorage.setItem('upload_geolocation', JSON.stringify(data.geolocation));
            }
        } catch (err) {
            console.error('Error fetching geolocation:', err);
            setError(err.message || 'Failed to load geolocation data.');
        } finally {
            setLoading(false);
        }
    };

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
                    {/* Header */}
                    <div className="mb-8">
                        <h1 className="text-4xl font-bold text-gray-900 mb-2">IP Geolocation Analysis</h1>
                        <p className="text-lg text-gray-600">
                            Geographic distribution and connection analysis of network traffic
                        </p>
                    </div>

                    {/* Loading State */}
                    {loading && (
                        <div className="bg-white rounded-lg shadow p-12 text-center">
                            <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
                            <p className="mt-4 text-gray-600">Loading geolocation data...</p>
                        </div>
                    )}

                    {/* Error State */}
                    {error && !loading && (
                        <div className="bg-red-50 border border-red-200 rounded-lg p-6 mb-6">
                            <h3 className="text-lg font-semibold text-red-800 mb-2">Error Loading Geolocation</h3>
                            <p className="text-red-700">{error}</p>
                            <button
                                onClick={() => fetchGeolocation(sessionId)}
                                className="mt-4 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
                            >
                                Retry
                            </button>
                        </div>
                    )}

                    {/* Geolocation Content */}
                    {!loading && !error && geolocation && (
                        <GeoMap geolocation={geolocation} />
                    )}

                    {/* No Data State */}
                    {!loading && !error && !geolocation && (
                        <div className="bg-white rounded-lg shadow p-12 text-center">
                            <div className="text-6xl mb-4">🌍</div>
                            <h3 className="text-xl font-semibold text-gray-800 mb-2">No Geolocation Data Available</h3>
                            <p className="text-gray-600 mb-6">
                                Please upload a PCAP file to analyze geographic distribution of network traffic.
                            </p>
                            <button
                                onClick={() => navigate('/analyze')}
                                className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
                            >
                                Upload PCAP File
                            </button>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default GeolocationPage;

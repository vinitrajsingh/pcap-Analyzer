const API_BASE_URL = '/api';

export const getPackets = async (
    sessionId,
    page = 1,
    perPage = 50,
    filters = {},
    sortBy = 'timestamp',
    sortOrder = 'asc'
) => {
    const params = new URLSearchParams({
        page: page.toString(),
        per_page: perPage.toString(),
        sort_by: sortBy,
        sort_order: sortOrder,
    });

    if (filters.protocol) {
        params.append('filter_protocol', filters.protocol);
    }
    if (filters.ip) {
        params.append('filter_ip', filters.ip);
    }

    const response = await fetch(`${API_BASE_URL}/packets/${sessionId}?${params}`);
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to fetch packets');
    }

    return response.json();
};

export const getAnalysis = async (sessionId) => {
    const response = await fetch(`${API_BASE_URL}/analysis/${sessionId}`);
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to fetch analysis');
    }
    
    return response.json();
};

export const getGeolocation = async (sessionId) => {
    const response = await fetch(`${API_BASE_URL}/geolocation/${sessionId}`);
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to fetch geolocation');
    }
    
    return response.json();
};

export const healthCheck = async () => {
    const response = await fetch(`${API_BASE_URL}/health`);
    return response.json();
};

export const generateReport = async (sessionId) => {
    const response = await fetch(`${API_BASE_URL}/report/${sessionId}`);
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to generate report');
    }
    return response.blob();
};

export const checkReportStatus = async (sessionId) => {
    const response = await fetch(`${API_BASE_URL}/report/${sessionId}/status`);
    return response.json();
};

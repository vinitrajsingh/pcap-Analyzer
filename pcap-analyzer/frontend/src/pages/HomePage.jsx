import { useNavigate } from 'react-router-dom'
import Header from '../components/Header'

const HomePage = () => {
    const navigate = useNavigate()

    const handleAnalyzeClick = () => {
        navigate('/analyze')
    }

    const features = [
        {
            icon: '📊',
            title: 'Traffic Analysis',
            description: 'Comprehensive analysis of network protocols, top talkers, and traffic patterns with detailed statistics',
        },
        {
            icon: '🔍',
            title: 'Anomaly Detection',
            description: 'detection of suspicious patterns and network anomalies',
        },
        {
            icon: '🌍',
            title: 'Geolocation Visualization',
            description: 'Visualize network connections on an interactive world map with country and city-level insights',
        },
        {
            icon: '⚡',
            title: 'TCP Health Analysis',
            description: 'Detect TCP connection failures, resets, packet loss, and calculate comprehensive network health scores',
        },
        {
            icon: '📈',
            title: 'Pattern Recognition',
            description: 'Automated identification of communication patterns and network behavior analysis',
        },
        {
            icon: '📄',
            title: 'Automated Reporting',
            description: 'Generate professional PDF and HTML reports with detailed analysis and visualizations',
        },
    ]

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-slate-50">
            <Header />

            <div className="container mx-auto px-6 py-16">
                {/* Hero Section */}
                <div className="max-w-5xl mx-auto text-center mb-20">
                    <div className="mb-8">
                        <h1 className="text-6xl font-bold text-gray-900 mb-6 leading-tight">
                            Network Analysis
                            <span className="block text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-blue-800">
                                Made Intelligent
                            </span>
                        </h1>
                        <p className="text-xl text-gray-600 mb-4 max-w-3xl mx-auto leading-relaxed">
                            Upload your Wireshark PCAP files and get comprehensive network traffic analysis with
                            automated pattern recognition,anomaly detection, and interactive geolocation visualization.
                        </p>
                        <p className="text-lg text-gray-500 max-w-2xl mx-auto">
                            Designed for researchers, network analysts, and students to gain rapid insights into network behavior.
                        </p>
                    </div>

                    {/* Main CTA Button */}
                    <div className="mb-12">
                        <button
                            onClick={handleAnalyzeClick}
                            className="group relative inline-flex items-center justify-center px-8 py-4 text-lg font-semibold text-white bg-gradient-to-r from-blue-600 to-blue-700 rounded-xl shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300 overflow-hidden"
                        >
                            <span className="absolute inset-0 w-full h-full bg-gradient-to-r from-blue-700 to-blue-800 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></span>
                            <span className="relative flex items-center space-x-2">
                                <svg
                                    className="w-5 h-5"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                >
                                    <path
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth={2}
                                        d="M13 10V3L4 14h7v7l9-11h-7z"
                                    />
                                </svg>
                                <span>Let's Analyze the Network</span>
                            </span>
                        </button>
                    </div>

                    {/* Stats or Trust Indicators */}
                    <div className="flex items-center justify-center space-x-8 text-sm text-gray-600">
                        <div className="flex items-center space-x-2">
                            <svg className="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                            </svg>
                            <span>Accurate Analytics</span>
                        </div>
                        <div className="flex items-center space-x-2">
                            <svg className="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                            </svg>
                            <span>Real-time Processing</span>
                        </div>
                        <div className="flex items-center space-x-2">
                            <svg className="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                            </svg>
                            <span>Professional Reports</span>
                        </div>
                    </div>
                </div>

                {/* Features Grid */}
                <div className="max-w-7xl mx-auto">
                    <h2 className="text-3xl font-bold text-center text-gray-900 mb-12">
                        Key Features
                    </h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                        {features.map((feature, index) => (
                            <div
                                key={index}
                                className="bg-white p-8 rounded-xl shadow-md hover:shadow-xl transition-all duration-300 transform hover:-translate-y-2 border border-gray-100"
                            >
                                <div className="text-5xl mb-4">{feature.icon}</div>
                                <h3 className="text-xl font-semibold text-gray-900 mb-3">
                                    {feature.title}
                                </h3>
                                <p className="text-gray-600 leading-relaxed">
                                    {feature.description}
                                </p>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    )
}

export default HomePage

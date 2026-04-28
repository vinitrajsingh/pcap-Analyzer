import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import HomePage from './pages/HomePage'
import AnalyzeNetworkPage from './pages/AnalyzeNetworkPage'
import DashboardPage from './pages/DashboardPage'
import GeolocationPage from './pages/GeolocationPage'

function App() {
    return (
        <Router>
            <Routes>
                <Route path="/" element={<HomePage />} />
                <Route path="/analyze" element={<AnalyzeNetworkPage />} />
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/geolocation" element={<GeolocationPage />} />
            </Routes>
        </Router>
    )
}

export default App

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import Header from '../components/Header'

const AnalyzeNetworkPage = () => {
    const [file, setFile] = useState(null)
    const [uploading, setUploading] = useState(false)
    const [error, setError] = useState(null)
    const [success, setSuccess] = useState(false)
    const [dragActive, setDragActive] = useState(false)
    const navigate = useNavigate()

    const handleFileChange = (selectedFile) => {
        if (!selectedFile) return

        // Validate file type
        const validExtensions = ['.pcap', '.pcapng']
        const fileExtension = selectedFile.name.toLowerCase().substring(
            selectedFile.name.lastIndexOf('.')
        )

        if (!validExtensions.includes(fileExtension)) {
            setError('Please upload a valid PCAP file (.pcap or .pcapng)')
            setFile(null)
            return
        }

        // Validate file size (max 100MB)
        const maxSize = 100 * 1024 * 1024 // 100MB
        if (selectedFile.size > maxSize) {
            setError('File size exceeds 100MB limit. Please upload a smaller file.')
            setFile(null)
            return
        }

        setError(null)
        setFile(selectedFile)
        setSuccess(false)
    }

    const handleDrag = (e) => {
        e.preventDefault()
        e.stopPropagation()
        if (e.type === 'dragenter' || e.type === 'dragover') {
            setDragActive(true)
        } else if (e.type === 'dragleave') {
            setDragActive(false)
        }
    }

    const handleDrop = (e) => {
        e.preventDefault()
        e.stopPropagation()
        setDragActive(false)
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            handleFileChange(e.dataTransfer.files[0])
        }
    }

    const handleInputChange = (e) => {
        if (e.target.files && e.target.files[0]) {
            handleFileChange(e.target.files[0])
        }
    }

    const handleUpload = async () => {
        if (!file) {
            setError('Please select a file first')
            return
        }

        setUploading(true)
        setError(null)
        setSuccess(false)

        try {
            const formData = new FormData()
            formData.append('file', file)

            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData,
            })

            const data = await response.json()

            if (!response.ok) {
                throw new Error(data.error || 'Upload failed')
            }

            // Store session_id, summary, and analysis in localStorage for dashboard
            if (data.session_id) {
                localStorage.setItem('current_session_id', data.session_id)
                localStorage.setItem('upload_summary', JSON.stringify(data.summary || {}))
                if (data.analysis) {
                    localStorage.setItem('upload_analysis', JSON.stringify(data.analysis))
                }
                if (data.geolocation) {
                    localStorage.setItem('upload_geolocation', JSON.stringify(data.geolocation))
                }
            }

            setSuccess(true)
            setUploading(false)

            // Navigate to dashboard after successful upload
            setTimeout(() => {
                navigate('/dashboard')
            }, 1500)

        } catch (err) {
            setError(err.message || 'Failed to upload file. Please try again.')
            setUploading(false)
        }
    }

    const handleRemoveFile = () => {
        setFile(null)
        setError(null)
        setSuccess(false)
    }

    const formatFileSize = (bytes) => {
        if (bytes === 0) return '0 Bytes'
        const k = 1024
        const sizes = ['Bytes', 'KB', 'MB', 'GB']
        const i = Math.floor(Math.log(bytes) / Math.log(k))
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-slate-50">
            <Header />

            <div className="container mx-auto px-6 py-12">
                <div className="max-w-3xl mx-auto">
                    {/* Page Header */}
                    <div className="text-center mb-10">
                        <h1 className="text-5xl font-bold text-gray-900 mb-4">
                            Analyze Network Traffic
                        </h1>
                        <p className="text-xl text-gray-600">
                            Upload your PCAP file to begin comprehensive network analysis
                        </p>
                    </div>

                    {/* Upload Card */}
                    <div className="bg-white rounded-2xl shadow-xl p-8 border border-gray-100">
                        {/* File Input Area */}
                        <div className="mb-6">
                            <label className="block text-sm font-semibold text-gray-700 mb-3">
                                Select PCAP File
                            </label>

                            {!file ? (
                                <div
                                    onDragEnter={handleDrag}
                                    onDragLeave={handleDrag}
                                    onDragOver={handleDrag}
                                    onDrop={handleDrop}
                                    className={`border-2 border-dashed rounded-xl p-12 text-center transition-all duration-300 ${dragActive
                                        ? 'border-blue-500 bg-blue-50'
                                        : 'border-gray-300 hover:border-blue-400 hover:bg-gray-50'
                                        }`}
                                >
                                    <input
                                        type="file"
                                        accept=".pcap,.pcapng"
                                        onChange={handleInputChange}
                                        className="hidden"
                                        id="file-upload"
                                    />
                                    <label
                                        htmlFor="file-upload"
                                        className="cursor-pointer flex flex-col items-center"
                                    >
                                        <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                                            <svg
                                                className="w-8 h-8 text-blue-600"
                                                fill="none"
                                                stroke="currentColor"
                                                viewBox="0 0 24 24"
                                            >
                                                <path
                                                    strokeLinecap="round"
                                                    strokeLinejoin="round"
                                                    strokeWidth={2}
                                                    d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                                                />
                                            </svg>
                                        </div>
                                        <span className="text-gray-700 font-semibold text-lg mb-2">
                                            Click to upload or drag and drop
                                        </span>
                                        <span className="text-sm text-gray-500">
                                            PCAP or PCAPNG files only (Max 100MB)
                                        </span>
                                    </label>
                                </div>
                            ) : (
                                <div className="border-2 border-blue-300 rounded-xl p-6 bg-gradient-to-r from-blue-50 to-blue-100">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center space-x-4">
                                            <div className="flex-shrink-0">
                                                <div className="w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center">
                                                    <svg
                                                        className="w-7 h-7 text-white"
                                                        fill="none"
                                                        stroke="currentColor"
                                                        viewBox="0 0 24 24"
                                                    >
                                                        <path
                                                            strokeLinecap="round"
                                                            strokeLinejoin="round"
                                                            strokeWidth={2}
                                                            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                                                        />
                                                    </svg>
                                                </div>
                                            </div>
                                            <div>
                                                <p className="text-base font-semibold text-gray-900">{file.name}</p>
                                                <p className="text-sm text-gray-600 mt-1">
                                                    {formatFileSize(file.size)}
                                                </p>
                                            </div>
                                        </div>
                                        <button
                                            onClick={handleRemoveFile}
                                            className="text-red-600 hover:text-red-700 font-medium text-sm px-4 py-2 rounded-lg hover:bg-red-50 transition-colors"
                                        >
                                            Remove
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Error Message */}
                        {error && (
                            <div className="mb-6 p-4 bg-red-50 border-l-4 border-red-500 rounded-lg">
                                <div className="flex items-center">
                                    <svg className="w-5 h-5 text-red-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                                    </svg>
                                    <p className="text-sm text-red-800 font-medium">{error}</p>
                                </div>
                            </div>
                        )}

                        {/* Success Message */}
                        {success && (
                            <div className="mb-6 p-4 bg-green-50 border-l-4 border-green-500 rounded-lg">
                                <div className="flex items-center">
                                    <svg className="w-5 h-5 text-green-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                                    </svg>
                                    <p className="text-sm text-green-800 font-medium">
                                        File uploaded successfully! Redirecting to dashboard...
                                    </p>
                                </div>
                            </div>
                        )}

                        {/* Upload Button */}
                        <button
                            onClick={handleUpload}
                            disabled={!file || uploading}
                            className="w-full bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 disabled:from-gray-400 disabled:to-gray-500 disabled:cursor-not-allowed text-white font-semibold py-4 px-6 rounded-xl shadow-lg hover:shadow-xl transform hover:scale-[1.02] disabled:hover:scale-100 transition-all duration-200 flex items-center justify-center space-x-2"
                        >
                            {uploading ? (
                                <>
                                    <svg
                                        className="animate-spin h-5 w-5 text-white"
                                        xmlns="http://www.w3.org/2000/svg"
                                        fill="none"
                                        viewBox="0 0 24 24"
                                    >
                                        <circle
                                            className="opacity-25"
                                            cx="12"
                                            cy="12"
                                            r="10"
                                            stroke="currentColor"
                                            strokeWidth="4"
                                        ></circle>
                                        <path
                                            className="opacity-75"
                                            fill="currentColor"
                                            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                                        ></path>
                                    </svg>
                                    <span>Uploading & Analyzing...</span>
                                </>
                            ) : (
                                <>
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                                    </svg>
                                    <span>Upload & Analyze</span>
                                </>
                            )}
                        </button>

                        {/* Info Section */}
                        <div className="mt-8 pt-6 border-t border-gray-200">
                            <h3 className="text-sm font-semibold text-gray-900 mb-4 flex items-center">
                                <svg className="w-5 h-5 text-blue-600 mr-2" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                                </svg>
                                What happens next?
                            </h3>
                            <ul className="space-y-3 text-sm text-gray-600">
                                {[
                                    'Your PCAP file will be parsed using Pyshark',
                                    'Network patterns and statistics will be analyzed with Pandas/NumPy',
                                    'Anomaly detection will identify suspicious activities',
                                    'Geolocation data will be extracted and visualized',
                                    'TCP health metrics and connection issues will be detected',
                                    'A comprehensive dashboard with interactive visualizations will be generated',
                                ].map((item, index) => (
                                    <li key={index} className="flex items-start">
                                        <svg className="w-5 h-5 text-blue-600 mr-2 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                                            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                                        </svg>
                                        <span>{item}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default AnalyzeNetworkPage

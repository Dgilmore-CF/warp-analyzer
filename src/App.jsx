import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
// import JSZip from 'jszip'; // This will be loaded from a CDN
import { FileText, AlertTriangle, CheckCircle, Cpu, WifiOff, ShieldOff, ChevronDown, ChevronRight, Loader, Server } from 'lucide-react';

// --- Utility to load a script dynamically ---
const loadScript = (src) => {
    return new Promise((resolve, reject) => {
        if (document.querySelector(`script[src="${src}"]`)) {
            resolve();
            return;
        }
        const script = document.createElement('script');
        script.src = src;
        script.onload = () => resolve();
        script.onerror = () => reject(new Error(`Script load error for ${src}`));
        document.head.appendChild(script);
    });
};

// --- Utility to wait for a global variable to be ready ---
const waitForGlobal = (variableName, timeout = 5000) => {
    return new Promise((resolve, reject) => {
        const startTime = Date.now();
        const interval = setInterval(() => {
            if (window[variableName]) {
                clearInterval(interval);
                resolve();
            } else if (Date.now() - startTime > timeout) {
                clearInterval(interval);
                reject(new Error(`Library '${variableName}' did not initialize in time.`));
            }
        }, 100);
    });
};


// --- Error Code Database ---
const ERROR_DEFINITIONS = {
    'failed to connect to edge': {
        severity: 'Critical',
        icon: WifiOff,
        title: 'Edge Network Connection Failure',
        description: 'The WARP client could not establish a connection to the nearest Cloudflare data center.',
        recommendation: 'Check your internet connection. Ensure your firewall or antivirus is not blocking Cloudflare WARP. Try restarting the WARP client.'
    },
    'quic_error': {
        severity: 'Critical',
        icon: WifiOff,
        title: 'QUIC Protocol Error',
        description: 'An error occurred with the QUIC protocol, which WARP uses for fast and reliable connections. This can indicate a network-level interference.',
        recommendation: 'Some networks block QUIC. Try switching WARP to TCP-only mode in the settings (Preferences > Connection > Protocol).',
    },
    'dns query failed': {
        severity: 'Warning',
        icon: AlertTriangle,
        title: 'DNS Query Failed',
        description: 'A DNS request sent through the WARP tunnel failed to resolve.',
        recommendation: 'This could be a temporary issue. If it persists, check the specific domain that is failing. Ensure DNS over HTTPS is enabled in your WARP settings.'
    },
    'gateway_policy_block': {
        severity: 'Info',
        icon: ShieldOff,
        title: 'Gateway Policy Block',
        description: 'A network request was blocked by a Cloudflare Gateway policy.',
        recommendation: 'This is expected behavior if your organization uses Gateway to block certain categories of websites. Check your Gateway audit logs for details on which policy was triggered.'
    },
    'another vpn is active': {
        severity: 'Critical',
        icon: Cpu,
        title: 'Conflicting VPN Detected',
        description: 'Another VPN client was detected running on your system. Running multiple VPNs can cause connectivity conflicts.',
        recommendation: 'Disable or uninstall any other VPN software and restart the WARP client.'
    },
    'TCP Retransmission': {
        severity: 'Warning',
        icon: AlertTriangle,
        title: 'High TCP Retransmissions',
        description: 'The packet capture shows a high number of TCP retransmissions, suggesting packet loss or network congestion between your device and the server.',
        recommendation: 'Run a speed test and a traceroute to check for network quality issues. This may not be a WARP-specific problem but a general network health issue.'
    },
    'DNS Timeout': {
        severity: 'Warning',
        icon: AlertTriangle,
        title: 'DNS Query Timeout',
        description: 'Packet capture indicates that DNS queries are timing out. This can cause slow page loads or connection failures.',
        recommendation: 'Ensure your device can reach the configured DNS resolvers (e.g., 1.1.1.1). Check for firewall rules blocking outbound DNS traffic.'
    },
};


// --- UI Components ---
const ProgressBar = ({ value, message }) => {
    return (
        <div style={{ textAlign: 'center' }}>
            <p style={{ marginBottom: '0.5rem', fontSize: '1rem', fontWeight: 600, color: '#374151' }}>{message}</p>
            <div style={{ width: '100%', backgroundColor: '#e5e7eb', borderRadius: '0.5rem', overflow: 'hidden' }}>
                <div 
                    style={{ 
                        width: `${value}%`, 
                        height: '1.5rem', 
                        backgroundColor: '#f97316', 
                        transition: 'width 0.4s ease-in-out',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'white',
                        fontWeight: 'bold',
                        fontSize: '0.875rem'
                    }}
                >
                   {value > 5 && `${Math.round(value)}%`}
                </div>
            </div>
        </div>
    );
};

const LogViewer = ({ fileName, content }) => {
    const [isOpen, setIsOpen] = useState(false);

    const renderColorCodedLine = (line) => {
        const keywordStyles = {
            'DEBUG': { color: '#22c55e' }, // Green
            'WARN': { color: '#f59e0b' },  // Yellow
            'ERROR': { color: '#ef4444' }  // Red
        };
        const regex = /(DEBUG|WARN|ERROR)/g;
        const parts = line.split(regex);

        return parts.map((part, index) => {
            if (keywordStyles[part]) {
                return <span key={index} style={keywordStyles[part]}>{part}</span>;
            }
            return part;
        });
    };
    
    return (
        <div style={{ borderTop: '1px solid #e5e7eb' }}>
            <button
                onClick={() => setIsOpen(!isOpen)}
                style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    width: '100%',
                    padding: '0.75rem 1rem',
                    backgroundColor: '#f9fafb',
                    border: 'none',
                    cursor: 'pointer',
                    fontSize: '0.875rem',
                    color: '#374151',
                    textAlign: 'left',
                }}
            >
                <span>{fileName}</span>
                {isOpen ? <ChevronDown /> : <ChevronRight />}
            </button>
            {isOpen && (
                <pre style={{
                    padding: '1rem',
                    backgroundColor: '#111827',
                    color: '#d1d5db',
                    fontSize: '0.875rem',
                    lineHeight: '1.5',
                    whiteSpace: 'pre-wrap',
                    wordWrap: 'break-word',
                    maxHeight: '300px',
                    overflowY: 'auto',
                    margin: 0,
                }}>
                    {content.split('\n').map((line, i) => (
                        <div key={i}>{renderColorCodedLine(line)}</div>
                    ))}
                </pre>
            )}
        </div>
    );
};

const FileUpload = ({ onFilesUploaded, isProcessing, progress }) => {
    const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop: onFilesUploaded, disabled: isProcessing });
    const baseStyle = { padding: '2rem', border: '4px dashed #d1d5db', borderRadius: '0.75rem', textAlign: 'center', cursor: 'pointer', transition: 'border-color 300ms, background-color 300ms', backgroundColor: '#f9fafb' };
    const activeStyle = { borderColor: '#f97316', backgroundColor: '#fff7ed' };
    const style = isDragActive ? { ...baseStyle, ...activeStyle } : baseStyle;

    return (
        <div {...getRootProps({ style })}>
            <input {...getInputProps()} />
            {isProcessing ? (
                <ProgressBar value={progress.value} message={progress.message} />
            ) : (
                <>
                    <FileText style={{ margin: 'auto', height: '4rem', width: '4rem', color: '#9ca3af' }} />
                    <p style={{ marginTop: '1rem', fontSize: '1.125rem', fontWeight: 600 }}>Drop warp-diag.zip, pcap/pcapng, or log files here</p>
                </>
            )}
        </div>
    );
};

const ReportCard = ({ issue }) => {
    const severityStyles = {
        Critical: { borderLeft: '4px solid #ef4444', backgroundColor: '#fee2e2' },
        Warning: { borderLeft: '4px solid #f59e0b', backgroundColor: '#fef3c7' },
        Info: { borderLeft: '4px solid #3b82f6', backgroundColor: '#dbeafe' },
    };
    const iconColor = { Critical: '#dc2626', Warning: '#d97706', Info: '#2563eb' };
    const Icon = issue.icon;

    return (
        <div style={{ borderRadius: '0 0.5rem 0.5rem 0', padding: '1rem', marginBottom: '1rem', ...severityStyles[issue.severity] }}>
            <div style={{ display: 'flex', alignItems: 'flex-start' }}>
                <Icon style={{ height: '1.5rem', width: '1.5rem', marginRight: '1rem', flexShrink: 0, color: iconColor[issue.severity] }} />
                <div style={{ flexGrow: 1 }}>
                    <h3 style={{ fontWeight: 'bold', fontSize: '1.125rem' }}>{issue.title}</h3>
                    <p style={{ marginTop: '0.25rem' }}>{issue.description}</p>
                    <p style={{ fontSize: '0.875rem', marginTop: '0.5rem' }}><span style={{ fontWeight: '600' }}>Recommendation:</span> {issue.recommendation}</p>
                    {issue.sources && issue.sources.length > 0 && (
                        <p style={{ fontSize: '0.75rem', color: '#4b5563', marginTop: '0.75rem', paddingTop: '0.5rem', borderTop: '1px solid #d1d5db' }}>
                            <span style={{ fontWeight: '600' }}>Source(s):</span> {issue.sources.join(', ')}
                        </p>
                    )}
                </div>
            </div>
        </div>
    );
};

const PcapAnalyzer = ({ pcapFiles, onPcapAnalyzed, setError }) => {
    const [isAnalyzing, setIsAnalyzing] = useState(false);

    const handleAnalysis = async () => {
        setIsAnalyzing(true);
        setError(null);

        // In a real application, you would replace this URL with your actual Worker URL.
        const WORKER_URL = 'pcap-analyzer-worker.dgilmore-lab.workers.dev'; // <-- IMPORTANT: Replace this

        try {
            // Send the first pcap file for analysis. A real app could loop and send all.
            const response = await fetch(WORKER_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/octet-stream' },
                body: pcapFiles[0] 
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Analysis server responded with status: ${response.status}. ${errorText}`);
            }

            const results = await response.json();
            onPcapAnalyzed(results);

        } catch (err) {
            console.error(err);
            // Simulate a result if the worker call fails, to demonstrate UI flow
            const mockResults = [
                { fileName: `simulated-analysis-${pcapFiles[0].name}.txt`, content: `SIMULATED ANALYSIS\nCould not reach the analysis server. This is a mock result.\n\n- Found 15 instances of TCP Retransmission.\n- Found 3 instances of DNS Timeout.\n` }
            ];
            onPcapAnalyzed(mockResults);
            setError("Could not connect to the analysis worker. Displaying simulated results.");
        } finally {
            setIsAnalyzing(false);
        }
    };

    return (
        <div style={{ marginTop: '2rem', padding: '1rem', border: '1px solid #fde68a', backgroundColor: '#fefce8', borderRadius: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center' }}>
                <Server style={{ height: '2rem', width: '2rem', color: '#ca8a04', marginRight: '1rem' }} />
                <div>
                    <h3 style={{ fontWeight: 'bold', fontSize: '1.125rem', color: '#a16207' }}>Packet Capture Files Detected</h3>
                    <p style={{ color: '#854d0e', fontSize: '0.875rem' }}>For performance and security, packet captures (`.pcap`/`.pcapng`) are processed by a secure backend.</p>
                </div>
            </div>
            <ul style={{ listStyleType: 'disc', paddingLeft: '2rem', margin: '1rem 0', color: '#854d0e' }}>
                {pcapFiles.map((file, i) => <li key={i}>{file.name}</li>)}
            </ul>
            <button
                onClick={handleAnalysis}
                disabled={isAnalyzing}
                style={{
                    width: '100%',
                    padding: '0.75rem',
                    border: 'none',
                    borderRadius: '0.5rem',
                    backgroundColor: isAnalyzing ? '#9ca3af' : '#f97316',
                    color: 'white',
                    fontWeight: 'bold',
                    cursor: isAnalyzing ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                }}
            >
                {isAnalyzing && <Loader className="animate-spin" style={{ marginRight: '0.5rem' }} />}
                {isAnalyzing ? 'Analyzing on Secure Server...' : `Analyze ${pcapFiles.length} PCAP File(s)`}
            </button>
        </div>
    );
};

const AnalysisReport = ({ report, logFiles }) => {
    if (!report) return null;

    return (
        <div style={{ marginTop: '2rem' }}>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 'bold', marginBottom: '1rem' }}>Analysis Report</h2>
            {report.length === 0 ? (
                <div style={{ padding: '1.5rem', backgroundColor: '#f0fdf4', borderLeft: '4px solid #22c55e', borderRadius: '0 0.5rem 0.5rem 0'}}>
                    <div style={{ display: 'flex', alignItems: 'center' }}>
                        <CheckCircle style={{ height: '2rem', width: '2rem', color: '#16a34a', marginRight: '1rem' }} />
                        <div>
                            <h2 style={{ fontSize: '1.25rem', fontWeight: 'bold' }}>No Issues Found</h2>
                            <p>Our analysis did not reveal any known common issues.</p>
                        </div>
                    </div>
                </div>
            ) : (
                <>
                    {report.filter(r => r.severity === 'Critical').map(issue => <ReportCard key={issue.id} issue={issue} />)}
                    {report.filter(r => r.severity === 'Warning').map(issue => <ReportCard key={issue.id} issue={issue} />)}
                    {report.filter(r => r.severity === 'Info').map(issue => <ReportCard key={issue.id} issue={issue} />)}
                </>
            )}
            {logFiles.length > 0 && (
                 <div style={{ marginTop: '2rem', border: '1px solid #e5e7eb', borderRadius: '0.5rem' }}>
                    <h3 style={{padding: '0.75rem 1rem', fontWeight: 600, borderBottom: '1px solid #e5e7eb', margin: 0, backgroundColor: '#f9fafb'}}>Log File Breakdown</h3>
                    {logFiles.map((file, index) => <LogViewer key={index} {...file} />)}
                 </div>
            )}
        </div>
    );
};

// --- Main App Component ---
export default function App() {
    const [report, setReport] = useState(null);
    const [logFiles, setLogFiles] = useState([]);
    const [pcapFiles, setPcapFiles] = useState([]);
    const [isProcessing, setIsProcessing] = useState(false);
    const [error, setError] = useState(null);
    const [progress, setProgress] = useState({ value: 0, message: '' });

    const processFiles = async (files) => {
        setIsProcessing(true);
        setProgress({ value: 10, message: 'Reading files...' });
        setReport(null);
        setError(null);
        setLogFiles([]);
        setPcapFiles([]);

        let textLogs = [];
        let pcaps = [];
        
        try {
            await loadScript('https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js');
        } catch(e) {
            setError('Could not load required ZIP library. Please check your internet connection.');
            setIsProcessing(false);
            return;
        }

        for (const file of files) {
            if (file.name.endsWith('.zip')) {
                try {
                    await waitForGlobal('JSZip');
                    const zip = await window.JSZip.loadAsync(file);
                    for (const filePath in zip.files) {
                        const zipEntry = zip.files[filePath];
                        if (zipEntry.dir) continue;

                        if (filePath.endsWith('.pcap') || filePath.endsWith('.pcapng')) {
                            const fileData = await zipEntry.async('blob');
                            const pcapBlobAsFile = new File([fileData], filePath);
                            pcaps.push(pcapBlobAsFile);
                        } else if (filePath.endsWith('.txt') || filePath.endsWith('.log') || filePath.endsWith('.csv')) {
                            const content = await zipEntry.async('string');
                            textLogs.push({ fileName: filePath, content });
                        }
                    }
                } catch (e) {
                    setError(`Failed to process ZIP file: ${e.message}`);
                    setIsProcessing(false);
                    return;
                }
            } else if (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng')) {
                pcaps.push(file);
            } else {
                try {
                    const content = await file.text();
                    textLogs.push({ fileName: file.name, content });
                } catch (e) { /* ignore */ }
            }
        }
        
        setProgress({ value: 50, message: 'Analyzing text logs...' });

        const issuesMap = new Map();
        textLogs.forEach(logFile => {
            const lowerCaseContent = logFile.content.toLowerCase();
            for (const key in ERROR_DEFINITIONS) {
                if (lowerCaseContent.includes(key.toLowerCase())) {
                    if (!issuesMap.has(key)) {
                        issuesMap.set(key, { id: key, ...ERROR_DEFINITIONS[key], sources: new Set() });
                    }
                    issuesMap.get(key).sources.add(logFile.fileName);
                }
            }
        });
        
        const finalReport = Array.from(issuesMap.values()).map(issue => ({...issue, sources: Array.from(issue.sources)}));

        setLogFiles(textLogs);
        setPcapFiles(pcaps);
        setReport(finalReport);
        setIsProcessing(false);
        setProgress({ value: 100, message: 'Done' });
    };
    
    const handlePcapAnalyzed = (pcapResults) => {
        setLogFiles(prevLogs => [...prevLogs, ...pcapResults]);
        
        const issuesMap = new Map();
        report.forEach(r => issuesMap.set(r.id, r));

        pcapResults.forEach(res => {
            const lowerCaseContent = res.content.toLowerCase();
            for (const key in ERROR_DEFINITIONS) {
                if (lowerCaseContent.includes(key.toLowerCase())) {
                    if (!issuesMap.has(key)) {
                        issuesMap.set(key, { id: key, ...ERROR_DEFINITIONS[key], sources: new Set() });
                    }
                    issuesMap.get(key).sources.add(res.fileName);
                }
            }
        });

        const finalReport = Array.from(issuesMap.values()).map(issue => ({...issue, sources: Array.from(issue.sources)}));
        setReport(finalReport);
        setPcapFiles([]); // Clear the PCAP section
    };

    const handleReset = () => {
        setReport(null);
        setError(null);
        setIsProcessing(false);
        setLogFiles([]);
        setPcapFiles([]);
        setProgress({ value: 0, message: '' });
    };

    return (
        <div style={{ backgroundColor: '#f3f4f6', minHeight: '100vh', fontFamily: 'sans-serif', padding: '2rem' }}>
            <div style={{ maxWidth: '896px', margin: 'auto' }}>
                <header style={{ textAlign: 'center', marginBottom: '2rem' }}>
                    <h1 style={{ fontSize: '2.25rem', fontWeight: 800, color: '#1f2937' }}>Cloudflare WARP</h1>
                    <p style={{ fontSize: '1.25rem', color: '#f97316', fontWeight: 600 }}>Diagnostic Analyzer</p>
                </header>

                <main style={{ backgroundColor: 'white', padding: '2rem', borderRadius: '1rem', boxShadow: '0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1)' }}>
                    {error && (
                        <div style={{ padding: '1rem', marginBottom: '1rem', color: '#991b1b', backgroundColor: '#fee2e2', borderRadius: '0.5rem' }}>
                            <span style={{ fontWeight: '600' }}>Error:</span> {error}
                        </div>
                    )}

                    {!report && <FileUpload onFilesUploaded={processFiles} isProcessing={isProcessing} progress={progress} />}
                    
                    {report && pcapFiles.length > 0 && <PcapAnalyzer pcapFiles={pcapFiles} onPcapAnalyzed={handlePcapAnalyzed} setError={setError} />}

                    <AnalysisReport report={report} logFiles={logFiles} />
                    
                    {report && (
                        <div style={{ textAlign: 'center', marginTop: '2rem' }}>
                            <button 
                                onClick={handleReset}
                                style={{ backgroundColor: '#f97316', color: 'white', fontWeight: 'bold', padding: '0.5rem 1.5rem', borderRadius: '0.5rem', border: 'none', cursor: 'pointer' }}
                            >
                                Analyze New Files
                            </button>
                        </div>
                    )}
                </main>
                
                <footer style={{ textAlign: 'center', marginTop: '2rem', fontSize: '0.875rem', color: '#6b7280' }}>
                    <p>This tool performs a basic analysis. For complex problems, refer to official Cloudflare documentation.</p>
                </footer>
            </div>
        </div>
    );
}

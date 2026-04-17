# Cyber-Threat-Intelligence-Using-OSINT-ML
A backend-driven cyber threat intelligence system was developed to combine machine learning models with multiple external threat intelligence APIs for analyzing URLs, executable files, and IP addresses. The system was built using Python with Flask as the backend framework, integrating APIs such as VirusTotal, AbuseIPDB, Shodan, and WhoisXML for enriched threat analysis.

Users interact with the system through a web-based interface, where they can submit URLs, upload files, or input IP addresses for analysis. The backend processes these inputs by performing feature extraction, running machine learning inference for phishing and malware detection, and aggregating API responses into structured outputs for clear interpretation.

Performance and reliability were ensured through server-side input validation, private IP filtering, exception handling, and efficient request handling. The modular architecture supports scalability and is designed to be deployment-ready, with scope for future integration of asynchronous processing and cloud infrastructure, resulting in a 70% reduction in analysis time and significantly improved system responsiveness.

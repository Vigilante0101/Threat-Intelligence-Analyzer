# Threat Intelligence Analyzer

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Description

The Threat Intelligence Analyzer is a user-friendly, Python-based GUI tool designed to simplify the process of investigating potential cyber threats. By leveraging publicly available APIs from reputable threat intelligence platforms like VirusTotal, MalwareBazaar, and ThreatFox, this tool empowers users to quickly analyze Indicators of Compromise (IOCs) and gain valuable insights into potential security risks.

Whether you are a cybersecurity professional, a network administrator, or simply a curious user, this tool provides a convenient way to assess the reputation and threat level associated with:

*   Hash Values: MD5, SHA1, SHA256 hashes of suspicious files.
*   Domain Names: Potentially malicious or unknown domain names.
*   IP Addresses: IP addresses exhibiting suspicious network activity.

## Features

*   Comprehensive IOC Analysis: Analyze three key IOC types: Hash Values, Domain Names, and IP Addresses.
*   Multi-Source Threat Lookup: Queries multiple reputable threat intelligence services:
    *   VirusTotal:  Leverages the extensive scanning and analysis capabilities of VirusTotal.
    *   MalwareBazaar (for Hashes):  Accesses MalwareBazaar's database of malware samples and signatures.
    *   ThreatFox (for Hashes):  Utilizes ThreatFox's real-time threat intelligence platform focused on malware IOCs.
*   Threat Scoring System:  Provides a basic threat score based on the aggregated results from the queried sources, giving a quick indication of potential risk.
*   Detailed Analysis Summary (for Hashes): For hash IOCs, the tool provides a deeper analysis summary, including:
    *   Malware Family Consensus: Identifies the most likely malware family associated with the hash based on detection names.
    *   Behavioral Keywords: Highlights common behavioral keywords associated with the detected threats.
*   Contextual Research Suggestions: Offers relevant research keywords and recommended platforms for further investigation based on the IOC type, guiding users to expand their analysis.
*   Intuitive Graphical User Interface (GUI):  Features a clean and easy-to-use graphical interface built with Tkinter, making threat analysis accessible even to users with limited command-line experience.
*   VirusTotal API Key Input: Securely prompts for and utilizes a user-provided VirusTotal API v3 key, ensuring proper access and usage of the VirusTotal service.

## Prerequisites

Before running the Threat Intelligence Analyzer, ensure you have the following prerequisites in place:

1.  Python 3.x:  Python must be installed on your system. You can download the latest version from [python.org](https://www.python.org/).

2.  Required Python Libraries: Install the necessary Python libraries using `pip`:

    ```bash
    pip install requests tkinter collections
    ```

3.  VirusTotal API v3 Key:  To utilize the VirusTotal lookups, you need a valid VirusTotal API v3 key. You can obtain a free or paid API key by signing up for an account at [virustotal.com](https://www.virustotal.com/).  Please note:  Free API keys have usage limits.

## Usage

1.  Download the Script: Download the `threat_intelligence_analyzer.py` script.

2.  Run the Script: Execute the script from your terminal or command prompt:

    ```bash
    python threat_intelligence_analyzer.py
    ```

3.  Enter VirusTotal API Key: When the application starts, you will be prompted to enter your VirusTotal API v3 key in the designated field at the top of the window.  This is essential for VirusTotal lookups to function.

4.  Select IOC Type: Choose the type of Indicator of Compromise you want to analyze by selecting the appropriate radio button:
    *   Hash Values
    *   Domain Names
    *   IP Addresses

5.  Enter IOC Value:  In the "Enter IoC Value" field, type or paste the IOC you want to investigate (e.g., a hash, domain name, or IP address).

6.  Click "Search": Press the "Search" button to initiate the analysis.

7.  View Results: The results from VirusTotal, MalwareBazaar (if applicable), and ThreatFox (if applicable) will be displayed in the results text area. An "Analysis Summary" section will provide a threat score, consensus, behavioral insights (for hashes), and research suggestions.

8.  "Clear" Button: Use the "Clear" button to clear the IOC input field and the results area for a new analysis.

## Data Sources

This tool relies on the following public threat intelligence APIs:

*   VirusTotal: [https://www.virustotal.com/](https://www.virustotal.com/)
*   MalwareBazaar: [https://mb-api.abuse.ch/](https://mb-api.abuse.ch/)
*   ThreatFox: [https://threatfox.abuse.ch/](https://threatfox.abuse.ch/)

Important Note:  Please respect the terms of service and usage limits of these services.

## Disclaimer

The Threat Intelligence Analyzer is intended for informational and educational purposes only. The analysis and threat scores provided by this tool are based on publicly available threat intelligence data and should not be considered definitive or a substitute for professional security analysis. Always exercise caution and critical thinking when interpreting the results. The developers are not responsible for any misuse or misinterpretation of the information provided by this tool.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions to improve the Threat Intelligence Analyzer are welcome! Please feel free to fork the repository, submit pull requests, or open issues to suggest enhancements or report bugs.

---

Enjoy using the Threat Intelligence Analyzer!

import requests
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog
from collections import Counter

# --- API Keys ---
# VirusTotal API Key - User will be prompted to enter this when the program starts.
# MalwareBazaar and ThreatFox do not require API keys for basic queries.

# --- Functions for Searching Threat Intelligence Sources ---

def search_virustotal(ioc_type, ioc_value, api_key):
    """
    Searches VirusTotal for the given Indicator of Compromise (IoC).

    Args:
        ioc_type (str): Type of IoC ('hash', 'domain', 'ip').
        ioc_value (str): The IoC value to search for.
        api_key (str): VirusTotal API v3 key.

    Returns:
        tuple: A tuple containing:
            - list: Detection results from VirusTotal (or error message).
            - list: List of related IP addresses (for hash lookups, empty otherwise).
            - int: Threat score from VirusTotal.
    """
    if not api_key:
        return ["VirusTotal API key is missing. Please enter it to use VirusTotal."], [], 0

    if ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
    elif ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    else:
        return ["Invalid IoC type"], [], 0

    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    ip_list = []
    score = 0
    if response.status_code == 200:
        data = response.json()
        if ioc_type == "hash":
            malware_families = data["data"]["attributes"].get("last_analysis_results", {})
            detected_by = []
            for engine, result in malware_families.items():
                if result["category"] == "malicious" and result["result"]:
                    detected_by.append(f"{engine}: {result['result']}")
            score = len(detected_by) * 2

            relations_url = f"https://www.virustotal.com/api/v3/files/{ioc_value}/relationships/contacted_ips"
            rel_response = requests.get(relations_url, headers=headers)
            if rel_response.status_code == 200:
                rel_data = rel_response.json()
                for item in rel_data.get("data", []):
                    ip_list.append(item["id"])

            return detected_by if detected_by else ["Not identified in VirusTotal"], ip_list, score
        elif ioc_type in ["domain", "ip"]:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            detected_by = [f"Malicious: {stats.get('malicious', 0)} engines flagged it",
                           f"Suspicious: {stats.get('suspicious', 0)} engines flagged it",
                           f"Undetected: {stats.get('undetected', 0)} engines flagged it",
                           f"Harmless: {stats.get('harmless', 0)} engines flagged it"]
            score = stats.get("malicious", 0) * 2
            return detected_by, ip_list, score
    elif response.status_code == 401:
        return ["VirusTotal API key is invalid or unauthorized."], [], 0
    else:
        return ["Error connecting to VirusTotal or value not found"], [], 0


def search_malwarebazaar(hash_value):
    """
    Searches MalwareBazaar for the given hash value.

    Args:
        hash_value (str): The hash value to search for.

    Returns:
        tuple: A tuple containing:
            - list: MalwareBazaar results (or error message).
            - int: Threat score from MalwareBazaar.
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": hash_value}
    response = requests.post(url, data=data)

    if response.status_code == 200:
        result = response.json()
        if result["query_status"] == "ok":
            malware_family = result["data"][0].get("signature", "Unknown")
            return [f"MalwareBazaar: {malware_family}"], 10
        else:
            return ["Not found in MalwareBazaar"], 0
    else:
        return ["Error connecting to MalwareBazaar"], 0


def search_threatfox(hash_value):
    """
    Searches ThreatFox for the given hash value.

    Args:
        hash_value (str): The hash value to search for.

    Returns:
        tuple: A tuple containing:
            - list: ThreatFox results (or error message).
            - int: Threat score from ThreatFox.
    """
    url = "https://threatfox-api.abuse.ch/api/v1/"
    data = {"query": "search_hash", "hash": hash_value}
    response = requests.post(url, json=data)

    if response.status_code == 200:
        result = response.json()
        if result["query_status"] == "ok" and result["data"]:
            iocs = [f"ThreatFox: {item['ioc_value']} ({item['threat_type']})" for item in result["data"]]
            return iocs, 15
        else:
            return ["Not found in ThreatFox"], 0
    else:
        return ["Error connecting to ThreatFox"], 0


def analyze_results(ioc_type, ioc_value, vt_results, mb_results=None, tf_results=None):
    """
    Analyzes the results from different threat intelligence sources and provides a summary.

    Args:
        ioc_type (str): Type of IoC ('hash', 'domain', 'ip').
        ioc_value (str): The IoC value that was searched.
        vt_results (list): Results from VirusTotal.
        mb_results (list, optional): Results from MalwareBazaar (for hash). Defaults to None.
        tf_results (list, optional): Results from ThreatFox (for hash). Defaults to None.

    Returns:
        tuple: A tuple containing:
            - str: Consensus analysis summary.
            - str: Behavior summary (if applicable).
            - str: Research suggestion.
    """
    all_detections = vt_results + (mb_results or []) + (tf_results or [])
    consensus = ""
    behavior_summary = ""

    if ioc_type == "hash":
        family_counts = Counter()
        behavior_keywords = ["Trojan", "Downloader", "Dropper", "MSOffice", "VBA", "Dridex", "Valyria", "SLoad"]
        behavior_counts = Counter()

        for detection in all_detections:
            detection_lower = detection.lower()
            if "dridex" in detection_lower:
                family_counts["Dridex"] += 1
            if "valyria" in detection_lower:
                family_counts["Valyria"] += 1
            if "sload" in detection_lower:
                family_counts["SLoad"] += 1

            for keyword in behavior_keywords:
                if keyword.lower() in detection_lower:
                    behavior_counts[keyword] += 1

        most_common_family = family_counts.most_common(1)
        consensus = f"Most likely family: {most_common_family[0][0]} (detected by {most_common_family[0][1]} sources)" if most_common_family else "No clear family consensus identified."
        behavior_summary = "Common behaviors: " + ", ".join([f"{k} (mentioned {v} times)" for k, v in behavior_counts.most_common()]) if behavior_counts else "No specific behaviors identified."

    elif ioc_type in ["domain", "ip"]:
        malicious_engines = 0
        for result in vt_results:
            if "Malicious:" in result:
                malicious_engines = int(result.split(":")[1].strip().split(" ")[0])
                break

        if malicious_engines > 0:
            consensus = f"Identified as potentially malicious by {malicious_engines} engines on VirusTotal."
        else:
            consensus = "Not strongly flagged as malicious on VirusTotal."
        behavior_summary = "Further analysis might be needed to understand the context and behavior associated with this IoC."

    research_suggestion = "Search keywords with '{}': VirusTotal, [Other relevant sources for {}]".format(ioc_value, ioc_type.capitalize())
    if ioc_type == "hash":
        research_suggestion = "Search keywords with '{}': MalwareBazaar, FeodoTracker, SSL Blacklist, URLhaus, ThreatFox, TalosIntelligence".format(ioc_value)
    elif ioc_type == "domain":
        research_suggestion = "Search keywords with '{}': Whois, DNS records, URLhaus, VirusTotal, Google Safe Browsing".format(ioc_value)
    elif ioc_type == "ip":
        research_suggestion = "Search keywords with '{}': Shodan, Censys, AbuseIPDB, VirusTotal, GeoIP lookup".format(ioc_value)

    return consensus, behavior_summary, research_suggestion


# --- GUI Functions ---

def search_ioc():
    """
    Main function to handle IOC search based on user input from the GUI.
    Retrieves IOC type, value, and VirusTotal API key, then performs searches
    and displays results in the GUI.
    """
    ioc_type = ioc_type_var.get()
    ioc_value = ioc_entry.get().strip()
    vt_api_key = vt_api_key_entry.get().strip() # Get API key from entry

    total_score = 0

    result_text.delete(1.0, tk.END)  # Clear previous results
    result_text.tag_configure("blue", foreground="blue")
    result_text.tag_configure("red", foreground="red")
    result_text.tag_configure("green", foreground="green")
    result_text.tag_configure("bold", font=("Helvetica", 10, "bold"))

    result_text.insert(tk.END, "Searching...\n\n", "blue")

    vt_results, ip_list, vt_score = search_virustotal(ioc_type, ioc_value, vt_api_key)
    total_score += vt_score
    result_text.insert(tk.END, "VirusTotal Results:\n", ("bold", "blue"))
    for result in vt_results:
        if "Error" in result or "Not identified" in result or "invalid" in result.lower():
            result_text.insert(tk.END, f"- {result}\n", "green")
        else:
            result_text.insert(tk.END, f"- {result}\n", "red")

    if ioc_type == "hash":
        if ip_list:
            result_text.insert(tk.END, "\nRelated IP Addresses:\n", ("bold", "blue"))
            for ip in ip_list:
                result_text.insert(tk.END, f"- {ip}\n", "red")
        else:
            result_text.insert(tk.END, "\nRelated IP Addresses: None found.\n", "green")

        mb_results, mb_score = search_malwarebazaar(ioc_value)
        total_score += mb_score
        result_text.insert(tk.END, "\nMalwareBazaar Results:\n", ("bold", "blue"))
        for result in mb_results:
            if "Not found" in result or "Error" in result:
                result_text.insert(tk.END, f"- {result}\n", "green")
            else:
                result_text.insert(tk.END, f"- {result}\n", "red")

        tf_results, tf_score = search_threatfox(ioc_value)
        total_score += tf_score
        result_text.insert(tk.END, "\nThreatFox Results:\n", ("bold", "blue"))
        for result in tf_results:
            if "Not found" in result or "Error" in result:
                result_text.insert(tk.END, f"- {result}\n", "green")
            else:
                result_text.insert(tk.END, f"- {result}\n", "red")
        analysis_results_data = analyze_results(ioc_type, ioc_value, vt_results, mb_results, tf_results)
    else: # For domain and IP, MalwareBazaar and ThreatFox are not used
        analysis_results_data = analyze_results(ioc_type, ioc_value, vt_results)

    result_text.insert(tk.END, "\nAnalysis Summary:\n", ("bold", "blue"))
    consensus, behavior_summary, research_suggestion = analysis_results_data
    result_text.insert(tk.END, f"- Threat Score: {total_score}/100\n", "red" if total_score > 50 else "green")
    result_text.insert(tk.END, f"- {consensus}\n", "red" if "malicious" in consensus.lower() or "family" in consensus.lower() else "green")
    result_text.insert(tk.END, f"- {behavior_summary}\n", "red" if behavior_summary else "green")
    result_text.insert(tk.END, f"- {research_suggestion}\n", "blue")


def clear_results():
    """
    Clears the IOC entry field and the results text area in the GUI.
    """
    ioc_entry.delete(0, tk.END)
    result_text.delete(1.0, tk.END)


# --- GUI Setup ---

root = tk.Tk()
root.title("Threat Intelligence Analyzer")
root.geometry("800x750") # Adjusted height
root.configure(bg="#f0f0f0")

# VirusTotal API Key Input at the Top
api_key_frame = tk.Frame(root, bg="#f0f0f0")
api_key_frame.pack(pady=5)
tk.Label(api_key_frame, text="VirusTotal API Key:", bg="#f0f0f0", font=("Arial", 10)).grid(row=0, column=0, padx=5, sticky="e")
vt_api_key_entry = tk.Entry(api_key_frame, width=40, font=("Arial", 10), show="*") # Show "*" for security
vt_api_key_entry.grid(row=0, column=1, padx=5, sticky="w")
vt_api_key_entry.focus_set() # Focus on API key entry when starting

# Input Frame
input_frame = tk.Frame(root, bg="#f0f0f0")
input_frame.pack(pady=10)

# IOC Type Selection
tk.Label(input_frame, text="Choose IoC Type:", bg="#f0f0f0", font=("Arial", 12)).grid(row=0, column=0, padx=5)
ioc_type_var = tk.StringVar(value="hash")
ioc_types = [("Hash Values", "hash"), ("Domain Names", "domain"), ("IP Addresses", "ip")]
for i, (text, value) in enumerate(ioc_types):
    tk.Radiobutton(input_frame, text=text, variable=ioc_type_var, value=value, bg="#f0f0f0", font=("Arial", 10)).grid(row=0, column=i+1, padx=5)

# IOC Input
tk.Label(input_frame, text="Enter IoC Value:", bg="#f0f0f0", font=("Arial", 12)).grid(row=1, column=0, pady=5)
ioc_entry = tk.Entry(input_frame, width=50, font=("Arial", 10))
ioc_entry.grid(row=1, column=1, columnspan=3, pady=5)

# Buttons Frame
button_frame = tk.Frame(root, bg="#f0f0f0")
button_frame.pack(pady=10)
search_button = tk.Button(button_frame, text="Search", command=search_ioc, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
search_button.grid(row=0, column=0, padx=5)
clear_button = tk.Button(button_frame, text="Clear", command=clear_results, bg="#f44336", fg="white", font=("Arial", 10, "bold"))
clear_button.grid(row=0, column=1, padx=5)

# Results Display
result_text = scrolledtext.ScrolledText(root, width=80, height=35, wrap=tk.WORD, font=("Arial", 10)) # Adjusted height
result_text.pack(pady=10, padx=10)

root.mainloop()
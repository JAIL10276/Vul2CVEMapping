import requests
import torch
import json

NVD_API_KEY = '8f81605b-4562-4c96-acf4-fda182ecaa2f'  # Replace with your actual NVD API key
HEADERS={"apiKey": NVD_API_KEY}
from sentence_transformers import SentenceTransformer, util

model= SentenceTransformer('all-MiniLM-L6-v2')

with open("C:/Users/ayujo/SPRING 2025/IST 402/CVECodeExtrator/nvdcve-1.1-modified.json", 'r') as f:
    nvd_schema=json.load(f)

cve_ids = []
cve_descs = []
cvss_scores = []

for item in nvd_schema["CVE_Items"]:
    try:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description = item["cve"]["description"]["description_data"][0]["value"]
        score = item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
        cvss_scores.append(score)
    except:
        continue

    print("🔃 Embedding all CVE descriptions...")
    cve_embeddings = model.encode(cve_descs, convert_to_tensor=True)
    print("🔍 Searching for CVE descriptions...")

def match_cve(vul, top_n=3):
    if not vul or not isinstance(vul, str) or vul.strip() == "":
        return [{"cve_id": "invalid input", "score": 0.0, "cvss": "N/A", "description": ""}]
    
    query_embedding = model.encode(vul, convert_to_tensor=True)

    cos_scores = util.pytorch_cos_sim(query_embedding, cve_embeddings)[0]
    top_results = torch.topk(cos_scores, k=top_n)

    results=[]
    for score, index in zip(top_results[0], top_results[1]):
        results.append({
            "cve_id": cve_ids[index],
            "score": round(score.item(), 4),
            "cvss": cvss_scores[index],
            "description": cve_descs[index]
        })
    return results



def search_cve(query, max_results=3):
    url=f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params={
        "keywordSearch": query,
        "resultsPerPage": max_results,
    }

    try:
        response=requests.get(url, headers=HEADERS, params=params)
        print(f"Response status code: {response.status_code}")
        print(f"Response content: {response.text[:300]}")
        if response.status_code != 200:
            raise ValueError(f"Error: {response.status_code} - {response.text}")
        data= response.json()

        results=[]
        for item in data.get("Vulnerabilities", []):
            cve = item["cve"]
            cve_id = cve["id"]
            description = cve["descriptions"][0]["value"]


            score=(
                cve.get("metrics",{})
                .get("cvssMetricV31",[{}])[0]
                .get("cvssData",{})
                .get("baseScore", None)
            )

            if score is None:
                score = (
                    cve.get("metrics", {})
                    .get("cvssMetricV30", [{}])[0]
                    .get("cvssData", {})
                    .get("baseScore", None)
                )

            # Fallback to CVSS v2
            if score is None:
                score = (
                    cve.get("metrics", {})
                    .get("cvssMetricV2", [{}])[0]
                    .get("cvssData", {})
                    .get("baseScore", "N/A")
                )
            results.append((cve_id, description, score))
        return results
    except Exception as e:
        print(f"Error fetching CVE data: {e}")
        return []

import pandas as pd
import time
input_file= 'C:/Users/ayujo/SPRING 2025/IST 402/CVECodeExtrator/Simplified_Vulnerabilities.xlsx'
rsg2_df = pd.read_excel(input_file, sheet_name=None)

results_by_domain = {}

for domain, df in rsg2_df.items():
    print(f"Processing sheet: {domain}")

    if "Vulnerabilities" not in df.columns:
        print(f"No 'Vulnerabilities' column found in sheet: {domain}")
        continue

    cve_ids, cve_descs, cvss_scores = [], [], []

    for index in range(len(df)):
        try:
            #device = str(df.at[index, "Device Name"]) if pd.notna(df.at[index, "Device Name"]) else ""
            #summary = str(df.at[index, "Vulnerabilities"]) if pd.notna(df.at[index, "Vulnerabilities"]) else ""
            #if summary == "Summary Failed":
            #raise ValueError("Missing Summary, Skipping CVE search")
            df["Extracted Keywords"]=df["Vulnerabilities"].astype(str).apply(extract_keywords)
            device = str(df.at[index, "Device Name"]) if pd.notna(df.at[index, "Device Name"]) else ""
            query = f"{device} {df.at[index, "Extracted Keywords"]}"
            
            print(f"Querying NVD API for: {query}") 
 
            cves=search_cve(query)
            if cves:
                cve_id, cve_desc, cvss_score = cves[0]
                print(f"Current query:{cves[0]}")
            else:
                cve_id, cve_desc, cvss_score = "No CVE Found", "No Description", "N/A"
        except Exception as e:
            print(f"Error processing row {index}: {e} | query: {query}")
            cve_id, cve_desc, cvss_score = "", "", ""
        cve_ids.append(cve_id)
        cve_descs.append(cve_desc)
        cvss_scores.append(cvss_score)

        time.sleep(1)  # To avoid hitting the API rate limit
    # Add the results to the DataFrame
    df["CVE ID"] = cve_ids
    df["CVE Description"] = cve_descs
    df["CVSS Score"] = cvss_scores
    #df["Severity"]= df["CVSS Score"].apply(lambda score: "Unknown" if score == "N/A" else "Critical" if score >= 9.0 else "High" if score >= 7.0 else "Medium" if score >= 4.0 else "Low" if score >= 0.0 else "None")
    # Store updated DataFrame
    results_by_domain[domain] = df
with pd.ExcelWriter('C:/Users/ayujo/SPRING 2025/IST 402/CVECodeExtrator/Vuls_to_CVE_Results.xlsx') as writer:
    for domain, df in results_by_domain.items():
        df.to_excel(writer, sheet_name=domain, index=False)
print(f"✅ All domains processed and saved to 'Vuls_to_CVE_Results.xlsx'")
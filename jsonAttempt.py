import requests
import torch
import json
import pandas as pd
import time
input_file= 'C:/Users/ayujo/SPRING 2025/IST 402/CVECodeExtrator/Research Goal 2.xlsx'
rsg2_df = pd.read_excel(input_file, sheet_name=None)
NVD_API_KEY = '8f81605b-4562-4c96-acf4-fda182ecaa2f'  # Replace with your actual NVD API key
HEADERS={"apiKey": NVD_API_KEY}
from sentence_transformers import SentenceTransformer, util

model= SentenceTransformer('all-MiniLM-L6-v2')

with open("C:/Users/ayujo/SPRING 2025/IST 402/CVECodeExtrator/nvdcve-1.1-modified.json", 'r', encoding="utf-8") as f:
    nvd_schema=json.load(f)

cve_ids = []
cve_descs = []
cvss_scores = []

for item in nvd_schema["CVE_Items"]:
    try:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description = item["cve"]["description"]["description_data"][0]["value"]
        score = item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
        
        cve_ids.append(cve_id)
        cve_descs.append(description)
        cvss_scores.append(score)
    except:
        continue

print("🔃 Embedding all CVE descriptions...")
cve_embeddings = model.encode(cve_descs, convert_to_tensor=True)

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

def map_cve_to_vul():
    results_by_domain = {}

    for domain, df in rsg2_df.items():
        print(f"📃 Processing sheet: {domain}")

        if "Vulnerabilities" not in df.columns:
            print(f"❗Skipping sheet {domain}'Vulnerabilities' column found in sheet: {domain}")
            continue
        
        matched_cve_ids = []
        matched_cve_descs = []
        matched_cvss_scores = []

        for index in range(len(df)):
            try:
                
                vul_text = str(df.at[index,"Vulnerabilities"]) if pd.notna(df.at[index,"Vulnerabilities"]) else ""
                if vul_text.strip() == "" or vul_text == "Summary Failed":
                    raise ValueError("Invalid vulnerability text")

                matches = match_cve(vul_text, top_n=3)
                best = matches[0] if matches else {"cve_id": "invalid input", "description": "", "cvss": "N/A", "score": 0.0}
                
                matched_cve_ids.append(best["cve_id"])
                matched_cve_descs.append(best["description"])
                matched_cvss_scores.append(best["cvss"])
                print(f"Row {index}: Matched CVE ID: {best['cve_id']}, Description: {best['description']}, CVSS: {best['cvss']}")

            except Exception as e:
                print(f"❗Error processing row {index} in sheet {domain}: {e}")
                matched_cve_ids.append("")
                matched_cve_descs.append("")
                matched_cvss_scores.append("")

        df["Matched CVE ID"] = matched_cve_ids
        df["Matched CVE Description"] = matched_cve_descs
        df["Matched CVSS"] = matched_cvss_scores

        results_by_domain[domain] = df
        print(f"✅ Finished processing sheet: {domain}")

    output_path = "C:/Users/ayujo/SPRING 2025/IST 402/CVECodeExtrator/matched_cve_results.xlsx"

    with pd.ExcelWriter(output_path) as writer:
        for domain, df in results_by_domain.items():
            df.to_excel(writer, sheet_name=domain, index=False)
            print(f"✅ Saved results for sheet: {domain}")

    print(f"✅ All results saved to {output_path}")

if __name__ == "__main__":
    start_time = time.time()
    map_cve_to_vul()
    end_time = time.time()
    print(f"✅ Total processing time: {end_time - start_time:.2f} seconds")
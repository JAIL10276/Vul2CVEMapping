import requests
import torch
import json
import pandas as pd
import time
input_file= 'C:/Users/ayujo/SPRING 2025/IST 402/CVEExtractor/Vul2CVEMapping/Research Goal 2.xlsx'
print(f"🔃Loading File: {input_file}")
rsg2_df = pd.read_excel(input_file, sheet_name=None)
from sentence_transformers import SentenceTransformer, util
print(f"🔃Loading Ai Model🤖")
model= SentenceTransformer('all-MiniLM-L6-v2')
print("⚙️Parsing NVD Json Schema")
with open("C:/Users/ayujo/SPRING 2025/IST 402/CVEExtractor/Vul2CVEMapping/nvdcve-1.1-modified.json", 'r', encoding="utf-8") as f:
    nvd_schema=json.load(f)
print("✅Schema Loaded!")
cve_ids = []
cve_descs = []
cvss_scores = []
advisories=[]
for item in nvd_schema["CVE_Items"]:
    try:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description = item["cve"]["description"]["description_data"][0]["value"]
        score = item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
        advisory = item["cve"]["references"]["reference_data"][0]["url"]
        print(f"Check potential bug: {advisory}")
        
        cve_ids.append(cve_id)
        cve_descs.append(description)
        cvss_scores.append(score)
        advisories.append(advisory)
    except:
        continue

print("🔃 Embedding all CVE descriptions...")
cve_embeddings = model.encode(cve_descs, convert_to_tensor=True)

def match_cve(vul, top_n=3):
    if not vul or not isinstance(vul, str) or vul.strip() == "":
        return [{"cve_id": "invalid input", "score": 0.0, "cvss": "N/A", "description": "", "advisory": ""}]
    
    query_embedding = model.encode(vul, convert_to_tensor=True)
    print(f"📈Evaluating Query Matches")
    cos_scores = util.pytorch_cos_sim(query_embedding, cve_embeddings)[0]
    top_results = torch.topk(cos_scores, k=top_n)
    print(f"✅ Query Matches Evaluated!")
    results=[]
    for score, index in zip(top_results[0], top_results[1]):
        results.append({
            "cve_id": cve_ids[index],
            "score": round(score.item(), 4),
            "cvss": cvss_scores[index],
            "description": cve_descs[index],
            "advisory": advisories[index]
        })
    return results

def map_cve_to_vul():
    results_by_domain = {}

    for domain, df in rsg2_df.items():
        print(f"📃 Processing Domain: {domain}")

        if "Vulnerabilities" not in df.columns:
            print(f"❗Skipping sheet {domain}'Vulnerabilities' column not found in sheet: {domain}")
            print(f"Current columns {df.columns.to_list()}")
            continue
        
        matched_cve_ids = []
        matched_cve_descs = []
        matched_cvss_scores = []
        matched_Advisory= []

        for index in range(len(df)):
            try:
                
                vul_text = str(df.at[index,"Vulnerabilities".strip( )]) if pd.notna(df.at[index,"Vulnerabilities".strip( )]) else ""
                device_name = str(df.at[index, "Device Name".strip( )]) if pd.notna(df.at[index, "Device Name".strip( )]) else ""
                if vul_text.strip() == "" or vul_text == "Summary Failed":
                    raise ValueError("Invalid vulnerability text or White Space")

                matches = match_cve(f"{device_name}{vul_text}", top_n=3)
                best = matches[0] if matches else {"cve_id": "invalid input", "description": "", "cvss": "N/A", "score": 0.0}
                
                matched_cve_ids.append(best["cve_id"])
                matched_cve_descs.append(best["description"])
                matched_cvss_scores.append(best["cvss"])
                matched_Advisory.append(best["advisory"])
                print(f"Row {index}: Matched CVE ID: {best['cve_id']}, Description: {best['description']}, CVSS: {best['cvss']}, Advisory: {best['advisory']}")

            except Exception as e:
                print(f"❗Error processing row {index} in sheet {domain}: {e}")
                matched_cve_ids.append("")
                matched_cve_descs.append("")
                matched_cvss_scores.append("")
                matched_Advisory.append("")

        df["Matched CVE ID"] = matched_cve_ids
        df["Matched CVE Description"] = matched_cve_descs
        df["Matched CVSS"] = matched_cvss_scores
        df["Advisory"] = matched_Advisory

        results_by_domain[domain] = df
        print(f"✅ Finished processing sheet: {domain}")

    output_path = "C:/Users/ayujo/SPRING 2025/IST 402/CVEExtractor/Vul2CVEMapping/matched_cve_results_with_device_name.xlsx"

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
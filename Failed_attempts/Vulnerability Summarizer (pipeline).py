# NVD API Key: 8f81605b-4562-4c96-acf4-fda182ecaa2f  
import pandas as pd
from transformers import pipeline
def load_model():
    # Load the API key from the environment variable
    return pipeline("summarization", model="facebook/bart-large-cnn")
# load the Excel file with multiple sheets
df = pd.read_excel('C:/Users/ayujo/SPRING 2025/IST 402/CVECodeExtrator/Research Goal 2.xlsx', sheet_name=None)
# define the Cohere Ai using a Cohere API key
summarizer = load_model()

# Simplify the vulnerability text using Cohere's summarization model
# This function takes a string of text and returns a simplified version of it
# This will be used to query CEV IDs with the NVD API.
def simplify_Vuln(text):
    try:

        # Use the Cohere API to summarize the text
        summary = summarizer(text, max_length=50, min_length=25, do_sample=False)
        return summary[0]['summary_text']
    
    except Exception as e:

        print(f"Error simplifying text: {e}")
        return "Summary Failed"
    
    except Exception as e:
        print(f"Error simplifying text: {e}")
        return "Summary Failed"
    
summarized_sheets={}
for domain, df in df.items():
    if "Vulnerabilities" in df.columns:
        print(f"Processing sheet: {domain}")
        # Create a new column for the simplified vulnerability text
        df['Device Name']= df['Device Name'].astype(str)
        df['Simplified_Vulnerability'] = df['Vulnerabilities'].apply(simplify_Vuln)
        
        summarized_sheets[domain] = df
    else:
        print(f"No 'Vulnerabilities' column found in sheet: {domain}")
# Save the summarized sheets to a new Excel file
with pd.ExcelWriter('C:/Users/ayujo/SPRING 2025/IST 402/CVECodeExtrator/Simplified_Vulnerabilities.xlsx') as writer:
    for domain, df in summarized_sheets.items():
        df.to_excel(writer, sheet_name=domain, index=False)
        
print(f"✅Done saving to {'Simplified_Vulnerabilities.xlsx'}")
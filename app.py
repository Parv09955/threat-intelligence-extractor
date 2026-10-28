import streamlit as st
import pandas as pd

from extractor import extract_indicators

st.set_page_config(
    page_title="NLP PROJECT | Threat Intelligence Extractor",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Automated Threat Intelligence Extractor")
st.write(
    "An NLP-based application that automatically extracts and categorises cybersecurity entities, "
    "such as IP addresses, CVE identifiers, malware families, and threat actor names, "
    "from unstructured security reports using Named Entity Recognition (NER), "
    "regular expressions, and rule-based text processing. "
    "The extracted information is presented in a structured format for "
    "simplified threat intelligence analysis."
)

sample_text = """"""

text = st.text_area(
    "Enter a cybersecurity report:",
    value=sample_text,
    height=220
)

if st.button("Extract Indicators", type="primary"):
    if not text.strip():
        st.warning("Please enter a report first.")
    else:
        indicators = extract_indicators(text)

        if indicators:
            df = pd.DataFrame(indicators)

            st.subheader("Extraction Results")

            col1, col2 = st.columns(2)
            col1.metric("Total entities", len(df))
            col2.metric(
                "Unique categories",
                df["Category"].nunique()
            )

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True
            )

            st.subheader("Category Summary")
            summary = (
                df["Category"]
                .value_counts()
                .rename_axis("Category")
                .reset_index(name="Count")
            )

            st.bar_chart(
                summary.set_index("Category")
            )

            csv_data = df.to_csv(index=False).encode("utf-8")

            st.download_button(
                "Download Results as CSV",
                data=csv_data,
                file_name="threat_indicators.csv",
                mime="text/csv"
            )
        else:
            st.info("No supported indicators were found.")

st.caption(
    "This is an Educational Prototype. The extracted entities are not "
    "individually identified as a threat to cybersecurity."
)
st.caption(
    "Made by Dhyeya Choksi (23BIT055) and Parv Naik (23BIT056)."
)

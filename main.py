import yaml
import bcrypt
import pandas as pd
import spacy
import streamlit as st
import json
import os
import plotly.express as px
import pyzipper
from wordcloud import WordCloud
import meilisearch
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv
from auth import load_auth_config, get_authenticator

st.set_page_config(page_title="Entity Detection", layout="wide")
UPLOAD_DIR = "tmp/uploads"
METADATA_FILE = "uploaded_files.json"
os.makedirs(UPLOAD_DIR, exist_ok=True)

config = load_auth_config()
authenticator = get_authenticator(config)

if st.session_state.get("authentication_status") != True:
    register_tab = st.sidebar.checkbox("New user? Register here")
else:
    register_tab = False

if register_tab:
    st.title("Register New User")
    new_name = st.text_input("Full Name", key="name")
    new_username = st.text_input("Username", key="username")
    new_email = st.text_input("Email", key="email")
    new_password = st.text_input("Password", type="password", key="password")
    confirm_password = st.text_input("Confirm Password", type="password", key="password_2")

    if st.button("Register"):
        if new_password != confirm_password:
            st.error(" Passwords do not match.")
        elif not new_username or not new_password or not new_name:
            st.error(" Please fill in all required fields.")
        else:
            hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            with open("config.yaml", "r") as file:
                config_data = yaml.safe_load(file)
            if new_username in config_data["credentials"]["usernames"]:
                st.error(" Username already exists.")
            else:
                config_data["credentials"]["usernames"][new_username] = {
                    "name": new_name, "email": new_email, "password": hashed_pw
                }
                with open("config.yaml", "w") as file:
                    yaml.safe_dump(config_data, file)
                st.success(" Registered successfully! Please uncheck 'Register here' and log in.")
    st.stop()

# Auth
authenticator.login()
name = st.session_state.get("name")
authentication_status = st.session_state.get("authentication_status")
username = st.session_state.get("username")

if authentication_status is None:
    st.warning("Please enter your username and password.")
elif authentication_status is False:
    st.error("Username or password is incorrect.")

if authentication_status:

    st.sidebar.subheader(f"Hello, {name}!")
    authenticator.logout("Logout", "sidebar")


    def clean_old_files():
        if os.path.exists(METADATA_FILE):
            with open(METADATA_FILE, "r") as f:
                uploads = json.load(f)
        else:
            uploads = {}

        to_delete = []
        for fname, meta in uploads.items():
            uploaded_time = datetime.fromtimestamp(meta["timestamp"])
            if datetime.now() - uploaded_time > timedelta(hours=4):
                file_path = os.path.join(UPLOAD_DIR, fname)
                if os.path.exists(file_path):
                    os.remove(file_path)
                to_delete.append(fname)

        for fname in to_delete:
            uploads.pop(fname)

        with open(METADATA_FILE, "w") as f:
            json.dump(uploads, f)


    clean_old_files()

    st.title(" Welcome to the Dashboard")
    st.markdown(f"Hello **{name}**, please proceed by uploading your dataset below.")

    with st.expander(" Upload Data & Select Engine", expanded=True):

        uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])
        if uploaded_file:
            ts = int(time.time())
            filename = f"{ts}_{uploaded_file.name}"
            file_path = os.path.join(UPLOAD_DIR, filename)

            with open(file_path, "wb") as f:
                f.write(uploaded_file.read())

            # Track uploaded file
            if os.path.exists(METADATA_FILE):
                with open(METADATA_FILE, "r") as f:
                    uploads = json.load(f)
            else:
                uploads = {}

            uploads[filename] = {"timestamp": ts}
            with open(METADATA_FILE, "w") as f:
                json.dump(uploads, f)

            df = pd.read_csv(file_path)
            st.success(f" Uploaded file: {uploaded_file.name}")


            def infer_engine_from_schema(df):
                text_cols = {'text'}
                tabular_cols = {'fname', 'lname', 'email', 'phone', 'address', 'cc_number'}

                cols = set(df.columns.str.lower())

                if text_cols & cols:
                    return "Descriptive Data"
                elif tabular_cols & cols:
                    return "Tabular Data"
                else:
                    return None


            suggested_engine = infer_engine_from_schema(df)

            if suggested_engine:
                st.info(f" Suggested Detection Engine: **{suggested_engine}** based on file structure.")
                detection_engine = st.radio("Select Detection Engine", ["Tabular Data", "Descriptive Data"],
                                            index=["Tabular Data", "Descriptive Data"].index(suggested_engine))
            else:
                st.warning(" Could not determine engine automatically. Please select manually.")
                detection_engine = st.radio("Select Detection Engine", ["Tabular Data", "Descriptive Data"])

        else:
            st.warning("Upload a CSV file to begin detection.")
            st.stop()
        # spacy model trf
        nlp = spacy.load("en_core_web_trf")
        # Meilisearch
        load_dotenv()
        client = meilisearch.Client(os.getenv("CLIENT"), os.getenv("SSD_KEY"))
        try:
            client.get_index("pii_hii_data")
        except meilisearch.errors.MeilisearchApiError:
            client.create_index("pii_hii_data", {"primaryKey": "id"})
        index = client.index("pii_hii_data")

        processed_data_path = 'processed_pii_hii_data.json'
        pii_df, hii_df = pd.DataFrame(), pd.DataFrame()

        st.title("Entity Detection Dashboard")
        st.markdown(f"### Welcome, {name}")
        pii_df = pd.DataFrame(st.session_state.get('pii', []))
        hii_df = pd.DataFrame(st.session_state.get('hii', []))

        all_types = []

        if not pii_df.empty and 'Type' in pii_df.columns:
            all_types += pii_df['Type'].dropna().astype(str).unique().tolist()

        if not hii_df.empty and 'Type' in hii_df.columns:
            all_types += hii_df['Type'].dropna().astype(str).unique().tolist()

        all_types = sorted(set(all_types))
        detection_types = []
        if not pii_df.empty and 'Type' in pii_df.columns:
            detection_types += pii_df['Type'].dropna().astype(str).unique().tolist()
        if not hii_df.empty and 'Type' in hii_df.columns:
            detection_types += hii_df['Type'].dropna().astype(str).unique().tolist()
        detection_types = sorted(set(detection_types))

        # ZIP encryption password
        zip_password = st.sidebar.text_input("ZIP Encryption Password", type="password")
        RISK_SCORES = {
            "EMAIL": 2,
            "PHONE": 2,
            "CREDIT_CARD": 5,
            "ADDRESS": 3,
            "ID": 4,
            "NAME": 1,
            "BLOOD_TYPE": 1,
            "WEIGHT": 1,
            "HEIGHT": 1,
            "ALLERGIES": 2,
            "MEDICAL_CONDITIONS": 4,
            "MEDICATIONS": 3,
            "DOCTOR": 2,
            "HOSPITAL": 2,
            "INSURANCE": 3
        }

        # Dual Detection Sections
        st.subheader("Dataset Preview")
        st.write(df.head(20))


        def classify_entity_type(spacy_label):
            mapping = {
                'PERSON': 'Person',
                'ORG': 'Company',
                'EMAIL': 'Contact',
                'PHONE': 'Contact',
                'GPE': 'Location',
                'LOC': 'Location',
                'DATE': 'Time',
                'TIME': 'Time',
                'MONEY': 'Financial',
                'FAC': 'Other',
                'NORP': 'Other',
                'PRODUCT': 'Other'
            }
            return mapping.get(spacy_label, 'Unknown')


        def detect_rule_based(row):
            pii_data, hii_data = [], []
            try:
                pii_data.append((str(row.get('id', '')), 'ID'))
                pii_data.append((f"{row.get('fname', '')} {row.get('lname', '')}", 'NAME'))
                pii_data.append((row.get('email', ''), 'EMAIL'))
                pii_data.append((row.get('phone', ''), 'PHONE'))
                pii_data.append((
                                f"{row.get('address', '')}, {row.get('city', '')}, {row.get('state', '')} {row.get('zip', '')}",
                                'ADDRESS'))
                pii_data.append((row.get('cc_number', ''), 'CREDIT_CARD'))
                hii_data.append((row.get('blood_type', ''), 'BLOOD_TYPE'))
                hii_data.append((row.get('weight_kg', ''), 'WEIGHT'))
                hii_data.append((row.get('height_cm', ''), 'HEIGHT'))
                hii_data.append((row.get('allergies', ''), 'ALLERGIES'))
                hii_data.append((row.get('medical_conditions', ''), 'MEDICAL_CONDITIONS'))
                hii_data.append((row.get('medications', ''), 'MEDICATIONS'))
                hii_data.append((row.get('doctor_name', ''), 'DOCTOR'))
                hii_data.append((row.get('hospital_name', ''), 'HOSPITAL'))
                hii_data.append((row.get('insurance_provider', ''), 'INSURANCE'))
            except:
                pass
            return pii_data, hii_data


        def detect_ner(text):
            doc = nlp(text)
            return [(ent.text, ent.label_) for ent in doc.ents]


        def infer_detection_title(entity_types):
            entity_types = set(entity_types)

            categories = {
                "PII": {'EMAIL', 'PHONE', 'CREDIT_CARD', 'ADDRESS', 'ID', 'NAME'},
                "HII": {'BLOOD_TYPE', 'WEIGHT', 'HEIGHT', 'ALLERGIES', 'MEDICAL_CONDITIONS', 'MEDICATIONS', 'DOCTOR',
                        'HOSPITAL', 'INSURANCE'},
                "Contact Info": {'EMAIL', 'PHONE'},
                "Demographics": {'GPE', 'LOC', 'ZIP', 'COUNTRY', 'STATE', 'CITY'},
                "Identity": {'PERSON'},
                "Organizations": {'ORG', 'FAC', 'PRODUCT'},
                "Finance": {'MONEY'},
            }
            matched_labels = []
            for label, ents in categories.items():
                if any(ent in entity_types for ent in ents):
                    matched_labels.append(label)

            if not matched_labels:
                return "Uncategorized Entities"

            return " & ".join(sorted(set(matched_labels)))

    if st.button("Run Detection"):
        with st.spinner("Processing..."):
            pii_flat, hii_flat = [], []
            progress = st.progress(0)
            total_rows = len(df)


            def compute_risk_scores(detected_pii, detected_hii):
                risk_scores = []
                for i in range(len(detected_pii)):
                    score = 0
                    for ent, etype in detected_pii[i] + detected_hii[i]:
                        score += RISK_SCORES.get(etype.upper(), 1)
                    risk_scores.append(score)
                return risk_scores


            if detection_engine == "Tabular Data":
                required_cols = ['fname', 'lname', 'email', 'phone']
                if not any(col in df.columns for col in required_cols):
                    st.error("Required columns for tabular detection are missing.")
                    st.stop()

                detected_pii, detected_hii = [], []
                for i, row in enumerate(df.to_dict(orient="records")):
                    pii, hii = detect_rule_based(row)
                    detected_pii.append(pii)
                    detected_hii.append(hii)
                    progress.progress((i + 1) / total_rows)

                pii_flat = [item for sublist in detected_pii for item in sublist if item[0]]
                hii_flat = [item for sublist in detected_hii for item in sublist if item[0]]
                df["Risk_Score"] = compute_risk_scores(detected_pii, detected_hii)

            elif detection_engine == "Descriptive Data":
                if 'text' not in df.columns:
                    st.error("Missing 'text' column for descriptive NER detection.")
                    st.stop()

                df = df[df['text'].notna()].copy()  # Filter rows directly on df to maintain row index match
                df['text'] = df['text'].astype(str)
                detected_pii = []
                for i, text in enumerate(df['text']):
                    ents = detect_ner(text)
                    detected_pii.append(ents)
                    progress.progress((i + 1) / len(df))

                pii_flat = [item for sublist in detected_pii for item in sublist if item[0]]
                df["Risk_Score"] = [
                    sum(RISK_SCORES.get(ent_type.upper(), 1) for _, ent_type in ents)
                    for ents in detected_pii
                ]
                # Display Risk Assessment Metrics for Descriptive Data
                if "Risk_Score" in df.columns and not df["Risk_Score"].empty:
                    st.subheader("Risk Assessment")
                    avg_risk = df["Risk_Score"].mean()
                    max_risk = df["Risk_Score"].max()
                    min_risk = df["Risk_Score"].min()

                    col4, col5, col6 = st.columns(3)
                    with col4:
                        st.metric("Avg Risk", f"{avg_risk:.2f}")
                    with col5:
                        st.metric("Max Risk", f"{max_risk}")
                    with col6:
                        st.metric("Min Risk", f"{min_risk}")
            pii_df = pd.DataFrame(pii_flat, columns=["Entity", "Type"])
            pii_df["Risk_Score"] = pii_df["Type"].apply(lambda t: RISK_SCORES.get(t.upper(), 1))
            if "Risk_Score" in df.columns:
                st.subheader("Row-Wise Risk Scores")
                cols = ["Risk_Score"] + [col for col in df.columns if col != "Risk_Score"]
                st.dataframe(df[cols], use_container_width=True)

            hii_df = pd.DataFrame(hii_flat, columns=["Entity", "Type"])
            hii_df["Risk_Score"] = hii_df["Type"].apply(lambda t: RISK_SCORES.get(t.upper(), 1))

            st.session_state.pii = pii_df.to_dict(orient="records")
            st.session_state.hii = hii_df.to_dict(orient="records")

            st.success("Detection completed.")
            st.session_state['detection_ran'] = True

            documents_to_index = [
                {"id": i, "Entity": entity, "Type": entity_type}
                for i, (entity, entity_type) in enumerate(pii_flat + hii_flat)
            ]


            def clean_string(value):
                if value is None or (isinstance(value, float) and pd.isna(value)):
                    return ""
                return str(value).strip()


            documents_to_index = [
                {"id": i, "Entity": clean_string(entity), "Type": clean_string(entity_type)}
                for i, (entity, entity_type) in enumerate(pii_flat + hii_flat)
                if entity and entity_type
            ]
            if documents_to_index:
                from datetime import datetime

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                index_name = f"pii_hii_data_{timestamp}"

                try:
                    client.create_index(index_name, {"primaryKey": "id"})
                    run_index = client.index(index_name)

                    run_index.add_documents(documents_to_index)
                    st.success(f" Detection results indexed in Meilisearch index: `{index_name}`")
                except Exception as e:
                    st.error(f" Failed to create/index data: {e}")
            else:
                st.warning(" No entities to index. Check detection logic.")
    pii_df = pd.DataFrame(st.session_state.get("pii", []))
    hii_df = pd.DataFrame(st.session_state.get("hii", []))

    RISK_SCORES = {
        "EMAIL": 2,
        "PHONE": 2,
        "CREDIT_CARD": 5,
        "ADDRESS": 3,
        "ID": 4,
        "NAME": 1,
        "BLOOD_TYPE": 1,
        "WEIGHT": 1,
        "HEIGHT": 1,
        "ALLERGIES": 2,
        "MEDICAL_CONDITIONS": 4,
        "MEDICATIONS": 3,
        "DOCTOR": 2,
        "HOSPITAL": 2,
        "INSURANCE": 3
    }

    if not pii_df.empty and "Risk_Score" not in pii_df.columns:
        pii_df["Risk_Score"] = pii_df["Type"].apply(lambda t: RISK_SCORES.get(t.upper(), 1))

    if not hii_df.empty and "Risk_Score" not in hii_df.columns:
        hii_df["Risk_Score"] = hii_df["Type"].apply(lambda t: RISK_SCORES.get(t.upper(), 1))

    detected_types = sorted(set(
        (pii_df['Type'].unique().tolist() if 'Type' in pii_df else []) +
        (hii_df['Type'].unique().tolist() if 'Type' in hii_df else [])
    ))
    st.sidebar.title(" Detection Controls")
    data_sources = []
    if not pii_df.empty:
        data_sources.append("PII")
    if not hii_df.empty:
        data_sources.append("HII")

    if data_sources:
        detection_choice = st.sidebar.radio("Select Entity Table to View", ["Both"] + data_sources)

        selected_types = []
        if detection_choice in ["Both", "PII"]:
            pii_types = pii_df['Type'].dropna().astype(str).unique().tolist() if not pii_df.empty else []
            if pii_types:
                selected_pii = st.sidebar.multiselect("Select PII Types", pii_types, default=pii_types)
                selected_types += selected_pii

        if detection_choice in ["Both", "HII"]:
            hii_types = hii_df['Type'].dropna().astype(str).unique().tolist() if not hii_df.empty else []
            if hii_types:
                selected_hii = st.sidebar.multiselect("Select HII Types", hii_types, default=hii_types)
                selected_types += selected_hii
    else:
        st.sidebar.info("No detected data available to filter.")
        selected_types = []
    if selected_types:
        if detection_choice in ["Both", "PII"] and not pii_df.empty:
            pii_df = pii_df[pii_df['Type'].isin(selected_types)]
        else:
            pii_df = pd.DataFrame()

        if detection_choice in ["Both", "HII"] and not hii_df.empty:
            hii_df = hii_df[hii_df['Type'].isin(selected_types)]
        else:
            hii_df = pd.DataFrame()

    # Redaction by group
    grouped_dataframes = {"PII": pii_df, "HII": hii_df}
    redact_map = {}

    for idx, (group_name, group_df) in enumerate(grouped_dataframes.items()):
        if not group_df.empty and 'Type' in group_df.columns:
            st.sidebar.markdown(f"###  Redaction Settings for {group_name}")
            unique_prefix = f"{group_name}_{idx}"
            enable_redact = st.sidebar.checkbox(f"Enable Redaction for {group_name}", key=f"mask_{unique_prefix}")

            if enable_redact:
                type_list = group_df['Type'].dropna().unique().tolist()
                selected_redact_types = st.sidebar.multiselect(
                    f"Redact these {group_name} types",
                    type_list,
                    default=type_list,
                    key=f"redact_{unique_prefix}"
                )
                redact_map[group_name] = selected_redact_types
            else:
                redact_map[group_name] = []


    # Redaction logic
    def mask_entity(value, entity_type, active_types):
        if not value:
            return value
        if entity_type in active_types:
            return '[REDACTED]'
        return value


    for group_name, df in grouped_dataframes.items():
        if not df.empty:
            redact_types = redact_map.get(group_name, [])
            grouped_dataframes[group_name]['Entity'] = df.apply(
                lambda row: mask_entity(row['Entity'], row['Type'], redact_types),
                axis=1
            )

    pii_df = grouped_dataframes.get("PII", pd.DataFrame())
    hii_df = grouped_dataframes.get("HII", pd.DataFrame())

    keyword = st.sidebar.text_input("Filter Keyword", key="filter_k")
    if keyword:
        pii_df = pii_df[pii_df['Entity'].str.contains(keyword, na=False)]
        hii_df = hii_df[hii_df['Entity'].str.contains(keyword, na=False)]

    summary_df = pd.concat([pii_df, hii_df], ignore_index=True)

    if not summary_df.empty:
        st.subheader(" Detection Summary Overview")
        total_rows = len(df)
        total_entities = len(summary_df)
        most_common_entity_type = summary_df['Type'].value_counts().idxmax()
        most_common_count = summary_df['Type'].value_counts().max()

        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(
                f"<h3 style='font-size: 16px;'>Total Rows Processed:<br><span style='color:#4CAF50'>{total_rows}</span></h3>",
                unsafe_allow_html=True)
        with col2:
            st.markdown(
                f"<h3 style='font-size: 16px;'>Total Entities Detected:<br><span style='color:#2196F3'>{total_entities}</span></h3>",
                unsafe_allow_html=True)
        with col3:
            st.markdown(
                f"<h3 style='font-size: 16px;'>Most Common Entity:<br><span style='color:#f44336'>{most_common_entity_type} ({most_common_count})</span></h3>",
                unsafe_allow_html=True)
    else:
        st.info(" No entities found to summarize.")
    if "Risk_Score" in df.columns:
        st.subheader("Risk Assessment")
        avg_risk = df["Risk_Score"].mean()
        max_risk = df["Risk_Score"].max()
        min_risk = df["Risk_Score"].min()

        col4, col5, col6 = st.columns(3)
        with col4:
            st.metric("Avg Risk", f"{avg_risk:.2f}")
        with col5:
            st.metric("Max Risk", f"{max_risk}")
        with col6:
            st.metric("Min Risk", f"{min_risk}")

    if not pii_df.empty and "Type" in pii_df.columns:
        st.subheader(" PII Entity Distribution")
        pii_counts = pii_df["Type"].value_counts()
        if len(pii_counts) == 0:
            st.warning("No PII entities were detected in this dataset.")
        else:
            fig = px.bar(
                pii_counts,
                x=pii_counts.index,
                y=pii_counts.values,
                text=pii_counts.values,
                color=pii_counts.index,
                labels={'x': 'PII Type', 'y': 'Count'},
                title="Distribution of Detected PII Types",
                color_discrete_sequence=px.colors.qualitative.Set1
            )
            st.plotly_chart(fig)
    if 'detection_ran' in st.session_state and st.session_state['detection_ran']:
        if not pii_df.empty:
            st.subheader("Detected PII Entities")
            st.dataframe(pii_df[['Entity', 'Type', 'Risk_Score']], use_container_width=True)
        if not hii_df.empty:
            st.subheader("Detected HII Entities")
            st.dataframe(hii_df[['Entity', 'Type', 'Risk_Score']], use_container_width=True)

        if pii_df.empty and hii_df.empty:
            st.info("No entities were detected in this dataset.")
    else:
        st.info("Click **Run Detection** to view detected entities.")
    if "Risk_Score" in df.columns:
        st.subheader("Row-Wise Risk Scores")
        cols = ["Risk_Score"] + [col for col in df.columns if col != "Risk_Score"]
        st.dataframe(df[cols], use_container_width=True)


    #  WordCloud
    def safe_wordcloud(pii_df, hii_df):
        pii_entities = pii_df['Entity'].dropna().astype(str).tolist() if 'Entity' in pii_df.columns else []
        hii_entities = hii_df['Entity'].dropna().astype(str).tolist() if 'Entity' in hii_df.columns else []

        combined = pii_entities + hii_entities

        if combined:
            text = ' '.join(combined)
            wc = WordCloud(width=800, height=400, background_color="white").generate(text)
            st.subheader("Entity Word Cloud")
            st.image(wc.to_array(), use_container_width=True)
        else:
            st.info(" No entities detected to generate a word cloud.")


    safe_wordcloud(pii_df, hii_df)
    # advanced search button
    if st.button("Advanced Search"):
        import webbrowser

        webbrowser.open(os.getenv("MEILISEARCH"))

    # Secure ZIP download
    if zip_password:
        files = {}
        if not pii_df.empty:
            files['pii.csv'] = pii_df.to_csv(index=False)
        if not hii_df.empty:
            files['hii.csv'] = hii_df.to_csv(index=False)

        with pyzipper.AESZipFile("secure_data.zip", 'w', compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as zipf:
            zipf.setpassword(zip_password.encode())
            for fname, content in files.items():
                zipf.writestr(fname, content)

        with open("secure_data.zip", "rb") as zip_file:
            st.download_button("Download Encrypted ZIP", zip_file, file_name="secure_data.zip", mime="application/zip")
    else:
        st.warning("Set a password to enable secure ZIP download.")

    st.markdown("---")
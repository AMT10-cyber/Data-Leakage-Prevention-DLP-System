# Data Leakage Prevention (DLP) System

A secure, web-based system for detecting and redacting sensitive **PII** (Personally Identifiable Information) and **HII** (Health Information Identifiers) from both structured and unstructured datasets using rule-based logic and NLP.

This Streamlit-powered application offers user authentication, encrypted downloads, real-time redaction, and flexible upload support for tabular and descriptive data through `.csv` files.

---

## Key Features

### 1. User Management

* Secure login/logout with session tracking
* Self-registration built into the UI
* Passwords hashed using `bcrypt`
* Credentials stored securely in a local YAML file

### 2. Upload & Detection

* Upload custom `.csv` datasets directly via the app
* Dual detection engines:

  * **Tabular Engine**: For structured fields like `fname`, `email`, `phone`, etc.
  * **Descriptive Engine**: For free-form text using spaCy’s `en_core_web_trf` transformer NER model
* Automatic classification into **PII** and **HII** categories

### 3. Redaction & Security

* On-demand redaction of selected entity types
* Masked output using `[REDACTED]` format
* Export detected data securely as an **AES-encrypted ZIP**

### 4. Visualization & Filtering

* WordCloud visualization of detected entities
* Sidebar filtering by entity type and keyword
* Download either original or redacted results

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/Data-Leakage-Prevention-DLP-System.git
cd Data-Leakage-Prevention-DLP-System
```

### 2. (Optional) Create a Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Download NLP Model

```bash
python -m spacy download en_core_web_trf
```

---

## Meilisearch Setup (Optional but Recommended)

The app can optionally use [Meilisearch](https://www.meilisearch.com/) for fast indexing and search of detected entities.

### Step 1: Install Meilisearch

```bash
curl -L https://install.meilisearch.com | sh
```

Or manually download from [meilisearch.com/download](https://www.meilisearch.com/download)

### Step 2: Run Meilisearch

In a separate terminal:

```bash
./meilisearch --master-key your_master_key
```

> Meilisearch is optional. If it's not running, search and indexing features will be disabled.

---

### 5. Run the Application

```bash
streamlit run main.py
```

Then open your browser at [http://localhost:8501](http://localhost:8501)

---

## Upload Instructions

* Accepted file type: `.csv`
* **Tabular Engine** requires fields like:
  `fname`, `lname`, `email`, `phone`, `address`, etc.
* **Descriptive Engine** requires a `text` column with free-form content

---

## Sample Data

Sample files are available in the `sample_data/` folder for testing:

* `PII_HII_Dataset.csv` – for **Tabular Engine**
* `pii_dataset.csv` – for **Descriptive Engine**

Use them to try out the detection and redaction features quickly.

---

## Redaction & Secure Export

* Redact chosen entity types via sidebar controls
* Fields will be masked as `[REDACTED]`
* Optionally export the data as an AES-encrypted ZIP file

---

## License

This project is licensed under the [MIT License](LICENSE).
Developed by **Atharva Takalkar** and **Raj Patil**.

---

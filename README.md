# Data Leakage Prevention (DLP) System

A secure, web-based system for detecting and redacting sensitive **PII** (Personally Identifiable Information) and **HII** (Health Information Identifiers) from structured and unstructured datasets using rule-based logic and NLP.

This Streamlit-powered app offers user authentication, real-time registration, encrypted exports, and support for both tabular and descriptive data via CSV uploads.

---

## Key Features

### 1. User Management

* Secure login/logout with session management
* Passwords hashed using `bcrypt`
* Self-registration through the app
* Credentials stored securely in a YAML file

### 2. Upload & Detection

* Upload custom `.csv` files via the app interface
* Two detection engines:

  * **Tabular**: For structured fields like name, email, address, etc.
  * **Descriptive**: Uses spaCy Transformer NER (`en_core_web_trf`) for free-text detection
* Automatically categorizes entities into PII and HII

### 3. Redaction & Security

* Real-time redaction of selected entity types
* Redacted entities are masked as `[REDACTED]`
* AES-encrypted ZIP export of redacted data

### 4. Visualization & Filtering

* WordCloud visualization of all detected entities
* Sidebar filters by entity type and keyword
* Download filtered or redacted data securely

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
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
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

The app uses [Meilisearch](https://www.meilisearch.com/) for lightning-fast indexing and search of detected PII/HII entities.

### Step 1: Download Meilisearch (One-time Setup)

```bash
curl -L https://install.meilisearch.com | sh
```

Or download it manually from [https://www.meilisearch.com/download](https://www.meilisearch.com/download)

### Step 2: Start Meilisearch in a New Terminal

```bash
./meilisearch --master-key your_master_key
```

> Keep this terminal running. Meilisearch is optional — the app works even without it, but search and indexing will be disabled.

---

### 5. Run the App

Open a **new terminal window** and run:

```bash
streamlit run main.py
```

Then visit [http://localhost:8501](http://localhost:8501) in your browser.

---

## Upload Instructions

* Supported File Format: `.csv`
* **Tabular Engine**: Requires structured fields like `fname`, `lname`, `email`, `phone`, etc.
* **Descriptive Engine**: Requires a `text` column containing unstructured paragraphs

---

## Redaction & Download

* Redact specific entity types by selecting them in the sidebar
* Redacted fields are replaced with `[REDACTED]`
* Export results securely as an **AES-encrypted ZIP file**
* Temporary files are cleaned periodically

---

## License

This project is licensed under the [MIT License](LICENSE).
Developed by **Atharva Takalkar** and **Raj Patil**.

---

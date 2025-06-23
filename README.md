## Data Leakage Prevention (DLP) System

A web-based application that identifies and prevents potential data leakage from uploaded documents by detecting Personally Identifiable Information (PII) and Health Identifiable Information (HII). This system leverages advanced Natural Language Processing (NLP) techniques with spaCy and transformers, and uses Meilisearch for secure and efficient indexing.

---

## Project Features

- Upload and process TXT files
- Detect PII and HII entities such as names, emails, phone numbers, and addresses
- Uses spaCy's transformer-based `en_core_web_trf` model
- Redacts sensitive entities from uploaded files
- Allows users to review original and redacted text
- Indexes sanitized documents in Meilisearch for fast search
- Intuitive and interactive Streamlit-based web interface

---

## Technology Stack

- **Frontend**: Streamlit
- **Backend**: Python
- **NLP**: spaCy, Transformers, PyTorch
- **Search Engine**: Meilisearch
- **Others**: dotenv and tempfile

---

### Prerequisites

- Python 3.10 or later
- [Meilisearch](https://www.meilisearch.com/docs/learn/getting_started/installation/) running locally or remotely

---

## Security Considerations

* Models are loaded in-memory and not exposed to external inputs.
* `torch.load` is used with caution to avoid malicious unpickling.
* Files are processed in a secure, temporary location.
* Meilisearch runs locally with protected access via API key.

---

## Contributors

* **Atharva Takalkar**
* **Raj Patil**

---

## License

This project is licensed under the [MIT License](LICENSE). See the LICENSE file for details.

# Sentinel Malware Ensemble Analysis System

This system provides a high-fidelity malware detection pipeline for OOXML documents (`.docx`, `.xlsx`, `.pptx`) using a three-tier ensemble: **SFEM (Structural)**, **RAG (Memory)**, and **LLM (Semantic/Phi-3)**.

## 📋 1. Prerequisites & Installation
This code requires python3.11 version exactly(because of the llama_cpp version used)

### 🛑 IMPORTANT: Model Setup & Training
To keep the repository lightweight, large model files are **not included**. You must download the base models and (optionally) retrain the classifiers before running the system.
in order to install the models run:
```powershell
pip install huggingface_hub

huggingface-cli download microsoft/Phi-3-mini-4k-instruct-gguf Phi-3-mini-4k-instruct-q4.gguf --local-dir TSA-LLM/models --local-dir-use-symlinks False

huggingface-cli download sentence-transformers/all-MiniLM-L6-v2 --local-dir TSA-LLM/models/sentence-transformers_all-MiniLM-L6-v2 --local-dir-use-symlinks False
```
#### Create the Models Directory
Ensure the following directory exists in the project root:
```bash
mkdir -p TSA-LLM/models
```
### Local Virtual Environment (Development)
To run or test individual components outside of Docker, follow these steps to set up `venv311`:

1.  **Create the environment**:
    ```powershell
    python -m venv venv311
    ```

2.  **Activate the environment**:
    * **Windows**:
        ```powershell
        .\venv311\Scripts\activate
        ```
    * **Linux/Mac**:
        ```bash
        source venv311/bin/activate
        ```

3.  **Install Dependencies**:
    ```powershell
    pip install -r requirements.txt
    ```

### Required Model Artifacts
Before running, the following files must be placed in the `./TSA-LLM/models/` directory:

* `Phi-3-mini-4k-instruct-q4.gguf` (LLM Weights)
* `sfem_model.pkl` (Structural Classifier)
* `meta_weigher.pkl` (Meta-Classifier)
* `weight_training_data.csv` (Custom decision weights)

## 🐳 2. Deployment with Docker

The entire system is containerized to ensure **"Full Separation"** between the Python Backend and the JS-based Frontend.

**Command to Start:**
```powershell
docker compose up --build
```
### Access Points

* **Frontend UI:** [http://localhost:5000](http://localhost:5000)
* **OpenAPI (Swagger) Documentation:** [http://localhost:5000/apidocs](http://localhost:5000/apidocs)

## 🏗️ 3. Architecture & Requirements Fulfillment

### Worker & Queue Management
* **Worker Implementation:** The system utilizes **Gunicorn** to manage worker processes.
* **Queueing Logic:** Incoming analysis requests are handled via a TCP backlog queue managed by Gunicorn. This ensures that heavy LLM and SFEM processes are handled sequentially without crashing the server.

### Frontend/Backend Separation
* **Headless Backend:** The backend operates as a pure REST API, communicating solely via JSON.
* **Independent Frontend:** The UI is a single-page application that uses JavaScript `fetch()` to interact with the API endpoints.
* **OpenAPI Documentation:** The backend includes a self-documenting OpenAPI (Swagger) interface, allowing the API to be tested and used entirely independently of the frontend.

## 🧪 4. Component Testing & Configuration

### Testing Individual Models
To test components in isolation (ensure `venv311` is active):

* **LLM Analysis:** Modify `LLM_PATH` in `EnsemblePipeline.py` to point to your local `.gguf` file.
* **SFEM Extraction:** Run `sfem_features.py` directly to verify structural feature parsing.
* **RAG Recall:** The `KnowledgeBase` class in `LLMSentinel_v3.py` can be tested for vector similarity and retrieval accuracy.

### Important Paths
If you change your folder structure, update these constants at the top of `EnsemblePipeline.py`:

* `MODEL_DIR`: Location of all `.pkl` and `.gguf` files.
* `UPLOAD_FOLDER`: Directory for temporary file processing (mapped to `/tmp` in Docker).

## ✅ 5. Submission Checklist

- [x] **Dockerized:** System runs via a single `docker compose` command.
- [x] **OpenAPI:** Swagger UI is live at `/apidocs`.
- [x] **Separation:** Frontend and Backend communicate strictly via JSON API.
- [x] **Clean Code:** Virtual environments (`venv311`) and caches are excluded via `.gitignore` and `.dockerignore`.
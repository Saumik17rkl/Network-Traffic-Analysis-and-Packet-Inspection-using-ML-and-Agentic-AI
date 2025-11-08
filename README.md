# CompactNetTrace: Network Traffic Analysis & Packet Inspection using ML & Agentic AI

## 📝 Overview
CompactNetTrace is a lightweight, reproducible research project for network traffic analysis, intrusion detection, anomaly localization, and policy enforcement using compact ML models and an agentic finite-state controller.

## 🎯 Key Features
- **Flow-level Analysis**: Implements lightweight ML models for network flow analysis
- **Packet-level Inspection**: Utilizes compact 1D-CNN for deep packet inspection
- **Agentic FSM**: Integrates a deterministic finite-state machine for autonomous responses
- **Explainability**: Provides model interpretability through SHAP and LIME
- **Live & Offline Analysis**: Supports both real-time packet capture and offline dataset processing
- **Streamlit Web Interface**: Interactive demo for visualization and testing

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- 8GB RAM (minimum)
- Dual-core CPU or better

### Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd "Network Traffic Analysis and Packet Inspection using ML and Agentic AI"
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🏃‍♂️ Quick Start
1. Launch the Streamlit demo:
   ```bash
   streamlit run streamlit_app.py
   ```

2. Open your browser to `http://localhost:8501`

## 📂 Project Structure
```
.
├── notebooks/               # Jupyter notebooks for the project pipeline
│   ├── 00_environment_and_instructions.ipynb
│   ├── 01_data_acquisition_and_sampling.ipynb
│   ├── 02_preprocessing_and_feature_engineering.ipynb
│   ├── 03_baseline_models_training.ipynb
│   ├── 04_packet_level_model_training.ipynb
│   ├── 05_evaluation_and_explainability.ipynb
│   ├── 06_agentic_orchestration_and_simulation.ipynb
│   └── 07_deployment_and_demo_setup.ipynb
├── artifacts/              # Saved models and results
├── data/                   # Datasets and packet captures
├── app/                    # Streamlit application files
└── requirements.txt        # Project dependencies
```

## 📊 Features
- **Data Processing**: Efficient packet capture and flow feature extraction
- **Model Training**: Multiple ML models for different analysis levels
- **Visualization**: Interactive plots for traffic analysis
- **Real-time Monitoring**: Live packet capture and analysis
- **Anomaly Detection**: Identify suspicious network behavior

## 🤖 Agentic FSM
Our Finite State Machine (FSM) provides intelligent responses to network events:
- **States**: Monitoring, Alert, Mitigation, Recovery
- **Transitions**: Automatic state changes based on ML model outputs
- **Actions**: Configurable responses to security events

## 📝 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments
- Built with ❤️ using Python and open-source libraries
- Special thanks to the open-source community for their contributions
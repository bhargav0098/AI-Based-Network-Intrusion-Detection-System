# 🛡️ AI-Powered Network Intrusion Detection System (NIDS)

An advanced, real-time network traffic analysis and intrusion detection system built with **Python**, **Streamlit**, and **Scikit-learn**. This system leverages the **Random Forest** machine learning algorithm to identify and flag malicious network activities like DDoS and Port Scanning.

---

## 🚀 Features

- **Real-time Traffic Monitoring:** Simulates live network traffic and flags threats instantly.
- **Interactive Dashboard:** built with Streamlit for easy visualization of data and model performance.
- **ML-Powered Detection:** Uses a trained Random Forest Classifier to distinguish between Benign and Malicious traffic.
- **Dynamic Analysis:** Allows manual input of packet details for on-demand security checks.
- **Performance Visualization:** Includes feature importance charts, confusion matrices, and detailed classification reports.

## 🛠️ Technology Stack

- **Frontend:** Streamlit
- **Machine Learning:** Scikit-learn (Random Forest)
- **Data Analysis:** Pandas, NumPy
- **Visualization:** Plotly, Matplotlib, Seaborn

## 📦 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bhargav0098/AI-Based-Network-Intrusion-Detection-System.git
   cd AI-Based-Network-Intrusion-Detection-System
   ```

2. **Install dependencies:**
   ```bash
   pip install streamlit pandas numpy scikit-learn seaborn matplotlib plotly
   ```

3. **Run the Dashboard:**
   ```bash
   streamlit run nids_dashboard.py
   ```

## 🔍 How it Works

1. **Data Generation:** The system uses a synthetic dataset structured similarly to the **CIC-IDS2017** logs.
2. **Model Training:** Users can adjust parameters like "Number of Trees" and "Test Size" directly from the sidebar.
3. **Detection:** The model analyzes features such as Flow Duration, Packet Length, and Flow Rate to determine if a packet is safe or part of an attack.

## 🛡️ Security Note
This project is for **educational purposes**. For real-world production environments, ensure the model is trained on actual network logs specific to your infrastructure and integrated via a robust packet capture (PCAP) pipeline.

---
Built with ❤️ by [Bhargav](https://github.com/bhargav0098)

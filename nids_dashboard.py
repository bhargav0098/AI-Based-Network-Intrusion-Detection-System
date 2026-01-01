import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import seaborn as sns
import matplotlib.pyplot as plt
import time
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AI NIDS Dashboard", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .alert-box {
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .success-alert {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
    }
    .danger-alert {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
    }
</style>
""", unsafe_allow_html=True)

# --- DATA LOADING ---
@st.cache_data
def load_data():
    """
    Generates a synthetic dataset that mimics network traffic logs (CIC-IDS2017 structure).
    In a real deployment, this would be replaced by pd.read_csv('network_logs.csv').
    """
    np.random.seed(42)
    n_samples = 10000  # Increased for better training
    
    # Simulating features common in Network Logs
    data = {
        'Destination_Port': np.random.randint(1, 65535, n_samples),
        'Flow_Duration': np.random.randint(100, 100000, n_samples),
        'Total_Fwd_Packets': np.random.randint(1, 100, n_samples),
        'Total_Backward_Packets': np.random.randint(1, 100, n_samples),
        'Packet_Length_Mean': np.random.uniform(10, 1500, n_samples),
        'Packet_Length_Std': np.random.uniform(0, 500, n_samples),
        'Flow_Bytes_s': np.random.uniform(100, 10000, n_samples),
        'Flow_Packets_s': np.random.uniform(1, 100, n_samples),
        'Active_Mean': np.random.uniform(0, 1000, n_samples),
        'Idle_Mean': np.random.uniform(0, 1000, n_samples),
        'Label': np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])  # 0=Safe, 1=Attack
    }
    
    df = pd.DataFrame(data)
    
    # Introduce realistic patterns for the AI to learn
    # Attack patterns: DDoS (high packet rate), Port Scan (many connections)
    attack_indices = df[df['Label'] == 1].index
    
    # DDoS pattern (50% of attacks)
    ddos_indices = np.random.choice(attack_indices, size=len(attack_indices)//2, replace=False)
    df.loc[ddos_indices, 'Total_Fwd_Packets'] = np.random.randint(200, 1000, size=len(ddos_indices))
    df.loc[ddos_indices, 'Flow_Duration'] = np.random.randint(1, 1000, size=len(ddos_indices))
    df.loc[ddos_indices, 'Flow_Packets_s'] = np.random.uniform(50, 200, size=len(ddos_indices))
    
    # Port Scan pattern (50% of attacks)
    port_scan_indices = np.setdiff1d(attack_indices, ddos_indices)
    df.loc[port_scan_indices, 'Destination_Port'] = np.random.choice([80, 443, 22, 21, 25], size=len(port_scan_indices))
    df.loc[port_scan_indices, 'Total_Fwd_Packets'] = np.random.randint(1, 5, size=len(port_scan_indices))
    df.loc[port_scan_indices, 'Flow_Duration'] = np.random.randint(10000, 50000, size=len(port_scan_indices))
    
    return df

# --- HELPER FUNCTIONS ---
def train_model(X_train, y_train, n_estimators):
    """Train the Random Forest model"""
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=42,
        n_jobs=-1,
        max_depth=10
    )
    model.fit(X_train, y_train)
    return model

def evaluate_model(model, X_test, y_test):
    """Evaluate model and return metrics"""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred),
        'recall': recall_score(y_test, y_pred),
        'f1': f1_score(y_test, y_pred),
        'confusion_matrix': confusion_matrix(y_test, y_pred),
        'classification_report': classification_report(y_test, y_pred, output_dict=True),
        'predictions': y_pred,
        'probabilities': y_proba
    }
    return metrics

def plot_feature_importance(model, feature_names):
    """Plot feature importance using Plotly"""
    importance = model.feature_importances_
    importance_df = pd.DataFrame({
        'Feature': feature_names,
        'Importance': importance
    }).sort_values('Importance', ascending=True)
    
    fig = px.bar(
        importance_df,
        x='Importance',
        y='Feature',
        orientation='h',
        title='Feature Importance',
        color='Importance',
        color_continuous_scale='Blues'
    )
    fig.update_layout(height=400)
    return fig

def plot_data_distribution(df):
    """Plot distribution of key features"""
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Flow Duration', 'Total Forward Packets', 
                       'Packet Length Mean', 'Flow Bytes/s'),
        specs=[[{"secondary_y": False}, {"secondary_y": False}],
               [{"secondary_y": False}, {"secondary_y": False}]]
    )
    
    # Flow Duration
    fig.add_trace(
        go.Histogram(x=df['Flow_Duration'], name='Flow Duration', nbinsx=30),
        row=1, col=1
    )
    
    # Total Forward Packets
    fig.add_trace(
        go.Histogram(x=df['Total_Fwd_Packets'], name='Total Fwd Packets', nbinsx=30),
        row=1, col=2
    )
    
    # Packet Length Mean
    fig.add_trace(
        go.Histogram(x=df['Packet_Length_Mean'], name='Packet Length Mean', nbinsx=30),
        row=2, col=1
    )
    
    # Flow Bytes/s
    fig.add_trace(
        go.Histogram(x=df['Flow_Bytes_s'], name='Flow Bytes/s', nbinsx=30),
        row=2, col=2
    )
    
    fig.update_layout(height=600, showlegend=False)
    return fig

# --- MAIN APPLICATION ---
def main():
    # Header
    st.markdown('<h1 class="main-header">🛡️ AI-Powered Network Intrusion Detection System</h1>', 
                unsafe_allow_html=True)
    
    # Description
    st.markdown("""
    ### 🌐 Project Overview
    This advanced system uses Machine Learning (**Random Forest Algorithm**) to analyze network traffic in real-time.
    It classifies traffic into two categories:
    * **✅ Benign:** Safe, normal traffic patterns
    * **⚠️ Malicious:** Potential cyberattacks (DDoS, Port Scan, etc.)
    
    ---
    """)
    
    # Load Data
    df = load_data()
    
    # Sidebar Controls
    st.sidebar.header("⚙️ Control Panel")
    st.sidebar.info("Adjust model parameters and view system information here.")
    
    # Model Parameters
    st.sidebar.subheader("Model Parameters")
    split_size = st.sidebar.slider("Training Data Size (%)", 60, 90, 80)
    n_estimators = st.sidebar.slider("Number of Trees (Random Forest)", 50, 300, 100)
    test_size_slider = st.sidebar.slider("Test Data Size (%)", 10, 40, 20)
    
    # System Info
    st.sidebar.subheader("📊 System Information")
    st.sidebar.write(f"**Total Samples:** {len(df):,}")
    st.sidebar.write(f"**Benign Traffic:** {len(df[df['Label']==0]):,}")
    st.sidebar.write(f"**Malicious Traffic:** {len(df[df['Label']==1]):,}")
    st.sidebar.write(f"**Features:** {len(df.columns)-1}")
    
    # --- DATA EXPLORATION SECTION ---
    st.header("📈 Data Exploration")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Feature Distributions")
        fig_dist = plot_data_distribution(df)
        st.plotly_chart(fig_dist, use_container_width=True)
    
    with col2:
        st.subheader("Traffic Distribution")
        label_counts = df['Label'].value_counts()
        fig_pie = px.pie(
            values=label_counts.values,
            names=['Benign', 'Malicious'],
            title="Traffic Type Distribution",
            color_discrete_map={'Benign':'#00CC96', 'Malicious':'#EF553B'}
        )
        st.plotly_chart(fig_pie, use_container_width=True)
        
        # Data Sample
        st.subheader("Sample Data")
        st.dataframe(df.head(5), use_container_width=True)
    
    st.divider()
    
    # --- MODEL TRAINING SECTION ---
    st.header("🤖 Model Training & Evaluation")
    
    # Prepare Data
    X = df.drop('Label', axis=1)
    y = df['Label']
    feature_names = X.columns.tolist()
    
    # Split Data
    test_size = test_size_slider / 100
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, 
        test_size=test_size,
        random_state=42,
        stratify=y
    )
    
    # Training and Evaluation Columns
    col_train, col_metrics = st.columns([1, 2])
    
    with col_train:
        st.subheader("1. Model Training")
        
        if st.button("🚀 Train Model Now", type="primary"):
            with st.spinner("Training Random Forest Classifier..."):
                model = train_model(X_train, y_train, n_estimators)
                st.session_state['model'] = model
                st.session_state['trained'] = True
                st.success("✅ Training Complete!")
        
        if st.session_state.get('trained', False):
            st.success("✅ Model is Ready for Testing")
            
            # Feature Importance
            st.subheader("Feature Importance")
            model = st.session_state['model']
            fig_importance = plot_feature_importance(model, feature_names)
            st.plotly_chart(fig_importance, use_container_width=True)
    
    with col_metrics:
        st.subheader("2. Performance Metrics")
        
        if st.session_state.get('trained', False):
            model = st.session_state['model']
            metrics = evaluate_model(model, X_test, y_test)
            
            # Metrics Display
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Accuracy", f"{metrics['accuracy']*100:.2f}%")
            m2.metric("Precision", f"{metrics['precision']*100:.2f}%")
            m3.metric("Recall", f"{metrics['recall']*100:.2f}%")
            m4.metric("F1 Score", f"{metrics['f1']*100:.2f}%")
            
            # Confusion Matrix
            st.write("### Confusion Matrix")
            cm = metrics['confusion_matrix']
            fig_cm = px.imshow(
                cm,
                text_auto=True,
                color_continuous_scale='Blues',
                title="Confusion Matrix",
                labels=dict(x="Predicted", y="Actual", color="Count")
            )
            fig_cm.update_xaxes(ticktext=['Benign', 'Malicious'], tickvals=[0, 1])
            fig_cm.update_yaxes(ticktext=['Benign', 'Malicious'], tickvals=[0, 1])
            st.plotly_chart(fig_cm, use_container_width=True)
            
            # Classification Report
            with st.expander("📋 Detailed Classification Report"):
                report_df = pd.DataFrame(metrics['classification_report']).transpose()
                st.dataframe(report_df.style.format("{:.3f}"), use_container_width=True)
        else:
            st.warning("⚠️ Please train the model first to see performance metrics.")
    
    st.divider()
    
    # --- LIVE TRAFFIC SIMULATOR ---
    st.header("🔍 Live Traffic Simulator")
    st.write("Enter network packet details below to see if the AI flags it as an attack.")
    
    # Input Fields
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        p_port = st.number_input("Destination Port", 1, 65535, 80)
        p_dur = st.number_input("Flow Duration (ms)", 0, 100000, 500)
    
    with col2:
        p_fwd = st.number_input("Total Forward Packets", 0, 1000, 100)
        p_bwd = st.number_input("Total Backward Packets", 0, 1000, 50)
    
    with col3:
        p_len_mean = st.number_input("Packet Length Mean", 0, 1500, 500)
        p_len_std = st.number_input("Packet Length Std", 0, 500, 100)
    
    with col4:
        p_bytes_s = st.number_input("Flow Bytes/s", 0, 10000, 1000)
        p_packets_s = st.number_input("Flow Packets/s", 0, 200, 50)
        p_active = st.number_input("Active Mean", 0, 1000, 50)
        p_idle = st.number_input("Idle Mean", 0, 1000, 100)
    
    # Analysis Button
    col_analyze, col_random = st.columns([1, 1])
    
    with col_analyze:
        if st.button("🔎 Analyze Packet", type="primary"):
            if st.session_state.get('trained', False):
                model = st.session_state['model']
                input_data = np.array([[
                    p_port, p_dur, p_fwd, p_bwd, p_len_mean, 
                    p_len_std, p_bytes_s, p_packets_s, p_active, p_idle
                ]])
                
                pred = model.predict(input_data)[0]
                proba = model.predict_proba(input_data)[0]
                
                if pred == 1:
                    st.markdown("""
                    <div class="alert-box danger-alert">
                        <strong>🚨 ALERT: MALICIOUS TRAFFIC DETECTED!</strong><br>
                        Confidence: {:.1f}%<br>
                        <strong>Reason:</strong> High packet count with unusual flow patterns.
                    </div>
                    """.format(proba[1]*100), unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div class="alert-box success-alert">
                        <strong>✅ Traffic Status: BENIGN (Safe)</strong><br>
                        Confidence: {:.1f}%
                    </div>
                    """.format(proba[0]*100), unsafe_allow_html=True)
            else:
                st.error("❌ Please train the model first!")
    
    with col_random:
        if st.button("🎲 Generate Random Traffic"):
            # Generate random packet
            random_packet = {
                'Destination_Port': np.random.randint(1, 65535),
                'Flow_Duration': np.random.randint(100, 100000),
                'Total_Fwd_Packets': np.random.randint(1, 1000),
                'Total_Backward_Packets': np.random.randint(1, 1000),
                'Packet_Length_Mean': np.random.uniform(10, 1500),
                'Packet_Length_Std': np.random.uniform(0, 500),
                'Flow_Bytes_s': np.random.uniform(100, 10000),
                'Flow_Packets_s': np.random.uniform(1, 200),
                'Active_Mean': np.random.uniform(0, 1000),
                'Idle_Mean': np.random.uniform(0, 1000)
            }
            
            # Update input fields
            st.session_state.update(random_packet)
            st.rerun()
    
    # Real-time Simulation
    st.subheader("📡 Real-time Traffic Monitor")
    st.write("Simulating live network traffic monitoring...")
    
    if st.button("▶️ Start Real-time Monitoring"):
        if st.session_state.get('trained', False):
            model = st.session_state['model']
            placeholder = st.empty()
            
            for i in range(20):  # Simulate 20 packets
                # Generate random packet
                random_packet = np.array([[
                    np.random.randint(1, 65535),
                    np.random.randint(100, 100000),
                    np.random.randint(1, 1000),
                    np.random.randint(1, 1000),
                    np.random.uniform(10, 1500),
                    np.random.uniform(0, 500),
                    np.random.uniform(100, 10000),
                    np.random.uniform(1, 200),
                    np.random.uniform(0, 1000),
                    np.random.uniform(0, 1000)
                ]])
                
                # Predict
                pred = model.predict(random_packet)[0]
                proba = model.predict_proba(random_packet)[0]
                
                # Display
                with placeholder.container():
                    col1, col2, col3 = st.columns(3)
                    
                    col1.metric("Packet #", f"{i+1}")
                    
                    if pred == 1:
                        col2.metric("Status", "🚨 MALICIOUS", delta=None)
                        col3.metric("Confidence", f"{proba[1]*100:.1f}%")
                    else:
                        col2.metric("Status", "✅ BENIGN", delta=None)
                        col3.metric("Confidence", f"{proba[0]*100:.1f}%")
                
                time.sleep(0.5)  # Simulate real-time
        else:
            st.error("❌ Please train the model first!")
    
    # --- FOOTER ---
    st.divider()
    st.markdown("""
    <div style='text-align: center; color: #666;'>
        <p>AI-Powered Network Intrusion Detection System | Built with Streamlit & Scikit-learn</p>
        <p>© 2024 | For Educational Purposes</p>
    </div>
    """, unsafe_allow_html=True)

# Initialize session state
if 'trained' not in st.session_state:
    st.session_state['trained'] = False

# Run the application
if __name__ == "__main__":
    main()
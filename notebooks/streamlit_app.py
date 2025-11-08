# streamlit_app.py
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go
from sklearn.preprocessing import LabelEncoder, StandardScaler
import json
# --- Pre-flight dependency check ---
import importlib, sys
# --- Pre-flight dependency check ---
import importlib, streamlit as st
# --- Pre-flight dependency check (final corrected) ---
import importlib, streamlit as st, platform

# ✅ Use the correct import names (e.g., sklearn instead of scikit_learn)
required = ["plotly", "torch", "sklearn", "matplotlib", "pandas", "numpy"]
missing = [pkg for pkg in required if importlib.util.find_spec(pkg) is None]

if missing:
    st.error(f"⚠️ Missing dependencies detected: {missing}")
    st.stop()
else:
    st.sidebar.success("✅ All dependencies verified")
    st.sidebar.markdown(f"""
    **Python:** {platform.python_version()}  
    **Torch:** {__import__('torch').__version__}  
    **Scikit-learn:** {__import__('sklearn').__version__}
    """)

# Set page config
st.set_page_config(
    page_title="Network Traffic Analysis",
    page_icon="🌐",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        max-width: 1200px;
        padding: 2rem;
    }
    .metric-box {
        background-color: #f8f9fa;
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    </style>
""", unsafe_allow_html=True)

# Constants
BASE_DIR = Path(__file__).parent  # Point to notebooks directory
MODELS_DIR = BASE_DIR / "artifacts" / "models"
DATA_DIR = BASE_DIR / "data" / "raw" / "NSL-KDD" / "nsl-kdd"

# Define categorical columns for NSL-KDD dataset
CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']

# Load models
@st.cache_resource
def load_models():
    models = {}
    model_files = {
        "Random Forest": "flow_rf_20251108_231711.joblib",
        "Logistic Regression": "flow_logreg_20251108_231711.joblib",
        "Isolation Forest": "flow_iforest_20251108_231711.joblib"
    }
    
    st.sidebar.subheader("Model Loading Status")
    st.sidebar.write(f"Looking in: {MODELS_DIR.absolute()}")
    if MODELS_DIR.exists():
        st.sidebar.write(f"Found {len(list(MODELS_DIR.glob('*.joblib')))} model files")
        st.sidebar.write("Available models:")
        for model_file in MODELS_DIR.glob('*.joblib'):
            st.sidebar.write(f"- {model_file.name}")
    else:
        st.sidebar.error(f"Models directory not found: {MODELS_DIR.absolute()}")
    
    for name, filename in model_files.items():
        try:
            model_path = MODELS_DIR / filename
            st.sidebar.write(f"🔍 Looking for {name} at: {model_path.absolute()}")
            
            if not model_path.exists():
                st.sidebar.error(f"❌ Model file not found: {filename}")
                continue
                
            models[name] = joblib.load(model_path)
            st.sidebar.success(f"✅ Successfully loaded {name}")
            
        except Exception as e:
            st.sidebar.error(f"❌ Error loading {name} model: {str(e)[:200]}")
    
    if not models:
        st.sidebar.error("⚠️ No models were loaded. Please check the model files and paths.")
    
    return models
# Add this function near the top with other utility functions
def make_prediction(model, df):
    """Make predictions using the model with proper data preprocessing"""
    try:
        # Get the expected features from the model (if available)
        if hasattr(model, 'feature_names_in_'):
            expected_features = list(model.feature_names_in_)
        else:
            # If model doesn't have feature names, use the first n columns from the dataframe
            # (assuming the model was trained on the first n features)
            expected_features = [col for col in df.columns if col != 'target']
            if hasattr(model, 'n_features_in_'):
                expected_features = expected_features[:model.n_features_in_]
        
        # Create a sample with only the expected features
        sample = df[expected_features].sample(1).copy()
        
        # Ensure categorical columns are properly encoded
        categorical_cols = [col for col in CATEGORICAL_COLS if col in sample.columns]
        for col in categorical_cols:
            if col in sample.columns and not pd.api.types.is_numeric_dtype(sample[col]):
                le = LabelEncoder()
                sample[col] = le.fit_transform(sample[col].astype(str))
        
        # Ensure all columns are numeric
        for col in sample.columns:
            if not pd.api.types.is_numeric_dtype(sample[col]):
                try:
                    sample[col] = pd.to_numeric(sample[col], errors='coerce')
                    sample[col] = sample[col].fillna(0)
                except:
                    st.error(f"Could not convert column {col} to numeric")
                    return None, None
        
        # Ensure we have the right number of features
        if hasattr(model, 'n_features_in_') and sample.shape[1] != model.n_features_in_:
            st.error(f"Feature count mismatch: Expected {model.n_features_in_} features, got {sample.shape[1]}")
            return None, None
        
        # Make prediction
        prediction = model.predict(sample)
        proba = model.predict_proba(sample) if hasattr(model, 'predict_proba') else None
        return prediction, proba
        
    except Exception as e:
        st.error(f"Prediction error: {str(e)}")
        return None, None

# This function will be called when making predictions in the main app flow
# Load and preprocess data
@st.cache_data
def load_nsl_kdd_data():
    try:
        # Verify data directory exists
        if not DATA_DIR.exists():
            st.error(f"❌ Data directory not found at: {DATA_DIR.absolute()}")
            return None
            
        # NSL-KDD columns (predefined as the feature names file might not exist in all distributions)
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'target'
        ]
        
        # Load training data
        train_path = DATA_DIR / "KDDTrain+.txt"
        test_path = DATA_DIR / "KDDTest+.txt"
        
        if not train_path.exists() or not test_path.exists():
            st.error(f"❌ Data files not found. Looking for:\n{train_path.absolute()}\n{test_path.absolute()}")
            return None
            
        # Load data with error handling for bad lines
        try:
            train_df = pd.read_csv(train_path, header=None, names=columns, low_memory=False, 
                                 on_bad_lines='warn')
            test_df = pd.read_csv(test_path, header=None, names=columns, low_memory=False,
                                on_bad_lines='warn')
        except Exception as e:
            st.error(f"Error reading data files: {e}")
            return None
        
        # Display dataset info before preprocessing
        st.sidebar.info(f"Training samples: {len(train_df)}")
        st.sidebar.info(f"Test samples: {len(test_df)}")
        
        # Combine train and test for full dataset
        df = pd.concat([train_df, test_df], axis=0)
        
        # Display data types and missing values
        with st.expander("Data Summary (Before Preprocessing)"):
            st.write("### Data Types")
            st.write(df.dtypes)
            st.write("\n### Missing Values")
            st.write(df.isnull().sum())
        
        # Preprocessing
        with st.spinner("Preprocessing data (this may take a moment)..."):
            df = preprocess_data(df)
            
            # Display preprocessed data info
            with st.expander("Data Summary (After Preprocessing)"):
                st.write("### Data Types")
                st.write(df.dtypes)
                st.write("\n### First few rows")
                st.dataframe(df.head())
            
            return df
    except Exception as e:
        st.error(f"❌ Error loading NSL-KDD dataset: {e}")
        st.error(f"Error details: {str(e)}")
        return None

def preprocess_data(df):
    # Make a copy of the dataframe to avoid modifying the original
    df = df.copy()
    
    # Use global categorical columns, ensuring they exist in the dataframe
    categorical_cols = [col for col in CATEGORICAL_COLS if col in df.columns]
    
    # Get numerical columns (exclude target and categorical columns)
    numerical_cols = [col for col in df.columns 
                     if col not in categorical_cols + ['target'] 
                     and df[col].dtype in ['int64', 'float64']]
    
    # Encode categorical features
    label_encoders = {}
    for col in categorical_cols:
        try:
            le = LabelEncoder()
            # Handle any potential NaN values in categorical columns
            df[col] = df[col].fillna('unknown')
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le
        except Exception as e:
            st.error(f"Error encoding column {col}: {e}")
    
    # Convert numerical columns to float and handle any conversion errors
    for col in numerical_cols:
        try:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            # Fill NaN values with the mean of the column
            df[col] = df[col].fillna(df[col].mean())
        except Exception as e:
            st.error(f"Error processing numerical column {col}: {e}")
    
    # Scale numerical features
    if numerical_cols:
        try:
            scaler = StandardScaler()
            df[numerical_cols] = scaler.fit_transform(df[numerical_cols])
        except Exception as e:
            st.error(f"Error scaling numerical features: {e}")
    
    return df

# Initialize session state
if 'df' not in st.session_state:
    st.session_state.df = None
if 'models' not in st.session_state:
    st.session_state.models = load_models()

# Main app
st.title("🌐 Network Traffic Analysis with ML")
st.markdown("""
    Analyze network traffic using pre-trained machine learning models. 
    This app uses the NSL-KDD dataset and pre-trained models to detect network intrusions.
""")

# Display current working directory and paths for debugging
with st.expander("Debug Info"):
    st.write(f"Current working directory: {os.getcwd()}")
    st.write(f"Base directory: {BASE_DIR.absolute()}")
    st.write(f"Models directory: {MODELS_DIR.absolute()}")
    st.write(f"Data directory: {DATA_DIR.absolute()}")
    
    # Check if directories exist
    st.write("\n**Directory Status:**")
    st.write(f"Models directory exists: {MODELS_DIR.exists()}")
    if MODELS_DIR.exists():
        st.write("Files in models directory:", os.listdir(MODELS_DIR))
    
    st.write(f"Data directory exists: {DATA_DIR.exists()}")
    if DATA_DIR.exists():
        st.write("Files in data directory:", os.listdir(DATA_DIR))

# Sidebar
st.sidebar.header("Settings")
model_choice = st.sidebar.selectbox(
    "Select Model",
    ["Random Forest", "Logistic Regression", "Isolation Forest"]
)

# Load data
if st.sidebar.button("Load NSL-KDD Dataset"):
    with st.spinner("Loading and preprocessing data..."):
        st.session_state.df = load_nsl_kdd_data()
    if st.session_state.df is not None:
        st.sidebar.success("✅ Data loaded successfully!")
        st.sidebar.info(f"Loaded {len(st.session_state.df)} samples with {len(st.session_state.df.columns)-1} features")

# Main content
if st.session_state.df is not None:
    df = st.session_state.df
    
    # Display dataset info
    st.subheader("Dataset Overview")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Samples", len(df))
    col2.metric("Features", len(df.columns) - 1)  # Exclude target
    col3.metric("Attack Types", df['target'].nunique())
    
    # Display sample data
    st.subheader("Sample Data")
    st.dataframe(df.head())
    
    # Model inference
    st.subheader("Model Prediction")
    
    if model_choice in st.session_state.models:
        model = st.session_state.models[model_choice]
        
        # Make prediction using our robust function
        prediction, proba = make_prediction(model, df)
        
        if prediction is not None:
            st.write("### Prediction for Random Sample")
            st.write(f"**Model:** {model_choice}")
            st.write(f"**Prediction:** {'Attack' if prediction[0] == 1 else 'Normal'}")
            
            if proba is not None:
                st.write("**Probability:**")
                proba_df = pd.DataFrame({
                    'Class': ['Normal', 'Attack'],
                    'Probability': [proba[0][0], proba[0][1]]
                })
                fig = px.bar(proba_df, x='Class', y='Probability', 
                            title='Prediction Probabilities')
                st.plotly_chart(fig)
        
            # Display feature importance if available
            if hasattr(model, 'feature_importances_') or hasattr(model, 'coef_'):
                st.subheader("Feature Importance")
                
                # Get feature names (excluding target)
                feature_names = [col for col in df.columns if col != 'target']
                
                # Handle different model types
                if hasattr(model, 'feature_importances_'):
                    # Tree-based models (Random Forest, etc.)
                    importances = model.feature_importances_
                elif hasattr(model, 'coef_'):
                    # Linear models (Logistic Regression, etc.)
                    if len(model.coef_.shape) > 1:  # For multi-class models
                        importances = np.abs(model.coef_[0])
                    else:
                        importances = np.abs(model.coef_)
                
                # Ensure we have the same number of features and importance scores
                if len(feature_names) == len(importances):
                    feature_importance = pd.DataFrame({
                        'Feature': feature_names,
                        'Importance': importances
                    }).sort_values('Importance', ascending=False)
                    
                    # Display top 10 features
                    fig = px.bar(feature_importance.head(10), 
                                x='Importance', 
                                y='Feature',
                                title='Top 10 Most Important Features')
                    st.plotly_chart(fig)
                else:
                    st.warning(f"Feature importance not displayed: Expected {len(feature_names)} features but got {len(importances)} importance scores")
    
    # Data visualization
    # ===================== 🌐 Enhanced Data Visualization =====================
    # ===================== 🌐 Enhanced Data Visualization =====================
            st.subheader("📊 Interactive Network Data Visualization")

            tab1, tab2, tab3, tab4, tab5 = st.tabs([
                "Attack Overview",
                "Traffic Heatmap",
                "Feature Correlation",
                "Protocol Insights",
                "Feature Distribution"
            ])

            # --- Tab 1: Attack Overview ---
            with tab1:
                st.markdown("### ⚔️ Attack Type Distribution")
                attack_counts = df['target'].value_counts().reset_index()
                attack_counts.columns = ['Attack Type', 'Count']

                # Top attacks bar
                top_attacks = attack_counts.head(10)
                fig1 = px.bar(
                    top_attacks,
                    x='Attack Type', y='Count', color='Attack Type', text='Count',
                    color_discrete_sequence=px.colors.qualitative.Set3,
                    title="Top 10 Most Common Attack Types"
                )
                fig1.update_layout(showlegend=False, template="plotly_dark")
                st.plotly_chart(fig1, use_container_width=True)

                if st.checkbox("Show Full Attack Pie Chart"):
                    fig_pie = px.pie(
                        attack_counts,
                        values='Count', names='Attack Type', hole=0.4,
                        title="All Attack Types (Donut Chart)",
                        color_discrete_sequence=px.colors.qualitative.Pastel
                    )
                    fig_pie.update_traces(textposition='inside', textinfo='percent+label')
                    fig_pie.update_layout(template="plotly_dark")
                    st.plotly_chart(fig_pie, use_container_width=True)

            # --- Tab 2: Traffic Heatmap ---
            with tab2:
                st.markdown("### 🌡 Feature Correlation Heatmap (Top 10 Numeric Columns)")
                numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
                if len(numeric_cols) > 1:
                    corr = df[numeric_cols].corr()
                    fig2 = px.imshow(
                        corr.iloc[:10, :10],
                        text_auto=True,
                        color_continuous_scale="Viridis",
                        title="Top 10 Numeric Features Correlation Matrix"
                    )
                    fig2.update_layout(template="plotly_dark", height=600)
                    st.plotly_chart(fig2, use_container_width=True)
                else:
                    st.warning("Not enough numeric columns for correlation heatmap.")

            # --- Tab 3: Feature Correlation Scatter ---
            with tab3:
                st.markdown("### 🔍 Feature Pair Analysis")
                num_cols = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c])]
                if len(num_cols) > 1:
                    col_x = st.selectbox("Select X-axis Feature", num_cols, index=0)
                    col_y = st.selectbox("Select Y-axis Feature", num_cols, index=1)
                    fig3 = px.scatter(
                        df.sample(min(2000, len(df))),  # limit for performance
                        x=col_x, y=col_y, color='target',
                        title=f"Scatter Plot: {col_x} vs {col_y}",
                        opacity=0.6,
                        color_discrete_sequence=px.colors.qualitative.Bold
                    )
                    fig3.update_layout(template="plotly_dark", height=600)
                    st.plotly_chart(fig3, use_container_width=True)

            # --- Tab 4: Protocol Insights ---
            with tab4:
                st.markdown("### 🌐 Protocol Type Traffic Overview")
                if 'protocol_type' in df.columns:
                    proto_agg = df.groupby('protocol_type')[['src_bytes', 'dst_bytes']].mean().reset_index()
                    fig4 = go.Figure()
                    fig4.add_trace(go.Bar(
                        x=proto_agg['protocol_type'], y=proto_agg['src_bytes'],
                        name='Avg Src Bytes', marker_color='skyblue'
                    ))
                    fig4.add_trace(go.Bar(
                        x=proto_agg['protocol_type'], y=proto_agg['dst_bytes'],
                        name='Avg Dst Bytes', marker_color='lightcoral'
                    ))
                    fig4.update_layout(
                        barmode='group',
                        title="Average Traffic Bytes by Protocol Type",
                        xaxis_title="Protocol Type",
                        yaxis_title="Average Bytes",
                        legend_title="Metric",
                        template="plotly_dark",
                        height=600
                    )
                    st.plotly_chart(fig4, use_container_width=True)
                else:
                    st.warning("⚠️ No 'protocol_type' column found in the dataset.")

            # --- Tab 5: Feature Distribution ---
            with tab5:
                st.markdown("### 📈 Feature Distribution Analysis")
                available_num_cols = [
                    col for col in df.columns 
                    if col not in ['target'] + [c for c in CATEGORICAL_COLS if c in df.columns]
                    and pd.api.types.is_numeric_dtype(df[col])
                ]

                if available_num_cols:
                    num_col = st.selectbox("Select a numerical feature to analyze:", available_num_cols)
                    df_viz = df.copy()
                    df_viz[num_col] = df_viz[num_col].replace(0, np.nan)
                    df_viz[f"log_{num_col}"] = np.log1p(df_viz[num_col])

                    subtab1, subtab2, subtab3 = st.tabs(["Histogram", "Boxplot", "Violin Plot"])

                    # Histogram
                    with subtab1:
                        fig_h = px.histogram(
                            df_viz, x=f"log_{num_col}", color='target', nbins=50,
                            title=f"Distribution of {num_col} (Log Scaled)",
                            color_discrete_sequence=px.colors.qualitative.Dark24
                        )
                        fig_h.update_layout(template="plotly_dark", height=500)
                        st.plotly_chart(fig_h, use_container_width=True)

                    # Boxplot
                    with subtab2:
                        fig_b = px.box(
                            df_viz, x='target', y=f"log_{num_col}", color='target',
                            title=f"Boxplot of {num_col} (Log Scaled)",
                            color_discrete_sequence=px.colors.qualitative.Safe
                        )
                        fig_b.update_layout(template="plotly_dark", height=500)
                        st.plotly_chart(fig_b, use_container_width=True)

                    # Violin Plot
                    with subtab3:
                        fig_v = px.violin(
                            df_viz.sample(min(3000, len(df_viz))),
                            x='target', y=f"log_{num_col}", color='target',
                            box=True, points="all",
                            title=f"Violin Plot of {num_col} by Attack Type",
                            color_discrete_sequence=px.colors.qualitative.Prism
                        )
                        fig_v.update_layout(template="plotly_dark", height=550)
                        st.plotly_chart(fig_v, use_container_width=True)

    # Numerical feature distribution
    if len(df.columns) > 1:
        # Get available numerical columns (exclude target and categorical columns)
        available_num_cols = [col for col in df.columns 
                            if col not in ['target'] + [c for c in CATEGORICAL_COLS if c in df.columns]
                            and pd.api.types.is_numeric_dtype(df[col])]
        
        if available_num_cols:
            num_col = st.selectbox("Select a numerical feature to visualize:", available_num_cols)
            
            if num_col in df.columns:
                fig2 = px.histogram(df, x=num_col, color='target',
                                  title=f'Distribution of {num_col} by Attack Type',
                                  marginal='box')
                st.plotly_chart(fig2)

else:
    st.info("Click the 'Load NSL-KDD Dataset' button in the sidebar to get started.")

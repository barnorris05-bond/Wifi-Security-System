import streamlit as st
from ai.context_builder import AIContextBuilder
from ai.nemotron_client import NemotronAnalyst

def render_ai_analysis_tab(scan_session, networks, assessments):
    st.header("🤖 AI Wi-Fi Security Analyst (Powered by Nemotron)")

    analyst = NemotronAnalyst()
    
    if not analyst.is_available():
        st.warning(
            "⚠️ **AI Analyst Unavailable**: NVIDIA_API_KEY environment variable not configured in .env. "
            "Displaying standard deterministic analysis."
        )
        return

    if st.button("Generate AI Security Explanation"):
        with st.spinner("Building context & querying Nemotron..."):
            context = AIContextBuilder.build_scan_context(scan_session, networks, assessments)
            ai_response = analyst.analyze_scan(context)

            if ai_response:
                st.subheader("📋 Executive Summary")
                st.write(ai_response.summary)

                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("### ⚠️ Key Risks Identified")
                    for risk in ai_response.key_risks:
                        st.markdown(f"- {risk}")

                with col2:
                    st.markdown("### 🛡️ Recommended Actions")
                    for rec in ai_response.recommendations:
                        st.markdown(f"- {rec}")

                st.subheader("🔬 Technical Interpretation")
                st.info(ai_response.technical_interpretation)
                
                st.caption(
                    "Note: AI explanations are advisory interpretations derived strictly from deterministic scan metrics."
                )
            else:
                st.error("Failed to generate AI insights. Please verify your network connection and API credentials.")

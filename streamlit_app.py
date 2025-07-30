from pathlib import Path

import streamlit as st
import pandas as pd
import altair as alt
import plotly.express as px
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode

def create_bar_chart(data, title):
    color_scale = alt.Scale(domain=["informational", "low", "medium", "high", "critical"],
                            range=["#00FFFF", "#00FF00", "#FFFF00", "#FFAF00", "#FF0000"])
    chart = alt.Chart(data).mark_bar().encode(
        x=alt.X("Level", sort=["critical", "high", "medium", "low", "informational"]),
        y=alt.Y("Value", scale=alt.Scale(domain=(0, 1000))),
        color=alt.Color("Level", scale=color_scale)
    ).properties(
        width=300,
        height=400,
        title=title
    )
    return chart

### Title and SelectBox
st.set_page_config(page_title='Comparison of Baseline Guides for Event Log Audit Settings',  layout='wide')
st.markdown("<h1 style='text-align: center;'>Comparison of Baseline Guides for Event Log Audit Settings</h1>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align: center;'>A security-driven approach to configuring Windows event logs</h3>", unsafe_allow_html=True)
_,m,_ = st.columns((1,10,1))
with m:
    selected_guide = st.selectbox('', ["Windows Default", "YamatoSecurity", "Australian Signals Directorate", "Microsoft(Server)", "Microsoft(Client)"], index=0, label_visibility="collapsed")
st.markdown("<hr>", unsafe_allow_html=True)
data_path = Path("./data") / selected_guide.replace(" ", "_").replace("(", "_").replace(")", "")
guide_link  = {
    "Windows Default": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
    "YamatoSecurity": "https://github.com/Yamato-Security/EnableWindowsLogSettings",
    "Australian Signals Directorate": "https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding",
    "Microsoft(Server)": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
    "Microsoft(Client)": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
}

### Audit settings
df_audit = pd.read_csv(data_path.joinpath("WELA-Audit-Result.csv"))
default_audit = Path("./data/Windows_Default")
df_audit_default = pd.read_csv(default_audit.joinpath("WELA-Audit-Result.csv"))
st.markdown(f"<h3 style='text-align: center;'>{selected_guide} Audit Settings</h3>", unsafe_allow_html=True)
st.markdown(f"<p style='text-align: center;'><a href='{guide_link[selected_guide]}' target='_blank'>{guide_link[selected_guide]}</a></p>", unsafe_allow_html=True)
df_combined = pd.concat([df_audit, df_audit_default], axis=1)
columns_to_display = [0, 1, 2, 14, 6, 7, 8]
df = df_combined.rename(columns={"CurrentSetting": "DefaultSetting"}).iloc[:, columns_to_display]

cellStyle = JsCode(
    r"""
    function(cellClassParams) {
        const defaultSetting = cellClassParams.data.DefaultSetting;
        const recommended = cellClassParams.data.RecommendedSetting;
    
        if (defaultSetting === "No Auditing" || defaultSetting === "Disabled") {
            if (
                recommended === null ||
                recommended === undefined ||
                recommended === "No Auditing" ||
                recommended === ""
            ) {
                return { 'background-color': 'lightgray' };
            } else {
                return { 'background-color': 'yellow' };
            }
        } else {
            return { 'background-color': 'palegreen' };
        }
    }
   """)

gb = GridOptionsBuilder.from_dataframe(df)
gb.configure_column("Category", pinned="left", width=150)
gb.configure_column("SubCategory", pinned="left", width=150)
go = gb.build()
go['defaultColDef']['cellStyle'] = cellStyle
AgGrid(data=df, gridOptions=go, allow_unsafe_jscode=True, key='grid1', editable=True)
st.markdown("<hr>", unsafe_allow_html=True)
m1,m2 = st.columns((8,3))
with m1:
    st.markdown(f"<h3 style='text-align: center;'>Log File Size Settings</h3>", unsafe_allow_html=True)
    msg = ""
    if selected_guide == "YamatoSecurity" or selected_guide == "Australian Signals Directorate":
        msg = f"The following table shows the recommended log size based on {selected_guide}."
    else:
        msg = f"{selected_guide} does not include any recommended settings regarding log size."
    st.markdown(f"<p style='text-align: center;'>{msg}</p>", unsafe_allow_html=True)
    csv_file = data_path.joinpath("WELA-FileSize-Result.csv")
    df = pd.read_csv(csv_file)
    columns_to_display = [0, 3, 4]
    df = df.iloc[:, columns_to_display]
    cellStyle = JsCode(
        r"""
        function(cellClassParams) {
             if (cellClassParams.data.Recommended === null ) {
                return {'background-color': `lightgray`}
             } else {
                return {'background-color': 'yellow'}
             }
        }
       """)

    gb = GridOptionsBuilder.from_dataframe(df)
    go = gb.build()
    go['defaultColDef']['cellStyle'] = cellStyle
    AgGrid(df, gridOptions=go, allow_unsafe_jscode=True, key="log_file_size", editable=True)

with m2:
    legend_data = [
        {"Color": "yellow", "Description": "Change required"},
        {"Color": "palegreen", "Description": "No change needed. Default setting is acceptable"},
        {"Color": "lightgray", "Description": "No change needed. No auditing or no recommended setting"},
    ]
    # 判例（Legend）用DataFrameの作成
    df_legend = pd.DataFrame(legend_data)

    # 判例の色分け表示用cellStyle
    legend_cellStyle = JsCode(
        r'''
        function(cellClassParams) {
            if (cellClassParams.value === "lightgray") {
                return { 'background-color': 'lightgray' };
            } else if (cellClassParams.value === "yellow") {
                return { 'background-color': 'yellow' };
            } else if (cellClassParams.value === "palegreen") {
                return { 'background-color': 'palegreen' };
            }
        }
        '''
    )

    st.markdown(f"<h3 style='text-align: center;'>Legend</h3>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>The cell colors represent the following states.</p>", unsafe_allow_html=True)
    gb = GridOptionsBuilder.from_dataframe(df_legend)
    gb.configure_column("Color", cellStyle=legend_cellStyle)
    go = gb.build()
    AgGrid(df_legend, gridOptions=go, allow_unsafe_jscode=True, key='legend', editable=False)

### Sigma Rule Statistics
st.markdown("<br>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align: center;'>Statistics on Usable and Unusable Sigma Rule(hayabusa rule)</h2>", unsafe_allow_html=True)

df_usable = pd.read_csv(data_path.joinpath("UsableRules.csv"))
df_unusable = pd.read_csv(data_path.joinpath("UnusableRules.csv"))

m1, m2, = st.columns(2)
level_order = ["critical", "high", "medium", "low", "informational"]
with m1:
    df_usable["level"] = pd.Categorical(df_usable["level"], categories=level_order, ordered=True)
    df_usable.sort_values("level", inplace=True)
    data = df_usable["level"].value_counts().reindex(level_order).reset_index()
    data.columns = ["Level", "Value"]
    usable_total = data["Value"].sum()

    ## Bar chart
    st.markdown(f"<h4 style='text-align: center;'>Usable Rules Group by Level (Total: {usable_total})</h4>", unsafe_allow_html=True)
    st.altair_chart(create_bar_chart(data, ""), use_container_width=True)

with m2:
    df_unusable["level"] = pd.Categorical(df_unusable["level"], categories=level_order, ordered=True)
    df_unusable.sort_values("level", inplace=True)
    data = df_unusable["level"].value_counts().reindex(level_order).reset_index()
    data.columns = ["Level", "Value"]
    unusable_total = data["Value"].sum()

    ## Bar chart
    st.markdown(f"<h4 style='text-align: center;'>Unusable Rules Group by Level (Total: {unusable_total})</h4>", unsafe_allow_html=True)
    st.altair_chart(create_bar_chart(data, ""), use_container_width=True)

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)
## List
st.markdown(f"<h4 style='text-align: center;'>Usable Rules List (Total: {usable_total})</h4>", unsafe_allow_html=True)
cellStyle_unusable = JsCode(
    r"""
    function(cellClassParams) {
        return {'background-color': 'lightcyan'}
    }
    """
)
gb = GridOptionsBuilder.from_dataframe(df_usable)
gb.configure_column("title", pinned="left", width=150)
gb.configure_grid_options(enableCellTextSelection=True)
gb.configure_grid_options(ensureDomOrder=True)
go = gb.build()
go['defaultColDef']['cellStyle'] = cellStyle_unusable

AgGrid(df_usable, gridOptions=go, allow_unsafe_jscode=True, key='usable_rules', editable=True)
st.markdown("<br>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)

## List
st.markdown(f"<h4 style='text-align: center;'>Unusable Rules List (Total: {unusable_total})</h4>", unsafe_allow_html=True)
cellStyle_unusable = JsCode(
    r"""
    function(cellClassParams) {
        return {'background-color': 'gold'}
    }
    """
)
gb = GridOptionsBuilder.from_dataframe(df_unusable)
gb.configure_column("title", pinned="left", width=150)
go = gb.build()
go['defaultColDef']['cellStyle'] = cellStyle_unusable
gb.configure_grid_options(enableCellTextSelection=True)
gb.configure_grid_options(ensureDomOrder=True)
AgGrid(df_unusable, gridOptions=go, allow_unsafe_jscode=True, key='un_usable_rules', editable=True)

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)

m1, m2, = st.columns((1, 1))
with m1:
    columns_to_display = [0, 1, 2]
    df_enabled = df_audit[(df_audit["CurrentSetting"] == "Enabled") | (df_audit["CurrentSetting"] == "Success") | (df_audit["CurrentSetting"] == "Success and Failure")]
    df_enabled = df_enabled.iloc[:, columns_to_display]
    df_enabled = df_enabled.sort_values(by="RuleCount", ascending=False)
    df_top10 = df_enabled.head(10)
    df_top10.loc[:, 'SubCategory'] = df_top10['SubCategory'].fillna(df_top10['Category'])
    data = df_top10
    st.markdown(f"<h4 style='text-align: center;'>Usable Rules Group by Audit Category</h4>", unsafe_allow_html=True)
    chart = alt.Chart(data).mark_bar().encode(
        x=alt.X("SubCategory", sort="y", axis=alt.Axis(labelAngle=-45, labelOverlap=False)),
        y=alt.Y("RuleCount")
    ).properties(
        width=300,
        height=400,
        title=""
    )
    st.altair_chart(chart, use_container_width=True)


with m2:
    columns_to_display = [0, 1, 2]
    df_disabled = df_audit[df_audit["CurrentSetting"] == "No Auditing"]
    df_disabled = df_disabled.iloc[:, columns_to_display]
    df_disabled = df_disabled.sort_values(by="RuleCount", ascending=False)
    df_top10 = df_disabled.head(10)
    df_top10.loc[:, 'SubCategory'] = df_top10['SubCategory'].fillna(df_top10['Category'])
    data = df_top10
    st.markdown(f"<h4 style='text-align: center;'>Unusable Rules Group by Audit Category</h4>", unsafe_allow_html=True)
    chart = alt.Chart(data).mark_bar().encode(
        x=alt.X("SubCategory", sort="y", axis=alt.Axis(labelAngle=-45, labelOverlap=False)),
        y=alt.Y("RuleCount"),
        color=alt.value("#D2B48C")
    ).properties(
        width=300,
        height=400,
        title=""
    )
    st.altair_chart(chart, use_container_width=True)
st.markdown("<br>", unsafe_allow_html=True)

m1, m2 = st.columns(2)
with m1:
    st.markdown("<hr>", unsafe_allow_html=True)
    data = df_usable["service"].dropna()
    st.markdown(f"<h4 style='text-align: center;'>Usable Rules Group by Sigma Service</h4>", unsafe_allow_html=True)
    data = data.value_counts().head(10).reset_index()
    data.columns = ["Service", "Count"]
    chart = alt.Chart(data).mark_bar().encode(
        x=alt.X("Service", sort="y", axis=alt.Axis(labelAngle=-45, labelOverlap=False)),
        y=alt.Y("Count")
    ).properties(
        width=600,
        height=400,
        title=""
    )
    st.altair_chart(chart, use_container_width=True)

with m2:
    st.markdown("<hr>", unsafe_allow_html=True)
    data = df_unusable["service"].dropna()
    st.markdown(f"<h4 style='text-align: center;'>Unusable Rules Group by Sigma Service</h4>", unsafe_allow_html=True)
    data = data.value_counts().head(10).reset_index()
    data.columns = ["Category", "Count"]
    chart = alt.Chart(data).mark_bar().encode(
        x=alt.X("Category", sort="y", axis=alt.Axis(labelAngle=-45, labelOverlap=False)),
        y=alt.Y("Count"),
        color=alt.value("#D2B48C")
    ).properties(
        width=600,
        height=400,
        title=""
    )
    st.altair_chart(chart, use_container_width=True)


m1, m2 = st.columns(2)
with m1:
    st.markdown("<hr>", unsafe_allow_html=True)
    data = df_usable["category"].dropna()
    st.markdown(f"<h4 style='text-align: center;'>Usable Sigma Category</h4>", unsafe_allow_html=True)
    data = data.value_counts().head(10).reset_index()
    data.columns = ["Service", "Count"]
    chart = alt.Chart(data).mark_bar().encode(
        x=alt.X("Service", sort="y", axis=alt.Axis(labelAngle=-45, labelOverlap=False)),
        y=alt.Y("Count")
    ).properties(
        width=600,
        height=400,
        title=""
    )
    st.altair_chart(chart, use_container_width=True)

with m2:
    st.markdown("<hr>", unsafe_allow_html=True)
    data = df_unusable["category"].dropna()
    st.markdown(f"<h4 style='text-align: center;'>Unusable Sigma Category</h4>", unsafe_allow_html=True)
    data = data.value_counts().head(10).reset_index()
    data.columns = ["Category", "Count"]
    chart = alt.Chart(data).mark_bar().encode(
        x=alt.X("Category", sort="y", axis=alt.Axis(labelAngle=-45, labelOverlap=False)),
        y=alt.Y("Count"),
        color=alt.value("#D2B48C")
    ).properties(
        width=600,
        height=400,
        title=""
    )
    st.altair_chart(chart, use_container_width=True)


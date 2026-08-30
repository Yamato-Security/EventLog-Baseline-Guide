from pathlib import Path

import streamlit as st
import pandas as pd
import altair as alt
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode

DATA_ROOT = Path("./data")
DEFAULT_GUIDE = "Windows Default"
GUIDES = [DEFAULT_GUIDE, "YamatoSecurity", "Australian Signals Directorate", "Microsoft(Server)", "Microsoft(Client)"]
LEVEL_ORDER = ["critical", "high", "medium", "low", "informational"]
# Any of these means the subcategory is actually being audited, so its rules are usable.
AUDITING_SETTINGS = ["Enabled", "Success", "Failure", "Success and Failure"]
# WELA's audit-filesize ignores -Baseline and always emits the hardcoded YamatoSecurity
# log size table, so that is the only guide whose "Recommended" column is meaningful.
LOG_SIZE_RECOMMENDATION_GUIDE = "YamatoSecurity"

GUIDE_LINKS = {
    "Windows Default": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
    "YamatoSecurity": "https://github.com/Yamato-Security/EnableWindowsLogSettings",
    "Australian Signals Directorate": "https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-monitoring/windows-event-logging-and-forwarding",
    "Microsoft(Server)": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
    "Microsoft(Client)": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
}


def guide_data_path(guide):
    return DATA_ROOT / guide.replace(" ", "_").replace("(", "_").replace(")", "")


def fix_arrow_utf8(df):
    """Convert object columns to str to avoid Arrow LargeUtf8 serialization error."""
    for col in df.select_dtypes(include=["object"]).columns:
        df[col] = df[col].astype(str).where(df[col].notna(), other=None)
    return df


def normalize_settings(df):
    """Trim stray whitespace and unify known typos so cell styling can match on the value."""
    aliases = {"Enable": "Enabled", "Patially": "Partially Enabled"}
    for col in ("DefaultSetting", "CurrentSetting", "RecommendedSetting"):
        if col in df.columns and df[col].dtype == object:
            df[col] = df[col].str.strip().replace(aliases)
    return df


def load_audit(guide):
    return normalize_settings(pd.read_csv(guide_data_path(guide).joinpath("WELA-Audit-Result.csv")))


def load_rules(guide, file_name):
    # WELA lists the same rule once per channel it maps to, so identical rows are dropped
    # to keep the totals and the group-by charts from being inflated.
    return pd.read_csv(guide_data_path(guide).joinpath(file_name)).drop_duplicates()


def with_windows_default_setting(df_guide, df_default):
    """Attach the Windows default setting, matched on audit category.

    The guide CSVs do not always list the categories in the same order, so joining them
    by row position silently pairs a category with another category's default setting.
    """
    keys = ["Category", "SubCategory"]
    left = df_guide.drop(columns=["DefaultSetting"]).copy()
    right = df_default[keys + ["DefaultSetting"]].copy()
    for frame in (left, right):
        frame["_key"] = frame["Category"].fillna("") + " / " + frame["SubCategory"].fillna("")
    merged = left.merge(right.drop(columns=keys), on="_key", how="left", validate="many_to_one")
    return merged.drop(columns="_key")


def level_counts(df_rules):
    counts = df_rules["level"].value_counts().reindex(LEVEL_ORDER, fill_value=0).reset_index()
    counts.columns = ["Level", "Value"]
    return counts


def sort_by_level(df_rules):
    df_rules = df_rules.copy()
    df_rules["level"] = pd.Categorical(df_rules["level"], categories=LEVEL_ORDER, ordered=True)
    return df_rules.sort_values("level")


def axis_upper_bound(value, step=250):
    """Round up to a shared, readable axis maximum so the bars are never clipped."""
    return max(step, -(-int(value) // step) * step)


def create_bar_chart(data, y_max):
    color_scale = alt.Scale(domain=["informational", "low", "medium", "high", "critical"],
                            range=["#00FFFF", "#00FF00", "#FFFF00", "#FFAF00", "#FF0000"])
    chart = alt.Chart(data).mark_bar().encode(
        x=alt.X("Level", sort=LEVEL_ORDER),
        y=alt.Y("Value", scale=alt.Scale(domain=(0, y_max))),
        color=alt.Color("Level", scale=color_scale)
    ).properties(
        width=300,
        height=400
    )
    return chart


def create_audit_category_chart(df_source, color=None):
    data = df_source[["Category", "SubCategory", "RuleCount"]].sort_values(
        by="RuleCount", ascending=False).head(10).copy()
    data["SubCategory"] = data["SubCategory"].fillna(data["Category"])
    encodings = {
        "x": alt.X("SubCategory", sort="y", axis=alt.Axis(labelAngle=-45, labelOverlap=False)),
        "y": alt.Y("RuleCount"),
    }
    if color:
        encodings["color"] = alt.value(color)
    return alt.Chart(data).mark_bar().encode(**encodings).properties(width=300, height=400)


def create_count_chart(series, axis_title, color=None):
    data = series.dropna().value_counts().head(10).reset_index()
    data.columns = [axis_title, "Count"]
    encodings = {
        "x": alt.X(axis_title, sort="y", axis=alt.Axis(labelAngle=-45, labelOverlap=False)),
        "y": alt.Y("Count"),
    }
    if color:
        encodings["color"] = alt.value(color)
    return alt.Chart(data).mark_bar().encode(**encodings).properties(width=600, height=400)


### Title and SelectBox
st.set_page_config(page_title='Comparison of Baseline Guides for Event Log Audit Settings',  layout='wide')
st.markdown("<h1 style='text-align: center;'>Comparison of Baseline Guides for Event Log Audit Settings</h1>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align: center;'>A security-driven approach to configuring Windows event logs</h3>", unsafe_allow_html=True)
_,m,_ = st.columns((1,10,1))
with m:
    selected_guide = st.selectbox('Baseline guide', GUIDES, index=0, label_visibility="collapsed")
st.markdown("<hr>", unsafe_allow_html=True)
data_path = guide_data_path(selected_guide)

### Audit settings
df_audit = load_audit(selected_guide)
df_audit_default = load_audit(DEFAULT_GUIDE)
st.markdown(f"<h3 style='text-align: center;'>{selected_guide} Audit Settings</h3>", unsafe_allow_html=True)
st.markdown(f"<p style='text-align: center;'><a href='{GUIDE_LINKS[selected_guide]}' target='_blank'>{GUIDE_LINKS[selected_guide]}</a></p>", unsafe_allow_html=True)
df_combined = with_windows_default_setting(df_audit, df_audit_default)
if selected_guide == DEFAULT_GUIDE:
    # The RecommendedSetting stored under Windows Default is whatever baseline WELA was run
    # with (YamatoSecurity), not a Windows recommendation, so it is not shown here.
    columns_to_display = ["Category", "SubCategory", "RuleCount", "DefaultSetting"]
else:
    columns_to_display = ["Category", "SubCategory", "RuleCount", "DefaultSetting",
                          "RecommendedSetting", "Volume", "Note"]
df = df_combined[columns_to_display].copy()

cellStyle = JsCode(
    r"""
    function(cellClassParams) {
        const row = cellClassParams.data;
        const defaultSetting = (row.DefaultSetting == null ? "" : String(row.DefaultSetting)).trim();
        const recommended = (row.RecommendedSetting == null ? "" : String(row.RecommendedSetting)).trim();

        const auditingOff = (defaultSetting === "" || defaultSetting === "No Auditing" || defaultSetting === "Disabled");
        const noRecommendation = (recommended === "" || recommended === "nan" || recommended === "No Auditing");

        if (noRecommendation || recommended === defaultSetting) {
            return { 'background-color': auditingOff ? 'lightgray' : 'palegreen' };
        }
        return { 'background-color': 'yellow' };
    }
   """)

df = fix_arrow_utf8(df)
gb = GridOptionsBuilder.from_dataframe(df)
gb.configure_column("Category", pinned="left", width=150)
gb.configure_column("SubCategory", pinned="left", width=150)
go = gb.build()
go['defaultColDef']['cellStyle'] = cellStyle
AgGrid(data=df, gridOptions=go, allow_unsafe_jscode=True, key='grid1')
st.markdown("<hr>", unsafe_allow_html=True)
m1,m2 = st.columns((8,3))
with m1:
    st.markdown(f"<h3 style='text-align: center;'>Log File Size Settings</h3>", unsafe_allow_html=True)
    df_size = pd.read_csv(data_path.joinpath("WELA-FileSize-Result.csv"))
    has_log_size_recommendation = (selected_guide == LOG_SIZE_RECOMMENDATION_GUIDE
                                   and df_size["Recommended"].notna().any())
    if has_log_size_recommendation:
        msg = f"The following table shows the recommended log size based on {selected_guide}."
    else:
        msg = f"{selected_guide} does not include any recommended settings regarding log size."
    st.markdown(f"<p style='text-align: center;'>{msg}</p>", unsafe_allow_html=True)
    size_columns = ["LogFile", "Default", "MaxLogSize"]
    if has_log_size_recommendation:
        size_columns += ["Recommended", "CorrectSetting"]
    df_size = fix_arrow_utf8(df_size[size_columns].copy())
    cellStyle = JsCode(
        r"""
        function(cellClassParams) {
             const recommended = cellClassParams.data.Recommended;
             if (recommended === null || recommended === undefined || recommended === "") {
                return {'background-color': 'lightgray'}
             }
             const correct = (cellClassParams.data.CorrectSetting === "Y");
             return {'background-color': correct ? 'palegreen' : 'yellow'}
        }
       """)

    gb = GridOptionsBuilder.from_dataframe(df_size)
    if "CorrectSetting" in df_size.columns:
        # Kept in the row data so the styling can read it, but not shown as a column.
        gb.configure_column("CorrectSetting", hide=True)
    go = gb.build()
    go['defaultColDef']['cellStyle'] = cellStyle
    AgGrid(df_size, gridOptions=go, allow_unsafe_jscode=True, key="log_file_size")

with m2:
    legend_data = [
        {"Color": "yellow", "Description": "Change required"},
        {"Color": "palegreen", "Description": "No change needed. Current setting is acceptable"},
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
    AgGrid(fix_arrow_utf8(df_legend), gridOptions=go, allow_unsafe_jscode=True, key='legend', editable=False)

### Sigma Rule Statistics
st.markdown("<br>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align: center;'>Statistics on Usable and Unusable Sigma Rule(hayabusa rule)</h3>", unsafe_allow_html=True)

df_usable = sort_by_level(load_rules(selected_guide, "UsableRules.csv"))
df_unusable = sort_by_level(load_rules(selected_guide, "UnusableRules.csv"))

usable_counts = level_counts(df_usable)
unusable_counts = level_counts(df_unusable)
usable_total = usable_counts["Value"].sum()
unusable_total = unusable_counts["Value"].sum()
# Shared upper bound so the two charts stay comparable and nothing is cut off.
level_axis_max = axis_upper_bound(max(usable_counts["Value"].max(), unusable_counts["Value"].max()))

m1, m2, = st.columns(2)
with m1:
    ## Bar chart
    st.markdown(f"<h4 style='text-align: center;'>Usable Rules Group by Level (Total: {usable_total})</h4>", unsafe_allow_html=True)
    st.altair_chart(create_bar_chart(usable_counts, level_axis_max), use_container_width=True)

with m2:
    ## Bar chart
    st.markdown(f"<h4 style='text-align: center;'>Unusable Rules Group by Level (Total: {unusable_total})</h4>", unsafe_allow_html=True)
    st.altair_chart(create_bar_chart(unusable_counts, level_axis_max), use_container_width=True)

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)
## List
st.markdown(f"<h4 style='text-align: center;'>Usable Rules List (Total: {usable_total})</h4>", unsafe_allow_html=True)
cellStyle_usable = JsCode(
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
go['defaultColDef']['cellStyle'] = cellStyle_usable

AgGrid(fix_arrow_utf8(df_usable), gridOptions=go, allow_unsafe_jscode=True, key='usable_rules')
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
gb.configure_grid_options(enableCellTextSelection=True)
gb.configure_grid_options(ensureDomOrder=True)
go = gb.build()
go['defaultColDef']['cellStyle'] = cellStyle_unusable
AgGrid(fix_arrow_utf8(df_unusable), gridOptions=go, allow_unsafe_jscode=True, key='un_usable_rules')

st.markdown("<br>", unsafe_allow_html=True)
st.markdown("<hr>", unsafe_allow_html=True)

# Anything that is not actively audited (No Auditing, Disabled, unset) makes its rules
# unusable, so both charts split on the same condition to stay exhaustive.
is_auditing = df_audit["CurrentSetting"].isin(AUDITING_SETTINGS)
m1, m2, = st.columns((1, 1))
with m1:
    st.markdown(f"<h4 style='text-align: center;'>Usable Rules Group by Audit Category</h4>", unsafe_allow_html=True)
    st.altair_chart(create_audit_category_chart(df_audit[is_auditing]), use_container_width=True)

with m2:
    st.markdown(f"<h4 style='text-align: center;'>Unusable Rules Group by Audit Category</h4>", unsafe_allow_html=True)
    st.altair_chart(create_audit_category_chart(df_audit[~is_auditing], color="#D2B48C"), use_container_width=True)
st.markdown("<br>", unsafe_allow_html=True)

m1, m2 = st.columns(2)
with m1:
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown(f"<h4 style='text-align: center;'>Usable Rules Group by Sigma Service</h4>", unsafe_allow_html=True)
    st.altair_chart(create_count_chart(df_usable["service"], "Service"), use_container_width=True)

with m2:
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown(f"<h4 style='text-align: center;'>Unusable Rules Group by Sigma Service</h4>", unsafe_allow_html=True)
    st.altair_chart(create_count_chart(df_unusable["service"], "Service", color="#D2B48C"), use_container_width=True)


m1, m2 = st.columns(2)
with m1:
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown(f"<h4 style='text-align: center;'>Usable Sigma Category</h4>", unsafe_allow_html=True)
    st.altair_chart(create_count_chart(df_usable["category"], "Category"), use_container_width=True)

with m2:
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown(f"<h4 style='text-align: center;'>Unusable Sigma Category</h4>", unsafe_allow_html=True)
    st.altair_chart(create_count_chart(df_unusable["category"], "Category", color="#D2B48C"), use_container_width=True)

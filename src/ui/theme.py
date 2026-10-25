"""Centralized design tokens and functional visualization components."""
from __future__ import annotations

from html import escape
from pathlib import Path
from PIL import Image, ImageDraw
import streamlit as st

ASSETS = Path(__file__).resolve().parents[2] / "assets"

CSS = """
<style>
@font-face{font-family:Plex;src:url('/app/static/IBMPlexSans-Regular.woff2') format('woff2');font-weight:400;font-display:swap}
@font-face{font-family:PlexMono;src:url('/app/static/IBMPlexMono-Regular.woff2') format('woff2');font-display:swap}
:root{--graphite:#15191a;--panel:#1e2425;--ivory:#ede9df;--muted:#a8b3b1;--teal:#8cbab1;--oxide:#d18e7d;--line:#3b4848}
html,body,[data-testid="stAppViewContainer"],button,input,textarea,select{font-family:Plex,'IBM Plex Sans',sans-serif}
h1,h2,h3,h4{font-family:Plex,'IBM Plex Sans',sans-serif!important;font-weight:400!important;letter-spacing:-.035em}
h1{font-size:2.6rem!important;line-height:1.12!important;padding-top:0!important}
h2{font-size:1.45rem!important} h3{font-size:1.1rem!important}
p,li{line-height:1.6} code,.mono,[data-testid="stMetricValue"]{font-family:PlexMono,'IBM Plex Mono',monospace!important}
[data-testid="stMainBlockContainer"]{padding:2.5rem 3rem 3rem;max-width:1600px}
[data-testid="stSidebar"]{border-right:1px solid var(--line)}
[data-testid="stSidebar"]>div:first-child{padding-top:1.2rem}
[data-testid="stSidebar"] hr{margin:1.4rem 0;border-color:var(--line)}
[data-testid="stSidebar"] [data-testid="stRadio"] label{padding:.2rem 0}
button,[data-baseweb="select"]>div,[data-baseweb="input"],[data-testid="stVerticalBlockBorderWrapper"],[data-testid="stExpander"],[data-testid="stAlert"]{border-radius:2px!important;box-shadow:none!important}
button:focus-visible,a:focus-visible{outline:2px solid var(--teal)!important;outline-offset:3px}
[data-testid="stHeader"]{background:var(--graphite)}
[data-testid="stToolbar"]{display:none}
.wordmark{font-size:1.5rem;letter-spacing:.19em;color:var(--ivory);font-weight:600}
.wordmark small{display:block;font-family:PlexMono,monospace;font-size:.6rem;letter-spacing:.13em;color:var(--teal);margin-top:8px}
.eyebrow{font-family:PlexMono,monospace;letter-spacing:.13em;font-size:.67rem;text-transform:uppercase;color:var(--teal);margin:0 0 1rem}
.masthead{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:1rem;margin-bottom:2.2rem;gap:1rem}
.masthead span{font-family:PlexMono,monospace;font-size:.67rem;letter-spacing:.08em;color:var(--muted)}
.launch{border-left:2px solid var(--oxide);padding:8px 12px;color:var(--oxide);font-family:PlexMono,monospace;font-size:.66rem;line-height:1.6}
.deck{color:var(--muted);font-size:1rem;max-width:760px;margin-bottom:1.8rem}
.instrument{border:1px solid var(--line);padding:1.7rem 1.8rem;background:var(--panel);margin:0 0 1rem}
.instrument-top{display:flex;justify-content:space-between;gap:1rem;align-items:start}
.instrument .score{font:4.8rem/1.15 PlexMono,monospace;letter-spacing:-.07em;color:var(--ivory)}
.instrument .score small{font-size:1.6rem;letter-spacing:0}
.instrument .scenario{color:var(--muted);font-size:.85rem;max-width:170px;text-align:right}
.segments{display:flex;gap:4px;height:24px;margin:1.5rem 0 .8rem}
.segment{flex:1;background:#333e3f;border-top:2px solid #526161}
.segment.filled{background:#8cbab1;border-color:#b6d1c9}
.instrument-note{font: .67rem/1.6 PlexMono,monospace;color:var(--muted)}
.source-row{display:grid;grid-template-columns:1.5fr 1fr .7fr;gap:1rem;padding:.65rem 0;border-bottom:1px solid var(--line);font-size:.82rem}
.source-row b{font-weight:400;color:var(--ivory)}
.source-row span{font: .7rem/1.6 PlexMono,monospace;color:var(--muted)}
.index-number{font: .72rem PlexMono,monospace;color:var(--teal);margin-bottom:.6rem}
.stat{border-top:1px solid var(--line);padding:1rem 0}
.stat .value{font:2.1rem PlexMono,monospace;letter-spacing:-.05em}
.stat .label{font: .65rem PlexMono,monospace;color:var(--muted);letter-spacing:.08em;text-transform:uppercase}
.footer{border-top:1px solid var(--line);margin-top:3rem;padding-top:1rem;color:var(--muted);font: .65rem/1.7 PlexMono,monospace}
@media(max-width:760px){[data-testid="stMainBlockContainer"]{padding:1.5rem 1rem}h1{font-size:2rem!important}.instrument{padding:1rem}.instrument .score{font-size:3.7rem}.masthead{margin-bottom:1.4rem}.source-row{grid-template-columns:1.3fr 1fr .6fr;gap:.4rem}}
@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;animation:none!important;transition:none!important}}
</style>
"""


def favicon() -> Image.Image:
    """Original THREXIS T: three evidence tracks joined by a central spine."""
    image = Image.new("RGB", (64, 64), "#15191a")
    draw = ImageDraw.Draw(image)
    draw.rectangle((9, 10, 54, 17), fill="#8cbab1")
    draw.rectangle((28, 17, 35, 53), fill="#ede9df")
    draw.rectangle((9, 26, 23, 32), fill="#8cbab1")
    draw.rectangle((40, 26, 54, 32), fill="#8cbab1")
    draw.rectangle((9, 41, 23, 47), fill="#d18e7d")
    draw.rectangle((40, 41, 54, 47), fill="#8cbab1")
    return image


def apply_theme():
    st.markdown(CSS, unsafe_allow_html=True)


def page_header(index: str, title: str, description: str):
    st.markdown('<div class="masthead"><span>THREXIS / FORENSIC RESEARCH WORKSTATION</span><span>LOCAL ACADEMIC DEMONSTRATION</span></div>', unsafe_allow_html=True)
    st.markdown(f'<div class="eyebrow">{escape(index)}</div>', unsafe_allow_html=True)
    st.title(title)
    st.markdown(f'<div class="deck">{escape(description)}</div>', unsafe_allow_html=True)


def instrument(details: dict):
    score = details["readiness_percentage"]
    segments = "".join(f'<span class="segment{" filled" if (i + 1) * 5 <= score else ""}"></span>' for i in range(20))
    rows = "".join(
        f'<div class="source-row"><b>{escape(item["source_type"].replace("_", " "))}</b>'
        f'<span>{escape(item["status"].replace("_", " ").upper())}</span>'
        f'<span>{item["weighted_contribution"]:.3f}</span></div>'
        for item in details["requirements"])
    html = f"""<section class="instrument" aria-label="Forensic readiness assessment">
    <div class="eyebrow">READINESS / WEIGHTED SOURCE COVERAGE</div>
    <div class="instrument-top"><div class="score">{score:.1f}<small>%</small></div>
    <div class="scenario">{escape(details["profile_display_name"])}</div></div>
    <div class="segments" role="img" aria-label="Readiness {score:.1f} percent. Twenty segments, five percentage points each.">{segments}</div>
    <div class="instrument-note">0 &nbsp; / &nbsp; 20 SEGMENTS × 5 POINTS &nbsp; / &nbsp; 100</div>
    <div class="source-row"><span>EVIDENCE SOURCE</span><span>STATUS</span><span>CONTRIBUTION</span></div>{rows}
    <p class="instrument-note">Weighted status model. Availability and integrity are assessed separately.</p></section>"""
    st.markdown(html, unsafe_allow_html=True)


def statistic(label: str, value):
    st.markdown(f'<div class="stat"><div class="label">{escape(label)}</div><div class="value">{escape(str(value))}</div></div>', unsafe_allow_html=True)

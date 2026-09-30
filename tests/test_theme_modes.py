import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = (ROOT / "server" / "dashboard.html").read_text(encoding="utf-8")
APP = (ROOT / "server" / "app.py").read_text(encoding="utf-8")


def test_theme_selector_offers_both_new_dark_themes():
    assert 'id="themeSelect"' in DASHBOARD
    assert '<option value="dim">Dim Slate</option>' in DASHBOARD
    assert '<option value="carbon">Carbon Gray</option>' in DASHBOARD


def test_new_dark_themes_define_distinct_readable_surface_tokens():
    assert '[data-theme="dim"]{' in DASHBOARD
    assert '--bg:#22272E; --surface:#2D333B; --ink:#CDD9E5; --muted:#ADBAC7;' in DASHBOARD
    assert '[data-theme="carbon"]{' in DASHBOARD
    assert '--bg:#161616; --surface:#262626; --ink:#F4F4F4; --muted:#C6C6C6;' in DASHBOARD


def test_light_dark_theme_buttons_use_a_dark_contrast_color():
    assert '--accent-ink:#0D1117;' in DASHBOARD
    assert '--accent-ink:#161616;' in DASHBOARD
    assert '.btn{background:var(--accent);color:var(--accent-ink);' in DASHBOARD
    assert '.btn.danger{background:var(--danger);color:#fff}' in DASHBOARD


def test_theme_logic_applies_named_theme_and_preserves_old_dark_cookie():
    start = DASHBOARD.index('/* ---------- theme ---------- */')
    end = DASHBOARD.index('/* ---------- settings ---------- */', start)
    theme_script = DASHBOARD[start:end]
    harness = f"""
const assert = require('node:assert/strict');
let selected = {{value: ''}};
let applied = '';
const document = {{
  cookie: '',
  documentElement: {{setAttribute: (name, value) => {{if(name === 'data-theme') applied = value;}}}},
  querySelector: selector => selector === '#themeSelect' ? selected : null
}};
const window = {{matchMedia: () => ({{matches: false}})}};
const qs = selector => document.querySelector(selector);
let state = {{}};
{theme_script}
applyTheme('dim');
assert.equal(applied, 'dim');
assert.equal(selected.value, 'dim');
assert.equal(state.theme, 'dim');
document.cookie = 'session=x; outpost_theme=dark';
initTheme();
assert.equal(applied, 'dark');
console.log(JSON.stringify({{applied, selected: selected.value, stateTheme: state.theme}}));
"""
    result = subprocess.run(
        ["node", "-e", harness],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(result.stdout) == {
        "applied": "dark",
        "selected": "dark",
        "stateTheme": "dark",
    }


def test_platform_version_is_1316():
    assert 'PLATFORM_VERSION = "1.31.6"' in APP

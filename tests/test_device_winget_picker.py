from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = (ROOT / "server" / "dashboard.html").read_text(encoding="utf-8")
APP = (ROOT / "server" / "app.py").read_text(encoding="utf-8")


def test_device_overview_opens_a_searchable_winget_selection_menu():
    assert 'onclick="openWingetPicker(' in DASHBOARD
    assert 'id="wingetPickerModal"' in DASHBOARD
    assert 'id="wingetSearch"' in DASHBOARD
    assert 'function renderWingetPicker()' in DASHBOARD
    assert 'function selectVisibleWingetApps()' in DASHBOARD
    assert 'function clearWingetSelection()' in DASHBOARD


def test_winget_menu_uses_the_selected_device_software_inventory():
    assert '@app.get("/api/machines/{agent_id}/software")' in APP
    assert 'SELECT hostname, software FROM agents WHERE id=?' in APP
    assert "api(`/api/machines/${id}/software`)" in DASHBOARD
    assert 'installed_version' in DASHBOARD
    assert 'publisher' in DASHBOARD


def test_winget_menu_can_queue_selected_apps_or_all_eligible_apps():
    assert "body:JSON.stringify({ names })" in DASHBOARD
    assert "body:JSON.stringify({ names: [] })" in DASHBOARD
    assert "if(!names.length)return toast('Select at least one application')" in DASHBOARD
    assert 'wingetNamesB64' in APP
    assert "upgrade --name $name --exact" in APP
    assert "upgrade --all" in APP


def test_platform_version_is_1316():
    assert 'PLATFORM_VERSION = "1.31.6"' in APP

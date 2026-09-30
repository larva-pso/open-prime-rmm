from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = (ROOT / "server" / "dashboard.html").read_text(encoding="utf-8")
APP = (ROOT / "server" / "app.py").read_text(encoding="utf-8")


def test_device_overview_exposes_a_winget_install_catalog():
    assert 'onclick="openWingetInstall(' in DASHBOARD
    assert 'id="wingetInstallModal"' in DASHBOARD
    assert 'Approved catalog' in DASHBOARD
    assert 'Search Winget online' in DASHBOARD
    assert 'function renderWingetApprovedCatalog()' in DASHBOARD


def test_approved_catalog_is_server_owned_and_uses_verified_package_ids():
    assert 'WINGET_APPROVED_CATALOG = [' in APP
    assert '@app.get("/api/winget/catalog")' in APP
    for package_id in (
        "7zip.7zip", "VideoLAN.VLC", "Microsoft.PowerToys",
        "Microsoft.VisualStudioCode", "Git.Git", "PuTTY.PuTTY", "WinSCP.WinSCP",
    ):
        assert package_id in APP


def test_live_search_queues_a_read_only_endpoint_job_and_polls_its_result():
    assert '@app.post("/api/machines/{agent_id}/winget-search")' in APP
    assert 'WINGET_SEARCH_SCRIPT' in APP
    assert '& $wg search --query $query' in APP
    assert 'PNC_WINGET_SEARCH_JSON:' in APP
    assert "api(`/api/jobs/${state.wingetSearchJobId}`)" in DASHBOARD
    assert 'function parseWingetSearchOutput(' in DASHBOARD


def test_install_requires_an_explicit_package_id_confirmation():
    assert '@app.post("/api/machines/{agent_id}/winget-install")' in APP
    assert 'WINGET_INSTALL_SCRIPT' in APP
    assert '& $wg install --id $packageId --exact' in APP
    assert "body:JSON.stringify({package_id:pkg.id,source})" in DASHBOARD
    assert 'Install selected package' in DASHBOARD


def test_platform_version_is_1316():
    assert 'PLATFORM_VERSION = "1.31.6"' in APP

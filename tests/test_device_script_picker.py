from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = (ROOT / "server" / "dashboard.html").read_text(encoding="utf-8")
APP = (ROOT / "server" / "app.py").read_text(encoding="utf-8")


def test_device_automation_picker_replaces_large_inline_select():
    assert 'id="deviceScriptPicker"' in DASHBOARD
    assert '<h2>Choose an automation</h2>' in DASHBOARD
    assert 'id="dspSearch"' in DASHBOARD
    assert 'id="dspShell"' in DASHBOARD
    assert 'id="dspList"' in DASHBOARD
    assert 'onclick="executeDevicePickerAutomation()"' in DASHBOARD
    assert 'id="mpScript"' not in DASHBOARD


def test_device_picker_has_search_filter_internal_scroll_and_applications():
    assert 'function openDeviceScriptPicker()' in DASHBOARD
    assert 'function renderDeviceScriptPicker()' in DASHBOARD
    assert 'function useDeviceScriptPickerSelection()' in DASHBOARD
    assert 'max-height:430px;overflow-y:auto' in DASHBOARD
    assert "shellFilter==='all'||shell===shellFilter" in DASHBOARD
    assert '<option value="application">Application installers</option>' in DASHBOARD
    assert "shellFilter==='all'||shellFilter==='application'" in DASHBOARD
    assert 'Application installer' in DASHBOARD


def test_device_page_loads_applications_with_scripts():
    assert "api('/api/applications').catch(()=>({applications:[]}))" in DASHBOARD
    assert 'state.applications = applicationsResp.applications || [];' in DASHBOARD
    assert 'deviceApplicationId: null' in DASHBOARD


def test_device_picker_uses_typed_keys_so_script_and_application_ids_can_overlap():
    assert "`script:${s.id}`" in DASHBOARD
    assert "`application:${a.id}`" in DASHBOARD
    assert "state.deviceScriptPickerSelected = `${kind}:${+id}`;" in DASHBOARD
    assert "if(kind==='application')" in DASHBOARD


def test_device_one_time_run_supports_application_installation_and_preserves_scripts():
    assert 'const applicationId=+state.deviceApplicationId||0;' in DASHBOARD
    assert "api('/api/run-application',{method:'POST',body:JSON.stringify({application_id:applicationId,machine_ids:[state.currentMachine]})})" in DASHBOARD
    assert 'const sid = +state.deviceScriptId || 0;' in DASHBOARD
    assert "body: JSON.stringify({ script_id: sid, machine_ids: [state.currentMachine] })" in DASHBOARD
    assert 'Install selected application' in DASHBOARD
    assert 'Run selected script' in DASHBOARD


def test_incomplete_application_is_visible_but_cannot_be_selected_for_run():
    assert "ready:!!item.installer_file" in DASHBOARD
    assert 'Installer missing' in DASHBOARD
    assert 'use.disabled=!chosen.ready||targetCount===0' in DASHBOARD
    assert "Upload an installer file before selecting this application" in DASHBOARD


def test_application_picker_is_windows_only():
    assert "const canInstallApps=String(machine.os_version||'').toLowerCase().includes('windows');" in DASHBOARD
    assert "const applications=canInstallApps?(state.applications||[]).filter" in DASHBOARD


def test_fleet_multiselect_opens_unified_automation_picker_with_applications():
    assert 'onclick="openFleetAutomationPicker()">Run automation…</button>' in DASHBOARD
    assert 'id="fleetScriptSel"' not in DASHBOARD
    assert "state.deviceAutomationPickerMode='fleet'" in DASHBOARD
    assert "state.deviceAutomationTargetIds=[...fleetSel]" in DASHBOARD
    assert "application_id:chosen.id,machine_ids:targetIds" in DASHBOARD


def test_device_picker_confirms_and_queues_without_collapsing_back_to_device_details():
    assert 'id="dspConfirm"' in DASHBOARD
    assert 'id="dspVars"' in DASHBOARD
    assert 'onclick="executeDevicePickerAutomation()"' in DASHBOARD
    assert "collectVarValues(chosen.item.variables||[],'dspv')" in DASHBOARD
    assert "script_id:chosen.id,machine_ids:targetIds,variables" in DASHBOARD
    assert "application_id:chosen.id,machine_ids:targetIds" in DASHBOARD
    assert 'Use selected automation' not in DASHBOARD
    assert 'ondblclick="selectDeviceScriptPicker' not in DASHBOARD


def test_remove_device_dialog_has_explicit_online_and_permanent_offline_paths():
    assert 'id="removeMachineModal"' in DASHBOARD
    assert 'Uninstall agent and remove' in DASHBOARD
    assert 'Permanently delete offline record' in DASHBOARD
    assert 'onclick="orderMachineUninstall()"' in DASHBOARD
    assert 'onclick="deleteMachineRecordNow()"' in DASHBOARD
    assert "method:'DELETE'" in DASHBOARD
    assert "Leave the box empty" not in DASHBOARD


def test_platform_version_is_1316():
    assert 'PLATFORM_VERSION = "1.31.6"' in APP

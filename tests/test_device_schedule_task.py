from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = (ROOT / "server" / "dashboard.html").read_text(encoding="utf-8")
APP = (ROOT / "server" / "app.py").read_text(encoding="utf-8")


def test_device_overview_can_open_a_device_scoped_schedule_editor():
    assert 'onclick="openDeviceScheduleTask()"' in DASHBOARD
    assert 'id="deviceScheduleModal"' in DASHBOARD
    assert '<h2>Schedule task for this device</h2>' in DASHBOARD
    assert 'function openDeviceScheduleTask()' in DASHBOARD
    assert "state.deviceScheduleTargetId=machine.id" in DASHBOARD


def test_device_schedule_supports_power_updates_and_saved_scripts():
    assert 'id="dsAction"' in DASHBOARD
    assert '<option value="reboot">Reboot the device</option>' in DASHBOARD
    assert '<option value="shutdown">Shut down the device</option>' in DASHBOARD
    assert '<option value="install_updates">Install Windows updates</option>' in DASHBOARD
    assert '<option value="script">Run a saved script</option>' in DASHBOARD
    assert 'id="dsScript"' in DASHBOARD


def test_device_schedule_is_saved_for_only_the_open_device_and_refreshes_automation():
    assert "target_type:'machines',target_ids:[state.deviceScheduleTargetId]" in DASHBOARD
    assert "api('/api/schedules',{method:'POST',body:JSON.stringify(body)})" in DASHBOARD
    assert "toast('Scheduled task created')" in DASHBOARD
    assert "await loadAutomation()" in DASHBOARD
    assert "show('automation')" not in DASHBOARD[DASHBOARD.index('async function saveDeviceScheduleTask()'):DASHBOARD.index('async function saveDeviceScheduleTask()') + 1800]


def test_device_schedule_requires_an_explicit_name_and_script_when_needed():
    assert "if(!name)return toast('Give the scheduled task a name')" in DASHBOARD
    assert "if(action_type==='script'&&!script_id)return toast('Pick a script')" in DASHBOARD


def test_platform_version_is_1316():
    assert 'PLATFORM_VERSION = "1.31.6"' in APP

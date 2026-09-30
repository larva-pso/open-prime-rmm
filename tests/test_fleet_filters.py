import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = (ROOT / "server" / "dashboard.html").read_text(encoding="utf-8")


def test_fleet_toolbar_offers_device_os_protection_and_memory_filters():
    assert 'id="fleetClassSel"' in DASHBOARD
    assert 'id="fleetOsSel"' in DASHBOARD
    assert 'id="fleetProtectionSel"' in DASHBOARD
    assert 'id="fleetMemorySel"' in DASHBOARD
    assert '<option value="windows_11">Windows 11</option>' in DASHBOARD
    assert '<option value="windows_server">Windows Server</option>' in DASHBOARD


def test_advanced_fleet_filters_execute_together():
    start = DASHBOARD.index("function fleetOsFamily")
    end = DASHBOARD.index("function fleetHealthRank", start)
    filter_script = DASHBOARD[start:end]
    harness = f"""
const assert = require('node:assert/strict');
const values = {{
  '#fleetHealthSel':'all', '#fleetStatusSel':'all', '#fleetUpdatesSel':'all',
  '#fleetClassSel':'server', '#fleetOsSel':'windows_server',
  '#fleetProtectionSel':'missing', '#fleetMemorySel':'high'
}};
const qs = selector => ({{value: values[selector]}});
const machineHealth = () => ({{level:'healthy'}});
{filter_script}
const matching = {{
  device_class_effective:'server', os_version:'Microsoft Windows Server 2022',
  bdgz_protected:0, memory_alert:true, last_seen:Date.now()/1000
}};
assert.equal(matchesAdvancedFleetFilters(matching), true);
assert.equal(matchesAdvancedFleetFilters({{...matching, device_class_effective:'workstation'}}), false);
values['#fleetClassSel'] = 'all';
values['#fleetOsSel'] = 'windows_11';
assert.equal(matchesAdvancedFleetFilters({{...matching, os_version:'Microsoft Windows 11 Pro'}}), true);
assert.equal(matchesAdvancedFleetFilters({{...matching, os_version:'Microsoft Windows 10 Pro'}}), false);
values['#fleetOsSel'] = 'all';
values['#fleetMemorySel'] = 'normal';
assert.equal(matchesAdvancedFleetFilters({{...matching, memory_alert:false, memory_used_pct:72}}), true);
assert.equal(matchesAdvancedFleetFilters({{...matching, memory_alert:true}}), false);
values['#fleetMemorySel'] = 'unknown';
assert.equal(matchesAdvancedFleetFilters({{...matching, memory_alert:false, memory_used_pct:72, last_seen:(Date.now()/1000)-600}}), true);
console.log(JSON.stringify({{ok:true}}));
"""
    result = subprocess.run(
        ["node", "-e", harness], check=True, capture_output=True, text=True
    )
    assert json.loads(result.stdout) == {"ok": True}


def test_save_as_group_preserves_every_new_fleet_filter():
    start = DASHBOARD.index("function saveFleetAsGroup")
    end = DASHBOARD.index("function editGroup", start)
    save_script = DASHBOARD[start:end]
    harness = f"""
const assert = require('node:assert/strict');
const values = {{
  '#fleetHealthSel':'all', '#fleetStatusSel':'all', '#fleetUpdatesSel':'all',
  '#fleetSearch':'', '#fleetClassSel':'server', '#fleetOsSel':'windows_server',
  '#fleetProtectionSel':'missing', '#fleetMemorySel':'high'
}};
const qs = selector => ({{value: values[selector], insertAdjacentHTML:()=>{{}}}});
const show = () => {{}};
let captured = null;
const groupForm = group => {{captured = group.filters;}};
const setTimeout = fn => fn();
{save_script}
saveFleetAsGroup();
assert.deepEqual(captured, {{
  device_class:'server', os_family:'windows_server',
  protection_status:'missing', memory_status:'high'
}});
console.log(JSON.stringify(captured));
"""
    result = subprocess.run(
        ["node", "-e", harness], check=True, capture_output=True, text=True
    )
    assert json.loads(result.stdout) == {
        "device_class": "server",
        "os_family": "windows_server",
        "protection_status": "missing",
        "memory_status": "high",
    }

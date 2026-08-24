import os
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse, Response
from packaging.version import parse as parse_version
from sqlalchemy.orm import Session

from database import get_db, FIRMWARE_DIR
from utils import is_newer_version, _tag_gap, _sync_hardware_tag
from models import Device, OneShotRelease, VersionedRelease, ReleaseStatus, UpdateMode

router = APIRouter()


@router.post("/check-update")
def check_update(
    x_device_mac:       Optional[str] = Header(default=None),
    x_device_secret:    Optional[str] = Header(default=None),
    x_firmware_name:    Optional[str] = Header(default=None),
    x_firmware_version: Optional[str] = Header(default=None),
    x_device_battery:   Optional[str] = Header(default=None),
    x_compute_module:   Optional[str] = Header(default=None),
    x_heartbeat_interval: Optional[str] = Header(default=None),
    db:                 Session        = Depends(get_db),
):
    if not all([x_device_mac, x_device_secret, x_firmware_version]):
        return JSONResponse(status_code=400, content={"error": "Missing required headers."})
 

    # Step 1: Device lookup / auto-register
    device = db.query(Device).filter(Device.mac_address == x_device_mac).first()
    if not device:
        db.add(Device(
            mac_address=x_device_mac,
            secret="pending_claim",
            compute_module=x_compute_module,
            current_firmware_version=x_firmware_version,
            claimed=False,
            last_checkin=datetime.utcnow(),
        ))
        db.commit()
        return Response(status_code=204)

    if not device.claimed:
        return Response(status_code=204)

    # Step 2: Authenticate
    if not secrets.compare_digest(device.secret, x_device_secret):
        raise HTTPException(status_code=403, detail="Forbidden: Secret mismatch.")

    # Step 3: Update telemetry
    device.last_checkin = datetime.utcnow()
    device.current_firmware_version = x_firmware_version
    if x_compute_module:
        device.compute_module = x_compute_module
    if x_device_battery is not None:
        try:
            device.battery = int(x_device_battery)
        except ValueError:
            pass
    if x_heartbeat_interval is not None:
        try:
            device.heartbeat_interval = int(x_heartbeat_interval)
        except ValueError:
            pass
    _sync_hardware_tag(device, db)
    db.commit()

    # Step 4/5: Resolution (Priority 0, 1)
    name = ""
    version = None
    update_mode = UpdateMode.LATEST
    target_tags: set = set()
    resolved_release = None
    oneshot_release = None

    # Priority 0: device-level one-shot pin
    if device.target_oneshot_release_id:
        oneshot_release = db.query(OneShotRelease).filter(
            OneShotRelease.id == device.target_oneshot_release_id
        ).first()
        if oneshot_release:
            marker = f"oneshot_dispatched-{oneshot_release.id}"
            if device.last_ota_status == marker:
                return Response(status_code=204)
            oneshot_file = os.path.join(FIRMWARE_DIR, oneshot_release.filename)
            if not os.path.exists(oneshot_file):
                print(f"WARNING: OneShotRelease id={oneshot_release.id} file missing: {oneshot_file}")
                return Response(status_code=204)
            device.last_ota_status = marker
            db.commit()
            return FileResponse(
                oneshot_file,
                media_type="application/octet-stream",
                filename=oneshot_release.filename,
                headers={"X-Firmware-Version": "oneshot"},
            )

    # Priority 1: resolve effective target
    if device.target_firmware_name:
        name = device.target_firmware_name
        version = device.target_firmware_version or None
        update_mode = device.update_mode or UpdateMode.LATEST
        target_tags = {t.name for t in (device.tags or [])}
    elif device.fleet:
        fleet = device.fleet
        # Fleet-level one-shot pin
        if fleet.target_oneshot_release_id:
            fleet_oneshot = db.query(OneShotRelease).filter(
                OneShotRelease.id == fleet.target_oneshot_release_id
            ).first()
            if fleet_oneshot:
                if fleet_oneshot.compute_module != device.compute_module:
                    pass  # skip if compute_module doesn't match
                else:
                    marker = f"oneshot_dispatched-{fleet_oneshot.id}"
                    if device.last_ota_status == marker:
                        return Response(status_code=204)
                    oneshot_file = os.path.join(FIRMWARE_DIR, fleet_oneshot.filename)
                    if not os.path.exists(oneshot_file):
                        return Response(status_code=204)
                    device.last_ota_status = marker
                    db.commit()
                    return FileResponse(
                        oneshot_file,
                        media_type="application/octet-stream",
                        filename=fleet_oneshot.filename,
                        headers={"X-Firmware-Version": "oneshot"},
                    )
        # Fleet-level firmware targeting
        if fleet.target_firmware_name:
            name = fleet.target_firmware_name
            version = fleet.target_firmware_version or None
            update_mode = fleet.update_mode or UpdateMode.LATEST
            target_tags = {t.name for t in (device.tags or [])}
    else:
        # Fallback: device-reported firmware name in LATEST mode
        if x_firmware_name:
            name = x_firmware_name
            version = None
            update_mode = UpdateMode.LATEST
            target_tags = set()

    if not name:
        return Response(status_code=204)

    # Query candidates
    query = db.query(VersionedRelease).filter(
        VersionedRelease.firmware_name == name,
        VersionedRelease.compute_module == device.compute_module,
        VersionedRelease.status == ReleaseStatus.Approved,
    )
    if update_mode == UpdateMode.FIXED and version:
        query = query.filter(VersionedRelease.firmware_version == version)

    candidates = [r for r in query.all() if r.firmware_version]
    if not candidates:
        return Response(status_code=204)

    # Tag subset matching
    filtered = []
    for r in candidates:
        release_tags = {t.name for t in (r.tags or [])}
        gap = _tag_gap(release_tags, target_tags)
        if gap["subset_match"]:
            filtered.append(r)

    if not filtered:
        return Response(status_code=204)

    if update_mode == UpdateMode.FIXED and version:
        resolved_release = filtered[0]
    else:
        resolved_release = max(filtered, key=lambda r: parse_version(r.firmware_version))

    # Step 6: Deployment decision
    if not is_newer_version(resolved_release.firmware_version, x_firmware_version):
        return Response(status_code=204)

    if not os.path.exists(resolved_release.file_path):
        print(f"WARNING: VersionedRelease id={resolved_release.id} file missing: {resolved_release.file_path}")
        return Response(status_code=204)

    device.last_ota_status = f"update_dispatched-{name}-{resolved_release.firmware_version}"
    db.commit()

    return FileResponse(
        resolved_release.file_path,
        media_type="application/octet-stream",
        filename=os.path.basename(resolved_release.file_path),
        headers={"X-Firmware-Version": resolved_release.firmware_version},
    )

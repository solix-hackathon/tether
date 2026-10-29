"""One playbook per action type. Each one acts on the target system, then re-reads the target
system's own state to confirm the result instead of trusting the call's return value."""

from recall.mocks.systems import OperationFailed


def _result(playbook, resource, confirmed, at, error=None, **extra):
    return {"playbook": playbook, "resource": resource, "confirmed": bool(confirmed), "at": at, "error": error, **extra}


def revoke_links(world, action):
    out = []
    for recipient, lid in action["resources"].get("links", {}).items():
        err = None
        try:
            world.links.revoke(lid)
        except OperationFailed as e:
            err = str(e)
        st = world.links.status(lid)
        at = st["revoked_at"] if st["revoked_at"] is not None else (st["expires_at"] if not st["active"] else None)
        out.append(_result("revoke_links", lid, not st["active"], at, err, recipient=recipient))
    return out


def revoke_share(world, action):
    sid = action["resources"]["share_id"]
    err = None
    try:
        world.files.revoke_share(sid)
    except OperationFailed as e:
        err = str(e)
    st = world.files.share_status(sid)
    return [_result("revoke_share", sid, not st["active"], st["revoked_at"], err)]


def rotate_key(world, action):
    out = []
    for kid in action["resources"].get("key_ids", []):
        err = None
        try:
            world.vault.rotate(kid)
        except OperationFailed as e:
            err = str(e)
        st = world.vault.status(kid)
        out.append(_result("rotate_key", kid, st["status"] == "revoked", st["rotated_at"], err,
                           successor=st["successor"]))
    return out


def purge_mail(world, action):
    mid = action["resources"]["message_id"]
    err = None
    try:
        world.mail.purge(mid)
    except OperationFailed as e:
        err = str(e)
    st = world.mail.status(mid)
    return [_result("purge_mail", mid, st["internal_copies"] == 0 and st["purged_at"] is not None, st["purged_at"], err)]


def cancel_order(world, action):
    oid = action["resources"]["order_id"]
    err = None
    try:
        world.orders.cancel(oid)
    except OperationFailed as e:
        err = str(e)
    st = world.orders.status(oid)
    confirmed = st["status"] == "cancelled"
    return [_result("cancel_order", oid, confirmed, st["updated_at"] if confirmed else None, err)]


PLAYBOOKS = {
    "revoke_links": revoke_links,
    "revoke_share": revoke_share,
    "rotate_key": rotate_key,
    "purge_mail": purge_mail,
    "cancel_order": cancel_order,
}


def run(world, action):
    reversals = []
    for name in action.get("playbooks", []):
        reversals.extend(PLAYBOOKS[name](world, action))
    return reversals

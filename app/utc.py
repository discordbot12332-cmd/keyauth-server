from datetime import datetime, timezone, timedelta


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_add(**kwargs):
    return (datetime.now(timezone.utc) + timedelta(**kwargs)).replace(tzinfo=None)

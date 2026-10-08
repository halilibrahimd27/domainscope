"""The Python half of a time-travel run (tests/time-travel.mjs puts this folder first in PYTHONPATH).

Python imports a module of this name by itself at start-up. When DS_TIME_SKEW_MS is set, the
process's clock is moved by that many milliseconds and runs on from there: time.time(),
time.time_ns(), datetime.now() / utcnow() / today(), date.today() and the clock-less
time.gmtime() / localtime(). time.monotonic() and time.sleep() are not touched. Without the
variable it does nothing. Standard library only; Python 3.8 and later.
"""
import datetime as _datetime
import os as _os
import time as _time


def _skew_seconds():
    raw = _os.environ.get('DS_TIME_SKEW_MS', '').strip()
    if not raw:
        return None
    try:
        return float(raw) / 1000.0
    except ValueError:
        return None


_skew = _skew_seconds()

if _skew is not None:
    _real_time = _time.time
    _real_time_ns = _time.time_ns
    _real_gmtime = _time.gmtime
    _real_localtime = _time.localtime
    _RealDatetime = _datetime.datetime
    _RealDate = _datetime.date

    def _shifted_time():
        return _real_time() + _skew

    _time.time = _shifted_time
    _time.time_ns = lambda: _real_time_ns() + int(_skew * 1e9)
    _time.gmtime = lambda secs=None: _real_gmtime(_shifted_time() if secs is None else secs)
    _time.localtime = lambda secs=None: _real_localtime(_shifted_time() if secs is None else secs)

    # `isinstance(x, datetime.datetime)` stays true for every real datetime, whoever made it
    class _DatetimeMeta(type):
        def __instancecheck__(cls, obj):
            return isinstance(obj, _RealDatetime)

        def __subclasscheck__(cls, sub):
            return issubclass(sub, _RealDatetime)

    class _DateMeta(type):
        def __instancecheck__(cls, obj):
            return isinstance(obj, _RealDate)

        def __subclasscheck__(cls, sub):
            return issubclass(sub, _RealDate)

    class _ShiftedDatetime(_RealDatetime, metaclass=_DatetimeMeta):
        @classmethod
        def now(cls, tz=None):
            return _RealDatetime.fromtimestamp(_shifted_time(), tz)

        @classmethod
        def utcnow(cls):
            return _RealDatetime.fromtimestamp(_shifted_time(), _datetime.timezone.utc).replace(tzinfo=None)

        @classmethod
        def today(cls):
            return cls.now()

    class _ShiftedDate(_RealDate, metaclass=_DateMeta):
        @classmethod
        def today(cls):
            return _RealDate.fromtimestamp(_shifted_time())

    _datetime.datetime = _ShiftedDatetime
    _datetime.date = _ShiftedDate

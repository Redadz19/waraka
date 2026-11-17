from app.security import hash_serial, hash_value, new_serial


def test_hash_is_stable():
    assert hash_value("WARAKA") == hash_value("WARAKA")
    assert hash_value("WARAKA") != hash_value("waraka")


def test_serial_hash_is_case_and_whitespace_insensitive():
    serial = "WRK-ABCD-1234-EF56-7890"
    assert hash_serial(serial) == hash_serial(f"  {serial.lower()}  ")


def test_serial_format_and_uniqueness():
    first, second = new_serial(), new_serial()
    parts = first.split("-")
    assert parts[0] == "WRK"
    assert len(parts) == 9
    assert all(len(part) == 4 for part in parts[1:])
    assert first != second

from app.security import hash_value, new_serial

def test_hash_is_stable():
    assert hash_value("WARAKA") == hash_value("WARAKA")
    assert hash_value("WARAKA") != hash_value("waraka")

def test_serial_format_and_uniqueness():
    first, second = new_serial(), new_serial()
    assert len(first.split("-")) == 8
    assert first != second

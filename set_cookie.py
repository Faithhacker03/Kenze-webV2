# --- START OF REPLACEMENT FOR set_cookie.py ---
# This module provides a "Numbered Set" of cookies by either using a
# fixed number specified by the user or by cycling through the full list.

import threading

# --- Global State for this Module ---
_FIXED_NUMBER = None
_CYCLING_INDEX = -1
_lock = threading.Lock()

# --- Load Cookies from Configuration ---
try:
    from cookie_config import COOKIE_POOL
    if not isinstance(COOKIE_POOL, list) or not COOKIE_POOL:
        COOKIE_POOL = [{"datadome": "error_pool_is_malformed"}]
except ImportError:
    COOKIE_POOL = [{"datadome": "error_cookie_config_not_found"}]


def set_fixed_number(number):
    """
    Sets the fixed cookie number to use for the entire session.
    """
    global _FIXED_NUMBER
    with _lock:
        if number > 0:
            _FIXED_NUMBER = number - 1 # User input is 1-based, list index is 0-based
        else:
            _FIXED_NUMBER = None # If user enters 0 or nothing, cycle instead

def get_cookies():
    """
    Provides a cookie from the COOKIE_POOL.
    """
    global _CYCLING_INDEX
    selected_index = -1

    with _lock:
        if _FIXED_NUMBER is not None:
            selected_index = _FIXED_NUMBER
        else:
            _CYCLING_INDEX = (_CYCLING_INDEX + 1) % len(COOKIE_POOL)
            selected_index = _CYCLING_INDEX

    # Error Handling for index out of bounds
    if selected_index >= len(COOKIE_POOL):
        selected_index = len(COOKIE_POOL) - 1
    
    selected_cookie_object = COOKIE_POOL[selected_index]
    datadome_value = selected_cookie_object.get("datadome", "VALUE_NOT_FOUND")

    return {
        "datadome": datadome_value,
        # Add other necessary cookies with placeholder values
        "sso_key": "sso_from_set_cookie",
        "token_session": "token_from_set_cookie",
    }

# --- END OF REPLACEMENT FOR set_cookie.py ---
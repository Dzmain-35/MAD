"""
Typography constants for MAD (Malware Analysis Dashboard)

This module defines standardized fonts, sizes, and weights to ensure
consistent typography across the application.
"""

import customtkinter as ctk


# Font Size Scale
# Using a standardized scale for consistent visual hierarchy
FONT_SIZES = {
    "xs": 11,      # Helper text, footnotes, status indicators
    "sm": 12,      # Secondary text, smaller labels
    "base": 14,    # Primary body text, input fields
    "md": 16,      # Section labels, form labels
    "lg": 18,      # Subsection headers, subtab titles
    "xl": 20,      # Section headers
    "2xl": 24,     # Tab titles, important headers
    "3xl": 28,     # Main page headers
    "logo": 72,    # Logo text size
}


# Font Weights
FONT_WEIGHTS = {
    "regular": "normal",
    "bold": "bold",
}


# Font Families
FONT_FAMILIES = {
    "default": None,           # CustomTkinter default
    "ui": "Segoe UI",         # For text inputs and notes
    "mono": "Courier",        # For code, logs, and technical data
}


# Descriptor for lazy font initialization
class _FontDescriptor:
    """Descriptor that creates fonts on first access (lazy initialization)"""

    def __init__(self, key, size, weight):
        self.key = key
        self.size = size
        self.weight = weight

    def __get__(self, obj, objtype=None):
        """Create and cache font on first access"""
        if self.key not in objtype._cache:
            objtype._cache[self.key] = ctk.CTkFont(size=self.size, weight=self.weight)
        return objtype._cache[self.key]


# Standardized Font Objects
# These are reusable font instances for common UI elements
class Fonts:
    """Centralized font definitions for the MAD application

    Uses lazy initialization to create fonts only after tkinter root window exists.
    Fonts are created on first access and cached for reuse.
    """

    # Cache for font objects
    _cache = {}

    # Logo and branding
    logo_main = _FontDescriptor("logo_main", FONT_SIZES["logo"], FONT_WEIGHTS["bold"])
    logo_emoji = _FontDescriptor("logo_emoji", 80, FONT_WEIGHTS["regular"])
    logo_subtitle = _FontDescriptor("logo_subtitle", FONT_SIZES["xl"], FONT_WEIGHTS["bold"])

    # Headers and titles
    header_main = _FontDescriptor("header_main", FONT_SIZES["3xl"], FONT_WEIGHTS["bold"])
    header_section = _FontDescriptor("header_section", FONT_SIZES["2xl"], FONT_WEIGHTS["bold"])
    header_subsection = _FontDescriptor("header_subsection", FONT_SIZES["xl"], FONT_WEIGHTS["bold"])

    # Titles
    title_large = _FontDescriptor("title_large", FONT_SIZES["lg"], FONT_WEIGHTS["bold"])
    title_medium = _FontDescriptor("title_medium", FONT_SIZES["md"], FONT_WEIGHTS["bold"])

    # Body text
    body_large = _FontDescriptor("body_large", FONT_SIZES["base"], FONT_WEIGHTS["regular"])
    body_large_bold = _FontDescriptor("body_large_bold", FONT_SIZES["base"], FONT_WEIGHTS["bold"])
    body = _FontDescriptor("body", FONT_SIZES["sm"], FONT_WEIGHTS["regular"])
    body_bold = _FontDescriptor("body_bold", FONT_SIZES["sm"], FONT_WEIGHTS["bold"])

    # Labels and inputs
    label_large = _FontDescriptor("label_large", FONT_SIZES["base"], FONT_WEIGHTS["bold"])
    label = _FontDescriptor("label", FONT_SIZES["sm"], FONT_WEIGHTS["bold"])
    input_field = _FontDescriptor("input_field", FONT_SIZES["base"], FONT_WEIGHTS["regular"])

    # Buttons
    button_large = _FontDescriptor("button_large", FONT_SIZES["base"], FONT_WEIGHTS["bold"])
    button = _FontDescriptor("button", FONT_SIZES["sm"], FONT_WEIGHTS["bold"])

    # Navigation
    nav_button = _FontDescriptor("nav_button", FONT_SIZES["base"], FONT_WEIGHTS["bold"])

    # Helper and status text
    helper = _FontDescriptor("helper", FONT_SIZES["xs"], FONT_WEIGHTS["regular"])
    status = _FontDescriptor("status", FONT_SIZES["xs"], FONT_WEIGHTS["regular"])

    # Special purpose fonts with specific families
    @staticmethod
    def text_input(size=None):
        """Font for text input areas (uses Segoe UI)"""
        return (FONT_FAMILIES["ui"], size or FONT_SIZES["xs"])

    @staticmethod
    def monospace(size=None):
        """Font for code, logs, and technical data (uses Courier)"""
        return (FONT_FAMILIES["mono"], size or 13)


# Legacy mapping for gradual migration
# Maps old inline declarations to new font objects
# Uses lazy initialization to avoid creating fonts at import time
_FONT_MAP_CACHE = None


def _get_font_map():
    """Get the font mapping, creating it on first access"""
    global _FONT_MAP_CACHE
    if _FONT_MAP_CACHE is None:
        _FONT_MAP_CACHE = {
            (12, "normal"): Fonts.body,
            (12, "bold"): Fonts.body_bold,
            (14, "normal"): Fonts.body_large,
            (14, "bold"): Fonts.label_large,
            (16, "bold"): Fonts.title_medium,
            (18, "bold"): Fonts.title_large,
            (20, "bold"): Fonts.header_subsection,
            (24, "bold"): Fonts.header_section,
            (28, "bold"): Fonts.header_main,
        }
    return _FONT_MAP_CACHE


def get_font(size, weight="normal"):
    """
    Get a standardized font for given size and weight.

    Args:
        size: Font size (use FONT_SIZES constants when possible)
        weight: Font weight ("normal" or "bold")

    Returns:
        CTkFont object
    """
    key = (size, weight)
    font_map = _get_font_map()
    if key in font_map:
        return font_map[key]
    return ctk.CTkFont(size=size, weight=weight)

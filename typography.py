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


# Standardized Font Objects
# These are reusable font instances for common UI elements
class Fonts:
    """Centralized font definitions for the MAD application"""

    # Logo and branding
    logo_main = ctk.CTkFont(size=FONT_SIZES["logo"], weight=FONT_WEIGHTS["bold"])
    logo_emoji = ctk.CTkFont(size=80)
    logo_subtitle = ctk.CTkFont(size=FONT_SIZES["xl"], weight=FONT_WEIGHTS["bold"])

    # Headers and titles
    header_main = ctk.CTkFont(size=FONT_SIZES["3xl"], weight=FONT_WEIGHTS["bold"])
    header_section = ctk.CTkFont(size=FONT_SIZES["2xl"], weight=FONT_WEIGHTS["bold"])
    header_subsection = ctk.CTkFont(size=FONT_SIZES["xl"], weight=FONT_WEIGHTS["bold"])

    # Titles
    title_large = ctk.CTkFont(size=FONT_SIZES["lg"], weight=FONT_WEIGHTS["bold"])
    title_medium = ctk.CTkFont(size=FONT_SIZES["md"], weight=FONT_WEIGHTS["bold"])

    # Body text
    body_large = ctk.CTkFont(size=FONT_SIZES["base"], weight=FONT_WEIGHTS["regular"])
    body_large_bold = ctk.CTkFont(size=FONT_SIZES["base"], weight=FONT_WEIGHTS["bold"])
    body = ctk.CTkFont(size=FONT_SIZES["sm"], weight=FONT_WEIGHTS["regular"])
    body_bold = ctk.CTkFont(size=FONT_SIZES["sm"], weight=FONT_WEIGHTS["bold"])

    # Labels and inputs
    label_large = ctk.CTkFont(size=FONT_SIZES["base"], weight=FONT_WEIGHTS["bold"])
    label = ctk.CTkFont(size=FONT_SIZES["sm"], weight=FONT_WEIGHTS["bold"])
    input_field = ctk.CTkFont(size=FONT_SIZES["base"], weight=FONT_WEIGHTS["regular"])

    # Buttons
    button_large = ctk.CTkFont(size=FONT_SIZES["base"], weight=FONT_WEIGHTS["bold"])
    button = ctk.CTkFont(size=FONT_SIZES["sm"], weight=FONT_WEIGHTS["bold"])

    # Navigation
    nav_button = ctk.CTkFont(size=FONT_SIZES["base"], weight=FONT_WEIGHTS["bold"])

    # Helper and status text
    helper = ctk.CTkFont(size=FONT_SIZES["xs"], weight=FONT_WEIGHTS["regular"])
    status = ctk.CTkFont(size=FONT_SIZES["xs"], weight=FONT_WEIGHTS["regular"])

    # Special purpose fonts with specific families
    @staticmethod
    def text_input(size=None):
        """Font for text input areas (uses Segoe UI)"""
        return (FONT_FAMILIES["ui"], size or FONT_SIZES["xs"])

    @staticmethod
    def monospace(size=None):
        """Font for code, logs, and technical data (uses Courier)"""
        return (FONT_FAMILIES["mono"], size or 10)


# Legacy mapping for gradual migration
# Maps old inline declarations to new font objects
FONT_MAP = {
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
    if key in FONT_MAP:
        return FONT_MAP[key]
    return ctk.CTkFont(size=size, weight=weight)

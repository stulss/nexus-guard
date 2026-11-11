# -*- coding: utf-8 -*-
"""NEXUS-GUARD Enterprise SOC Dark Theme & Design Tokens.

Design Reference:
- CrowdStrike Falcon / SentinelOne Singularity / Datadog Cloud Security / GlassWire Pro
- Deep Obsidian Base (#070b14 / #0b1220) with Sub-surface Card (#0f172a, #111d33)
- Frost Borders (#1e293b, #283b5b)
- Neon Highlights: Cyber Cyan (#38bdf8), Emerald Shield (#10b981), Alert Crimson (#f43f5e),
  Amber Warning (#fbbf24), Purple AI (#a78bfa)
- Strict WCAG AA compliance (contrast ratio >= 4.5:1) for 24/7 mission-critical SOC operations
"""

# =========================================================================
# 1. Backgrounds & Surfaces (Glassmorphic Dark Mode - CrowdStrike / SentinelOne)
# =========================================================================
BG_DARK = "#070b14"          # Deep Obsidian Base canvas
BG_OBSIDIAN = "#0b1220"      # Elevated Obsidian Console surface
BG_SIDEBAR = "#070b14"       # Left Rail Darkest Obsidian
SURFACE_CARD = "#0f172a"     # Primary Card Surface (Sub-surface Card)
SURFACE_CARD_ALT = "#111d33" # Secondary Sub-surface Card / Tactic Card
SURFACE_INNER = "#070b14"    # Inner Graph & Scroll Area Surface
SURFACE_HOVER = "#162032"    # Card & Button Hover Surface
SURFACE_INPUT = "#0c1322"    # Text Entry & Dropdown Background

# =========================================================================
# 2. Borders & Subtle Dividers (Frost & Cyber Accents)
# =========================================================================
BORDER_SUBTLE = "#1e293b"    # 1px Sleek Frost Outline (Slate-800)
BORDER_FROST = "#283b5b"     # High-tech Frost Border (Slate-700 / Cyber Glow)
BORDER_ACTIVE = "#334155"    # Card Focus / Active Outline
BORDER_CYAN = "#0ea5e9"      # Ingress / Accent Outline
BORDER_EMERALD = "#059669"   # Protected Outline
BORDER_CRIMSON = "#dc2626"   # Threat Alert Outline

# =========================================================================
# 3. Status Accents & Threat Spectrum (Cyber Neon Highlights)
# =========================================================================
COLOR_SECURE = "#10b981"     # Emerald Shield - Normal / Secured / Allow / Protected
COLOR_SECURE_BG = "#052e25"  # Soft Emerald Pill Background
COLOR_CYAN = "#38bdf8"       # Cyber Cyan - Telemetry Flow / Ingress / Sensor
COLOR_CYAN_BG = "#0c2840"    # Soft Cyan Pill Background
COLOR_WARN = "#fbbf24"       # Amber Warning - Elevated / Attention / Suspicious
COLOR_WARN_BG = "#382305"    # Soft Amber Pill Background
COLOR_ALERT = "#f43f5e"      # Alert Crimson - 403 Drop / Block / Critical Threat
COLOR_ALERT_BG = "#380d15"   # Soft Crimson Pill Background
COLOR_PURPLE = "#a78bfa"     # Purple AI - AI-XDR LPU Cascade Engine
COLOR_PURPLE_BG = "#2a1245"  # Soft Purple Pill Background

# =========================================================================
# 4. Typography Scale & Inks (WCAG AA Compliance: min 4.5:1 for body)
# =========================================================================
TEXT_TITLE = "#f8fafc"       # Slate-50 (>15:1 contrast on dark surfaces)
TEXT_BODY = "#cbd5e1"        # Slate-300 (>10:1 contrast)
TEXT_MUTED = "#94a3b8"       # Slate-400 (>6.5:1 on dark surfaces - Safe WCAG AA)
TEXT_DIM = "#64748b"         # Non-text only: subtle grid lines, ticks, markers (3:1 graphical)

FONT_FAMILY_UI = "Segoe UI"
FONT_FAMILY_MONO = "Consolas"

# =========================================================================
# 5. Contrast Validation Pairs (for automated testing in test_gui_contrast.py)
# =========================================================================
CONTRAST_PAIRS = [
    # Surface Card (Primary Container Surfaces #0f172a)
    (TEXT_TITLE, SURFACE_CARD, "Card Title Text"),
    (TEXT_BODY, SURFACE_CARD, "Card Body Text"),
    (TEXT_MUTED, SURFACE_CARD, "Muted Meta Text on Card"),
    (COLOR_SECURE, SURFACE_CARD, "Secure Status on Card"),
    (COLOR_CYAN, SURFACE_CARD, "Cyan Status on Card"),
    (COLOR_WARN, SURFACE_CARD, "Warn Status on Card"),
    (COLOR_ALERT, SURFACE_CARD, "Alert Status on Card"),
    (COLOR_PURPLE, SURFACE_CARD, "AI Engine Badge on Card"),
    # Surface Inner (Radar, Canvas, Graph Surfaces #070b14)
    (TEXT_TITLE, SURFACE_INNER, "Inner Canvas Title Text"),
    (TEXT_BODY, SURFACE_INNER, "Inner Canvas Body Text"),
    (TEXT_MUTED, SURFACE_INNER, "Inner Canvas Muted Text"),
    (COLOR_SECURE, SURFACE_INNER, "Radar Core Node [CORE] (02.PORTAL)"),
    (COLOR_WARN, SURFACE_INNER, "Radar Warning Node [ACTIVE] (01.pfSense)"),
    (COLOR_CYAN, SURFACE_INNER, "Radar SIEM Node [ACTIVE] (03.SIEM)"),
    (COLOR_ALERT, SURFACE_INNER, "Radar Threat Node [ATTACK] (00.KALI)"),
    (TEXT_MUTED, SURFACE_INNER, "Radar Standby Node [STANDBY] (Gray)"),
    (COLOR_CYAN, SURFACE_INNER, "Traffic Realtime IO Active Label"),
    (COLOR_ALERT, SURFACE_INNER, "Traffic Threat Spike [BLOCK 403]"),
    (TEXT_MUTED, SURFACE_INNER, "Traffic Grid Speed [KB/s] Label"),
    # Sub-surface Card Alt (MITRE Matrix & Secondary Cards #111d33)
    (TEXT_TITLE, SURFACE_CARD_ALT, "Alt Card Title Text"),
    (TEXT_BODY, SURFACE_CARD_ALT, "Alt Card Body Text"),
    (TEXT_MUTED, SURFACE_CARD_ALT, "Alt Card Muted Text"),
    (COLOR_SECURE, SURFACE_CARD_ALT, "MITRE Matrix Clear Tactic"),
    (COLOR_CYAN, SURFACE_CARD_ALT, "MITRE Matrix Monitored Tactic"),
    (COLOR_WARN, SURFACE_CARD_ALT, "MITRE Matrix Elevated Tactic"),
    (COLOR_ALERT, SURFACE_CARD_ALT, "MITRE Matrix Critical Tactic"),
    (COLOR_PURPLE, SURFACE_CARD_ALT, "MITRE Matrix AI Guarded Tactic"),
]

# =========================================================================
# 6. Component Helper Styles
# =========================================================================
SIDEBAR_ACTIVE = "#2563eb"
SIDEBAR_HOVER = "#1e293b"
BUTTON_PRIMARY = "#2563eb"
BUTTON_PRIMARY_HOVER = "#1d4ed8"
BUTTON_DANGER = "#e11d48"
BUTTON_DANGER_HOVER = "#be123c"
BUTTON_SECONDARY = "#1e293b"
BUTTON_SECONDARY_HOVER = "#334155"
BUTTON_EMERGENCY = "#f43f5e"
BUTTON_EMERGENCY_HOVER = "#e11d48"
BUTTON_CISO = "#0284c7"
BUTTON_CISO_HOVER = "#0369a1"

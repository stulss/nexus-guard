"""NEXUS-GUARD 데스크톱 GUI 색 대비(WCAG 2.x). nexus_guard/gui/theme.py 는 색 상수만 있어 tkinter 없이 import 된다.
CONTRAST_PAIRS 의 모든 (글자색, 바탕색, 설명) 조합이 4.5:1 이상이어야 한다. 기준을 낮추지 않는다."""
import importlib.util
from pathlib import Path

import pytest

THEME = Path(__file__).resolve().parents[1] / "nexus_guard" / "gui" / "theme.py"


def load_theme():
    # nexus_guard.gui.__init__ 이 tkinter 를 끌어올 수 있어 파일 경로로 직접 불러온다
    spec = importlib.util.spec_from_file_location("nexus_gui_theme", THEME)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


theme = load_theme()


def lum(hex_color):
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a, b):
    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_theme_exposes_contrast_pairs_as_plain_constants():
    assert len(theme.CONTRAST_PAIRS) >= 10
    for fg, bg, label in theme.CONTRAST_PAIRS:
        assert fg.startswith("#") and bg.startswith("#") and label


@pytest.mark.parametrize("fg,bg,label", theme.CONTRAST_PAIRS, ids=[p[2] for p in theme.CONTRAST_PAIRS])
def test_gui_text_pairs_meet_wcag_aa(fg, bg, label):
    assert ratio(fg, bg) >= 4.5, f"{label}: {fg} on {bg} = {ratio(fg, bg):.2f}:1"

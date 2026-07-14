"""
Tests for the pure-function helpers in phishing_sandbox_scan.py that
don't need a browser at all -- the cheapest, fastest tests in this
suite, and a good first line of defense since they run in milliseconds.
"""

import math

from backend.phishing_sandbox_scan import (
    _quadratic_bezier_points,
    classify_window_opens,
    shannon_entropy,
)


def test_bezier_path_starts_and_ends_at_the_right_points():
    p0, p1, p2 = (0, 0), (50, 100), (100, 0)
    points = _quadratic_bezier_points(p0, p1, p2, n=10)

    assert len(points) == 10
    # The curve should approach p2 by the last point (t approaches 1).
    last_x, last_y = points[-1]
    assert abs(last_x - p2[0]) < 1
    assert abs(last_y - p2[1]) < 1


def test_bezier_path_is_actually_curved_not_a_straight_line():
    """The whole point of using Bezier interpolation instead of
    Playwright's default linear steps is that the path bends -- assert
    that explicitly, or a future refactor could silently flatten it
    back to a straight line without any test noticing."""
    p0, p1, p2 = (0, 0), (50, 100), (100, 0)  # control point well off the p0->p2 line
    points = _quadratic_bezier_points(p0, p1, p2, n=20)

    # A straight line from (0,0) to (100,0) would have y == 0 throughout.
    # The midpoint of a real quadratic curve through a control point at
    # y=100 should be substantially off that line.
    mid_y = points[len(points) // 2][1]
    assert mid_y > 20, "midpoint should be pulled toward the control point, not sit on the straight line"


def test_classify_window_opens_distinguishes_popups_from_tabs():
    events = [
        {"windowFeatures": ["width=400", "height=300"], "userGesture": True},   # sized -> popup
        {"windowFeatures": [], "userGesture": False},                          # no gesture -> popup
        {"windowFeatures": [], "userGesture": True},                           # plain link click -> tab
    ]
    popups, tabs = classify_window_opens(events)
    assert popups == 2
    assert tabs == 1


def test_classify_window_opens_handles_empty_list():
    assert classify_window_opens([]) == (0, 0)


def test_shannon_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_uniform_text_is_low():
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0


def test_shannon_entropy_random_looking_text_is_higher():
    low = shannon_entropy("aaaaaaaaaaaaaaaa")
    high = shannon_entropy("aK9$mZ#3xQ7!pL2&")
    assert high > low

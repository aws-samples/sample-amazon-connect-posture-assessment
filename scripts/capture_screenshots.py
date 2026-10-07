#!/usr/bin/env python3
"""Capture documentation screenshots from the sample assessment reports.

Install the optional screenshot dependencies before running this script:

    pip install -e ".[screenshots]"
    playwright install chromium

The default invocation captures the full length of the checked-in sample report
(about 1440x3040 at the default viewport width) plus a crop spanning the
Executive summary through the Caller journey map for inline use in the README:

    python scripts/capture_screenshots.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = REPO_ROOT / "examples" / "sample_assessment_report.html"
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "images" / "sample-assessment-report-full.png"
DEFAULT_PREVIEW_OUTPUT = REPO_ROOT / "docs" / "images" / "sample-assessment-report.png"
DEFAULT_PREVIEW_FROM = "Executive summary"
DEFAULT_PREVIEW_TO = "Caller journey map"
# Matches the vertical gap between report sections so the crop keeps a margin.
PREVIEW_PADDING_PX = 20

# Returns the document-space vertical bounds of the report section whose h2 starts
# with the given text. Climbs from the heading to the outermost ancestor that holds
# no other h2, which is the section's slot in the page's vertical stack.
_SECTION_BOUNDS_JS = """(text) => {
  const heading = [...document.querySelectorAll('h2')]
    .find((h) => h.textContent.trim().startsWith(text));
  if (!heading) return null;
  let section = heading;
  while (section.parentElement && section.parentElement.querySelectorAll('h2').length === 1) {
    section = section.parentElement;
  }
  const rect = section.getBoundingClientRect();
  return { top: rect.top + window.scrollY, bottom: rect.bottom + window.scrollY };
}"""


def parse_args() -> argparse.Namespace:
    """Parse command-line options for the screenshot workflow."""
    parser = argparse.ArgumentParser(
        description="Capture a screenshot from an HTML assessment report."
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT,
        help=f"HTML report to capture (default: {DEFAULT_REPORT})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"PNG output path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--preview-output",
        type=Path,
        default=DEFAULT_PREVIEW_OUTPUT,
        help=(
            "PNG path for a crop of the full capture from --preview-from through "
            f"--preview-to (default: {DEFAULT_PREVIEW_OUTPUT})"
        ),
    )
    parser.add_argument(
        "--preview-from",
        default=DEFAULT_PREVIEW_FROM,
        help=f"Heading of the first section in the preview (default: {DEFAULT_PREVIEW_FROM!r}).",
    )
    parser.add_argument(
        "--preview-to",
        default=DEFAULT_PREVIEW_TO,
        help=f"Heading of the last section in the preview (default: {DEFAULT_PREVIEW_TO!r}).",
    )
    parser.add_argument(
        "--no-preview",
        action="store_true",
        help="Skip writing the preview crop.",
    )
    parser.add_argument("--width", type=int, default=1440, help="Viewport width in pixels.")
    parser.add_argument("--height", type=int, default=900, help="Viewport height in pixels.")
    parser.add_argument(
        "--scroll-y",
        type=int,
        default=0,
        help="Vertical scroll position before a --viewport-only capture (default: 0).",
    )
    parser.add_argument(
        "--dark-mode",
        action="store_true",
        help="Enable the report's dark mode before capture.",
    )
    parser.add_argument(
        "--viewport-only",
        action="store_true",
        help="Capture only the visible viewport instead of the complete report (no preview).",
    )
    parser.add_argument(
        "--wait-ms",
        type=int,
        default=1500,
        help="Time to wait for charts and client-side rendering (default: 1500).",
    )
    parser.add_argument(
        "--no-optimize",
        action="store_true",
        help="Skip Pillow PNG optimization after capture.",
    )
    return parser.parse_args()


def _load_dependencies() -> tuple[Any, Any]:
    """Import optional browser dependencies with an actionable error."""
    try:
        from PIL import Image
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit(
            "Screenshot dependencies are missing. Install them with:\n"
            '  pip install -e ".[screenshots]"\n'
            "  playwright install chromium"
        ) from exc
    return Image, sync_playwright


def _validate_args(args: argparse.Namespace) -> None:
    """Reject invalid paths and viewport values before launching a browser."""
    if not args.report.is_file():
        raise SystemExit(f"Report file not found: {args.report}")
    if args.width <= 0 or args.height <= 0:
        raise SystemExit("Viewport width and height must be positive integers.")
    if args.scroll_y < 0:
        raise SystemExit("Scroll position must be zero or greater.")
    if args.wait_ms < 0:
        raise SystemExit("Wait time must be zero or greater.")


def _prepare_page(page: Any, args: argparse.Namespace) -> None:
    """Load the report and apply deterministic state before capturing it."""
    # The report UI reads its theme from localStorage["darkMode"] before the
    # OS preference, so pinning it here makes captures independent of the host.
    page.add_init_script(
        f"window.localStorage.setItem('darkMode', '{str(args.dark_mode).lower()}');"
    )
    page.goto(args.report.resolve().as_uri(), wait_until="domcontentloaded")
    page.wait_for_selector("#root h1", timeout=10_000)
    page.wait_for_timeout(args.wait_ms)

    page.evaluate("(scrollY) => window.scrollTo(0, scrollY)", args.scroll_y)
    page.wait_for_timeout(100)


def _optimize_png(image_path: Path, image_module: Any) -> None:
    """Apply lossless PNG optimization while preserving the documentation format."""
    with image_module.open(image_path) as image:
        if image.mode in {"RGBA", "P"}:
            image = image.convert("RGB")
        image.save(image_path, format="PNG", optimize=True)


def _preview_bounds(page: Any, args: argparse.Namespace) -> tuple[int, int]:
    """Locate the vertical span from the first to the last preview section."""
    start = page.evaluate(_SECTION_BOUNDS_JS, args.preview_from)
    end = page.evaluate(_SECTION_BOUNDS_JS, args.preview_to)
    missing = [
        text for text, bounds in ((args.preview_from, start), (args.preview_to, end)) if not bounds
    ]
    if missing:
        raise RuntimeError(f"Report section not found: {', '.join(map(repr, missing))}")
    top = int(start["top"]) - PREVIEW_PADDING_PX
    bottom = int(end["bottom"]) + PREVIEW_PADDING_PX
    if bottom <= top:
        raise RuntimeError(f"{args.preview_to!r} must appear after {args.preview_from!r}.")
    return max(top, 0), bottom


def _write_preview(
    source: Path, preview_path: Path, bounds: tuple[int, int], image_module: Any
) -> None:
    """Crop the full capture so both images come from one render."""
    preview_path.parent.mkdir(parents=True, exist_ok=True)
    top, bottom = bounds
    with image_module.open(source) as image:
        image.crop((0, top, image.width, min(bottom, image.height))).save(preview_path)


def capture(args: argparse.Namespace) -> list[Path]:
    """Capture the report screenshot, derive the preview crop, and optimize both."""
    image_module, sync_playwright = _load_dependencies()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_preview = not args.viewport_only and not args.no_preview
    preview_bounds = (0, 0)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": args.width, "height": args.height})
            _prepare_page(page, args)
            page.screenshot(path=str(args.output), full_page=not args.viewport_only)
            if write_preview:
                preview_bounds = _preview_bounds(page, args)
        finally:
            browser.close()

    outputs = [args.output]
    if write_preview:
        _write_preview(args.output, args.preview_output, preview_bounds, image_module)
        outputs.append(args.preview_output)

    if not args.no_optimize:
        for output in outputs:
            _optimize_png(output, image_module)
    return outputs


def main() -> int:
    """Run the screenshot capture command."""
    args = parse_args()
    _validate_args(args)
    try:
        outputs = capture(args)
    except RuntimeError as exc:
        print(f"Screenshot capture failed: {exc}", file=sys.stderr)
        return 1
    for output in outputs:
        print(f"Screenshot captured: {output} ({output.stat().st_size / 1024:.1f} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

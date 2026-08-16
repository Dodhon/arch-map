#!/usr/bin/env python3
"""
Automated Demo Video Generator for arch-map.

Renders architecture Markdown with dark mode & Mermaid.js, performs smooth
human-paced camera scrolls, animates cursor clicks on diagram nodes, and
jumps to the source code implementation. Emits web-optimized 1080p MP4 & GIF.
"""

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHROME_PATH = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def build_preview_html(arch_md: str, code_content: str, code_path: str, highlight_start: int, highlight_end: int) -> str:
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>arch-map Interactive Architecture Demo</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<style>
  :root {
    --bg: #0d1117;
    --card: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --link: #58a6ff;
    --accent: #2f81f7;
    --code-bg: #161b22;
  }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 32px 48px;
    line-height: 1.6;
    overflow-x: hidden;
  }
  .container {
    max-width: 1100px;
    margin: 0 auto;
    transition: transform 0.6s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.4s ease;
  }
  h1, h2, h3 {
    color: #fff;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    margin-top: 32px;
  }
  table {
    border-collapse: collapse;
    width: 100%;
    margin: 16px 0;
    background: var(--card);
    border-radius: 6px;
    overflow: hidden;
    border: 1px solid var(--border);
  }
  th, td {
    padding: 10px 16px;
    border: 1px solid var(--border);
    text-align: left;
  }
  th { background: #21262d; color: #fff; font-weight: 600; }
  a { color: var(--link); text-decoration: none; cursor: pointer; }
  a:hover { text-decoration: underline; }
  code {
    background: rgba(110,118,129,0.4);
    padding: 2px 6px;
    border-radius: 4px;
    font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, monospace;
    font-size: 0.9em;
  }
  .mermaid {
    background: var(--card);
    padding: 20px;
    border-radius: 8px;
    border: 1px solid var(--border);
    margin: 20px 0;
    display: flex;
    justify-content: center;
  }
  .cursor {
    position: fixed;
    width: 20px;
    height: 20px;
    background: rgba(255, 255, 255, 0.9);
    border: 2px solid #000;
    border-radius: 50% 0 50% 50%;
    transform: rotate(-45deg);
    pointer-events: none;
    z-index: 99999;
    box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    transition: transform 0.15s ease, opacity 0.2s ease;
    display: none;
  }
  .cursor.clicking {
    transform: rotate(-45deg) scale(0.85);
    background: #58a6ff;
  }
  .pulse {
    position: fixed;
    width: 40px;
    height: 40px;
    border: 2px solid #58a6ff;
    border-radius: 50%;
    pointer-events: none;
    z-index: 99998;
    transform: translate(-50%, -50%);
    animation: ripple 0.6s ease-out forwards;
  }
  @keyframes ripple {
    0% { opacity: 1; transform: translate(-50%, -50%) scale(0.3); }
    100% { opacity: 0; transform: translate(-50%, -50%) scale(2.2); }
  }
  #code-view {
    display: none;
    position: fixed;
    top: 40px;
    left: 50%;
    transform: translateX(-50%);
    width: 900px;
    max-height: 80vh;
    background: #161b22;
    border: 1px solid #58a6ff;
    border-radius: 8px;
    box-shadow: 0 16px 48px rgba(0,0,0,0.8);
    z-index: 10000;
    overflow: hidden;
  }
  .code-header {
    background: #21262d;
    padding: 12px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
  }
  .code-body {
    padding: 16px 0;
    margin: 0;
    overflow-y: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 14px;
    line-height: 1.5;
  }
  .code-line {
    padding: 2px 20px;
    display: flex;
  }
  .code-line.highlight {
    background: rgba(56, 139, 253, 0.15);
    border-left: 3px solid #58a6ff;
  }
  .line-no {
    color: #6e7681;
    width: 40px;
    user-select: none;
    text-align: right;
    margin-right: 16px;
  }
</style>
</head>
<body>
<div class="cursor" id="cursor"></div>
<div class="container" id="doc-container">
  <div id="content"></div>
</div>

<div id="code-view">
  <div class="code-header">
    <span>__CODE_PATH__ — Jumped to Line __HL_START__</span>
    <span style="color:#58a6ff; font-size:12px;">● Linked from Diagram Node</span>
  </div>
  <div class="code-body" id="code-lines"></div>
</div>

<script>
  mermaid.initialize({
    startOnLoad: false,
    theme: 'dark',
    themeVariables: {
      darkMode: true,
      background: '#161b22',
      primaryColor: '#21262d',
      primaryTextColor: '#e6edf3',
      primaryBorderColor: '#30363d',
      lineColor: '#58a6ff',
      secondaryColor: '#161b22',
      tertiaryColor: '#0d1117'
    }
  });

  const rawMd = `__RAW_MD__`;
  const codeContent = `__CODE_CONTENT__`;
  const hlStart = __HL_START__;
  const hlEnd = __HL_END__;

  const codeContainer = document.getElementById('code-lines');
  codeContent.split('\\n').forEach((line, idx) => {
    const lineNum = idx + 1;
    const div = document.createElement('div');
    div.className = 'code-line' + (lineNum >= hlStart && lineNum <= hlEnd ? ' highlight' : '');
    div.innerHTML = `<span class="line-no">${lineNum}</span><code>${escapeHtml(line)}</code>`;
    codeContainer.appendChild(div);
  });

  function escapeHtml(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  let html = marked.parse(rawMd);
  document.getElementById('content').innerHTML = html;

  document.querySelectorAll('pre code.language-mermaid').forEach(el => {
    const pre = el.parentElement;
    const div = document.createElement('div');
    div.className = 'mermaid';
    div.textContent = el.textContent;
    pre.replaceWith(div);
  });

  mermaid.run();

  window.jumpToCode = function() {
    const codeView = document.getElementById('code-view');
    codeView.style.display = 'block';
  };

  window.smoothScrollTo = function(targetY, durationMs) {
    return new Promise(resolve => {
      const startY = window.scrollY;
      const diff = targetY - startY;
      const startTime = performance.now();

      function step(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / durationMs, 1);
        const ease = progress < 0.5
          ? 4 * progress * progress * progress
          : 1 - Math.pow(-2 * progress + 2, 3) / 2;
        window.scrollTo(0, startY + diff * ease);
        if (progress < 1) {
          requestAnimationFrame(step);
        } else {
          resolve();
        }
      }
      requestAnimationFrame(step);
    });
  };

  window.moveCursorTo = function(x, y, durationMs) {
    return new Promise(resolve => {
      const cursor = document.getElementById('cursor');
      cursor.style.display = 'block';
      const startX = cursor.offsetLeft || window.innerWidth / 2;
      const startY = cursor.offsetTop || window.innerHeight / 2;
      const startTime = performance.now();

      function step(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / durationMs, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        const curX = startX + (x - startX) * ease;
        const curY = startY + (y - startY) * ease;
        cursor.style.left = curX + 'px';
        cursor.style.top = curY + 'px';
        if (progress < 1) {
          requestAnimationFrame(step);
        } else {
          resolve();
        }
      }
      requestAnimationFrame(step);
    });
  };

  window.triggerClick = function(x, y) {
    const cursor = document.getElementById('cursor');
    cursor.classList.add('clicking');
    const pulse = document.createElement('div');
    pulse.className = 'pulse';
    pulse.style.left = x + 'px';
    pulse.style.top = y + 'px';
    document.body.appendChild(pulse);
    setTimeout(() => {
      cursor.classList.remove('clicking');
      pulse.remove();
    }, 400);
  };
</script>
</body>
</html>
"""
    return (
        html_template.replace("__RAW_MD__", arch_md.replace("`", "\\`").replace("$", "\\$"))
        .replace("__CODE_CONTENT__", code_content.replace("`", "\\`").replace("\\", "\\\\"))
        .replace("__CODE_PATH__", code_path)
        .replace("__HL_START__", str(highlight_start))
        .replace("__HL_END__", str(highlight_end))
    )


async def record_video(html_path: Path, output_mp4: Path, output_gif: Path):
    from playwright.async_api import async_playwright

    temp_video_dir = ROOT / "docs/.video_temp"
    temp_video_dir.mkdir(parents=True, exist_ok=True)

    # Ensure ms-playwright ffmpeg link exists
    cache_ffmpeg = Path.home() / "Library/Caches/ms-playwright/ffmpeg-1010"
    cache_ffmpeg.mkdir(parents=True, exist_ok=True)
    ffmpeg_link = cache_ffmpeg / "ffmpeg-mac"
    if not ffmpeg_link.exists():
        system_ffmpeg = shutil.which("ffmpeg")
        if system_ffmpeg:
            os.symlink(system_ffmpeg, ffmpeg_link)

    print("🎬 Starting Playwright browser recording...")
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path=CHROME_PATH if os.path.exists(CHROME_PATH) else None,
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-web-security",
                "--allow-file-access-from-files",
            ],
        )
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            device_scale_factor=1,
            record_video_dir=str(temp_video_dir),
            record_video_size={"width": 1920, "height": 1080},
        )
        page = await context.new_page()
        await page.goto(f"file://{html_path}")
        await page.wait_for_timeout(2500)

        # Scene 1: Top Overview
        print("  ▶ Scene 1: Document Overview")
        await page.wait_for_timeout(2500)

        # Scene 2: Level 1 System Context
        print("  ▶ Scene 2: Level 1 System Context & Dependencies")
        await page.evaluate("window.smoothScrollTo(480, 2000)")
        await page.wait_for_timeout(3000)

        # Scene 3: Level 2a Control Plane
        print("  ▶ Scene 3: Level 2a Control Plane Wiring")
        await page.evaluate("window.smoothScrollTo(1100, 2000)")
        await page.wait_for_timeout(3000)

        # Scene 4: Level 2b Data Plane
        print("  ▶ Scene 4: Level 2b Horizontal Data Pipeline")
        await page.evaluate("window.smoothScrollTo(1720, 2000)")
        await page.wait_for_timeout(2000)

        # Scene 5: Cursor Navigation & Hover
        print("  ▶ Scene 5: Cursor Navigation on Diagram Node")
        await page.evaluate("window.moveCursorTo(740, 530, 1400)")
        await page.wait_for_timeout(1600)

        # Scene 6: Interactive Click
        print("  ▶ Scene 6: Click Node to Jump to Source")
        await page.evaluate("window.triggerClick(740, 530)")
        await page.wait_for_timeout(400)
        await page.evaluate("window.jumpToCode()")
        await page.wait_for_timeout(3000)

        # Scene 7: Code Inspection
        print("  ▶ Scene 7: Inspecting Implementation")
        await page.evaluate("""
            const el = document.getElementById('code-view');
            el.querySelector('.code-body').scrollTo({ top: 120, behavior: 'smooth' });
        """)
        await page.wait_for_timeout(4000)

        video = page.video
        await context.close()
        video_path = await video.path()
        await browser.close()

    print(f"\nRaw capture saved. Encoding {output_mp4} with FFmpeg...")
    subprocess.run([
        "ffmpeg", "-y", "-i", video_path,
        "-c:v", "libx264", "-pix_fmt", "yuv420p",
        "-preset", "slow", "-crf", "18",
        "-movflags", "+faststart",
        str(output_mp4),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"Encoding {output_gif} ...")
    subprocess.run([
        "ffmpeg", "-y", "-i", str(output_mp4),
        "-vf", "fps=12,scale=960:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse",
        "-loop", "0",
        str(output_gif),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if os.path.exists(temp_video_dir):
        shutil.rmtree(temp_video_dir)


def main():
    arch_file = ROOT / "examples/azure-chatbot-architecture.md"
    code_file = ROOT / "examples/azure-chatbot/src/foundry.py"

    arch_md = arch_file.read_text(encoding="utf-8")
    code_content = code_file.read_text(encoding="utf-8")

    html_content = build_preview_html(
        arch_md=arch_md,
        code_content=code_content,
        code_path="src/foundry.py",
        highlight_start=6,
        highlight_end=10,
    )

    temp_html = ROOT / "docs/demo_preview.html"
    temp_html.write_text(html_content, encoding="utf-8")

    output_mp4 = ROOT / "docs/demo.mp4"
    output_gif = ROOT / "docs/demo.gif"

    asyncio.run(record_video(temp_html, output_mp4, output_gif))

    shutil.copy(output_mp4, ROOT / "examples/demo.mp4")

    print("\n🎉 Demo video generation complete:")
    print(f"  - Video: {output_mp4} ({os.path.getsize(output_mp4)} bytes)")
    print(f"  - GIF: {output_gif} ({os.path.getsize(output_gif)} bytes)")


if __name__ == "__main__":
    main()

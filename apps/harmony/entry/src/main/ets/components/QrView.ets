// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// A QR code the core drew: its rows of modules, '1' for a dark one, on a
// white square with the quiet zone, so that any camera reads it in the
// dark theme too.

const QUIET: number = 4;

@ComponentV2
export struct QrView {
  @Param modules: string[] = [];
  @Param side: number = 260;
  private settings: RenderingContextSettings = new RenderingContextSettings(true);
  private ctx: CanvasRenderingContext2D = new CanvasRenderingContext2D(this.settings);

  @Monitor('modules')
  redraw(): void {
    this.draw();
  }

  draw(): void {
    const n = this.modules.length;
    this.ctx.fillStyle = '#ffffff';
    this.ctx.fillRect(0, 0, this.side, this.side);
    if (n === 0) {
      return;
    }
    const cell = this.side / (n + 2 * QUIET);
    this.ctx.fillStyle = '#000000';
    for (let y = 0; y < n; y++) {
      const row = this.modules[y];
      for (let x = 0; x < row.length; x++) {
        if (row.charAt(x) === '1') {
          this.ctx.fillRect((x + QUIET) * cell, (y + QUIET) * cell, Math.ceil(cell), Math.ceil(cell));
        }
      }
    }
  }

  build() {
    Canvas(this.ctx)
      .width(this.side)
      .height(this.side)
      .onReady(() => {
        this.draw();
      })
  }
}

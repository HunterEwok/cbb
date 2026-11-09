# SPDX-License-Identifier: AGPL-3.0-only
#
# Makes the site's textures in static/, for each theme: the polished wood of
# the boards' frames (old walnut for the dark theme, pale oak for the light
# one; -h.jpg with its grain along the rails, -v.jpg the same turned
# upright) and the wool felt the pages lie on (felt.jpg and felt-light.jpg,
# tiles that wrap without seams). The seeds are fixed, so the files come out
# the same each time. Needs NumPy and Pillow.
import os
import numpy as np
from PIL import Image

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def wood(name, dark, mid, light):
    rng = np.random.default_rng(11)
    W, H = 1800, 120

    def noise(gw, gh, w=W, h=H):
        a = (rng.random((gh, gw)) * 255).astype(np.uint8)
        return np.asarray(Image.fromarray(a).resize((w, h), Image.BICUBIC), dtype=np.float32) / 255

    y = np.arange(H)[:, None].astype(np.float32)
    warp = (noise(8, 3) - .5) * 18 + (noise(40, 6) - .5) * 4
    rings = np.sin((y + warp) * 0.42 + (noise(5, 2) - .5) * 6)
    rings = (rings * 0.5 + 0.5) ** 3
    fib = noise(120, 110)  # long fibres
    fib2 = noise(400, 120)
    pores = (noise(1400, 90) > 0.86).astype(np.float32) * 0.5
    figure = noise(9, 2)  # broad light and dark patches
    v = 0.30 * rings + 0.30 * fib + 0.12 * fib2 + 0.28 * figure - 0.10 * pores
    v = (v - v.min()) / (v.max() - v.min())
    dark, mid, light = np.array(dark), np.array(mid), np.array(light)
    c = np.where(v[..., None] < .5, dark + (mid - dark) * (v[..., None] / .5), mid + (light - mid) * ((v[..., None] - .5) / .5))
    img = Image.fromarray(np.clip(c, 0, 255).astype(np.uint8))
    img.save(os.path.join(STATIC, name + "-h.jpg"), quality=82)
    img.rotate(90, expand=True).save(os.path.join(STATIC, name + "-v.jpg"), quality=82)


def felt(name, base, amount):
    # Dense short fibres at every angle, a fine nap and a faint mottling,
    # filtered in the frequency domain so that the tile wraps.
    N = 512
    rng = np.random.default_rng(5)
    f = np.fft.fftfreq(N)
    r = np.hypot(*np.meshgrid(f, f))

    def band(lo, hi, amp=1):
        m = ((r >= lo) & (r < hi)).astype(float)
        n = np.real(np.fft.ifft2(np.fft.fft2(rng.standard_normal((N, N))) * m))
        return amp * n / n.std()

    fine = band(.18, .5)  # the nap: grain the size of a fibre
    mid = band(.04, .18, .6)  # tufts
    mott = band(.004, .03, .5)  # the cloth's gentle unevenness
    fib = np.zeros((N, N))  # short fibres, lighter than the cloth
    for _ in range(9000):
        x, y = rng.uniform(0, N, 2)
        a = rng.uniform(0, np.pi)
        L = rng.uniform(3, 9)
        for t in np.linspace(0, L, int(L * 2)):
            fib[int(y + t * np.sin(a)) % N, int(x + t * np.cos(a)) % N] += 1
    fib = np.real(np.fft.ifft2(np.fft.fft2(fib) * np.exp(-(r ** 2) / (2 * .25 ** 2))))
    fib = (fib - fib.mean()) / fib.std()
    v = np.tanh((.55 * fine + .35 * mid + .45 * mott + .35 * fib) / 2.2)  # soft limits, no hard specks
    img = np.array(base, float)[None, None, :] * (1 + amount * v[..., None])
    Image.fromarray(np.clip(img, 0, 255).astype(np.uint8)).save(os.path.join(STATIC, name + ".jpg"), quality=88)


if __name__ == "__main__":
    # the dark theme: old walnut on the site's deep teal
    wood("wood", [38, 22, 12], [86, 52, 27], [138, 92, 52])
    felt("felt", [13, 31, 38], .42)
    # the light theme: pale waxed oak on a soft sand-coloured cloth
    wood("oak", [150, 112, 70], [196, 156, 104], [228, 196, 146])
    felt("felt-light", [214, 205, 186], .07)

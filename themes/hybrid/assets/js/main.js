function initReadProgress() {
  const bar = document.querySelector("[data-read-progress]");
  const meter = bar && bar.closest(".read-progress");
  const article = document.querySelector(".post");

  if (!bar || !meter || !article) {
    return;
  }

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  /** Lower = softer follow (seconds-scale). ~2.2 feels very smooth. */
  const response = reduceMotion ? 24 : 2.2;

  let targetRatio = 0;
  let displayRatio = 0;
  let lastTime = 0;

  function measureTarget() {
    const start = article.getBoundingClientRect().top + window.scrollY;
    const end = start + article.offsetHeight - window.innerHeight;
    const range = end - start;

    if (range <= 0) {
      targetRatio = window.scrollY > 0 ? 1 : 0;
      return;
    }

    targetRatio = (window.scrollY - start) / range;
    targetRatio = Math.min(1, Math.max(0, targetRatio));
  }

  function tick(now) {
    if (!lastTime) {
      lastTime = now;
    }
    const dt = Math.min(48, now - lastTime) / 1000;
    lastTime = now;

    const delta = targetRatio - displayRatio;
    if (Math.abs(delta) < 0.0002) {
      displayRatio = targetRatio;
    } else {
      const alpha = 1 - Math.exp(-response * dt);
      displayRatio += delta * alpha;
    }

    bar.style.transform = `scaleX(${displayRatio})`;
    meter.setAttribute("aria-valuenow", String(Math.round(displayRatio * 100)));

    requestAnimationFrame(tick);
  }

  function onScrollOrResize() {
    measureTarget();
  }

  window.addEventListener("scroll", onScrollOrResize, { passive: true });
  window.addEventListener("resize", onScrollOrResize, { passive: true });
  measureTarget();
  requestAnimationFrame(tick);
}

function initTagJump() {
  document.querySelectorAll("[data-tag-jump]").forEach((select) => {
    select.addEventListener("change", () => {
      const url = select.value;
      if (url) {
        window.location.href = url;
      }
    });
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    initReadProgress();
    initTagJump();
  });
} else {
  initReadProgress();
  initTagJump();
}

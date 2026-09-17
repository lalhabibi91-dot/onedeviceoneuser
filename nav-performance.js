// Lightweight shared navigation setup. It intentionally does not intercept
// clicks: native navigation preserves every existing page handler and is the
// fastest, most reliable path in Chrome.
(() => {
  'use strict';

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('./sw.js').catch(() => {
        // The site can also be opened directly from a file, where service
        // workers are unavailable. Native navigation still works normally.
      });
    }, { once: true });
  }

  // Warm the main screens only when the browser is idle, preventing preloads
  // from competing with the page that the user is currently opening.
  const warmPages = () => {
    if (navigator.connection && navigator.connection.saveData) return;
    ['pay.html', 'home.html', 'contact-pay.html', 'activty.html'].forEach((href) => {
      const link = document.createElement('link');
      link.rel = 'prefetch';
      link.as = 'document';
      link.href = href;
      document.head.appendChild(link);
    });
  };

  if ('requestIdleCallback' in window) {
    window.requestIdleCallback(warmPages, { timeout: 1500 });
  } else {
    window.setTimeout(warmPages, 600);
  }
})();

(() => {
  const form = document.getElementById('proxyForm');
  const input = document.getElementById('url');
  const error = document.getElementById('error');

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    error.hidden = true;
    let value = input.value.trim();
    if (!value) return;
    if (!/^https?:\/\//i.test(value)) value = `https://${value}`;
    try {
      const url = new URL(value);
      if (!['http:', 'https:'].includes(url.protocol)) throw new Error();
      window.location.href = `/proxy?url=${encodeURIComponent(url.toString())}`;
    } catch {
      error.textContent = 'Enter a valid HTTP or HTTPS URL.';
      error.hidden = false;
    }
  });
})();

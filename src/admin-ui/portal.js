// Shows that the sign-in is under way, and stops a second tap sending it twice.
for (const form of document.querySelectorAll('form')) {
  form.addEventListener('submit', () => {
    const button = form.querySelector('button');
    if (!button) return;
    setTimeout(() => {
      button.disabled = true;
      button.textContent = 'Connecting…';
    }, 0);
  });
}

document.addEventListener('DOMContentLoaded', function () {
  const statusNodes = document.querySelectorAll('.status-card strong');
  statusNodes.forEach((node) => {
    const text = node.textContent.trim();
    if (text === 'VERIFIED') {
      node.style.color = '#34d399';
    }
  });
});

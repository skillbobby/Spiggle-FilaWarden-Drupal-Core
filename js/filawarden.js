
(function () {
  var root = document.getElementById('fw-app');
  if (!root) return;
  var key = 'filawarden-theme';
  if (localStorage.getItem(key) === 'dark') root.classList.add('dark');
  var btn = document.getElementById('fw-theme');
  if (btn) btn.addEventListener('click', function () {
    root.classList.toggle('dark');
    localStorage.setItem(key, root.classList.contains('dark') ? 'dark' : 'light');
  });
})();

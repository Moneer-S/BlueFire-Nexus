(function () {
  var root = document.documentElement;
  var key = "bluefire-lab-theme";
  try {
    var saved = localStorage.getItem(key);
    if (saved) root.dataset.theme = saved;
  } catch (error) {}
  document.getElementById("theme").addEventListener("click", function () {
    var dark = root.dataset.theme
      ? root.dataset.theme === "dark"
      : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try {
      localStorage.setItem(key, root.dataset.theme);
    } catch (error) {}
  });
  function openTarget() {
    var target = document.getElementById(location.hash.slice(1));
    if (target && target.tagName === "DETAILS") target.open = true;
  }
  addEventListener("hashchange", openTarget);
  openTarget();
})();

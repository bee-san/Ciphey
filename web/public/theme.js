// Applies a theme saved by the theme button before the page is drawn, so it doesn't flash in
// the system theme first. A file of its own, not inline, because the CSP allows no inline
// scripts. src/shell/theme.ts writes the setting.
try {
  const theme = localStorage.getItem("ciphey-theme");
  if (theme === "light" || theme === "dark") document.documentElement.setAttribute("data-theme", theme);
} catch {
  // Storage blocked: follow the system theme
}

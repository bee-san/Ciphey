// The theme button: dark or light. The page starts in the system's theme; pressing the button
// switches, and the choice is remembered (localStorage, on this device only). Switching back
// to the system's theme forgets the choice, so the page follows the system again.

const KEY = "ciphey-theme";
type Theme = "light" | "dark";

const system = window.matchMedia("(prefers-color-scheme: dark)");
const systemTheme = (): Theme => (system.matches ? "dark" : "light");

function chosen(): Theme | null {
  const t = document.documentElement.getAttribute("data-theme");
  return t === "light" || t === "dark" ? t : null;
}

export function currentTheme(): Theme {
  return chosen() ?? systemTheme();
}

function save(theme: Theme | null): void {
  try {
    if (theme) localStorage.setItem(KEY, theme);
    else localStorage.removeItem(KEY);
  } catch {
    // Storage blocked: the choice lasts until the page is closed
  }
}

export function setTheme(theme: Theme): void {
  if (theme === systemTheme()) {
    document.documentElement.removeAttribute("data-theme");
    save(null);
  } else {
    document.documentElement.setAttribute("data-theme", theme);
    save(theme);
  }
}

export function initThemeToggle(): void {
  const button = document.getElementById("theme-toggle");
  if (!button) return;
  const sync = () => button.setAttribute("aria-pressed", String(currentTheme() === "dark"));
  button.addEventListener("click", () => {
    setTheme(currentTheme() === "dark" ? "light" : "dark");
    sync();
  });
  system.addEventListener("change", sync);
  sync();
}

// Plain module (no 'use client') so the root layout, a server component, can
// inline the init script as a string.

export const THEME_STORAGE_KEY = 'truent-theme'

/**
 * Runs before hydration so the first paint already carries the right class
 * and there is no light/dark flash. Reads the saved choice, else the OS
 * preference. Kept as a string because it must run before React loads.
 */
export const THEME_INIT_SCRIPT = `(function(){try{var s=localStorage.getItem('${THEME_STORAGE_KEY}');var d=s?s==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;var c=document.documentElement.classList;d?c.add('dark'):c.remove('dark');}catch(e){}})();`

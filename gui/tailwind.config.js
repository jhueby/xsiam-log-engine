/** @type {import('tailwindcss').Config} */

// Colors resolve through CSS variables so themes can be swapped at runtime by
// toggling a class on <html>. Each variable holds space-separated RGB channels
// ("99 102 241") so Tailwind's <alpha-value> opacity modifiers keep working.
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`

const scale = (prefix, stops) =>
  Object.fromEntries(stops.map((s) => [s, v(`${prefix}-${s}`)]))

const GRAY_STOPS = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 950]
const ACCENT_STOPS = [50, 300, 400, 500, 600, 700]

export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        gray: scale('gray', GRAY_STOPS),
        // The primary accent. `indigo` and `brand` share the same themeable
        // accent variables so buttons, sliders, nav, and the logo all recolor
        // together per theme.
        indigo: scale('accent', ACCENT_STOPS),
        brand: scale('accent', ACCENT_STOPS),
      },
    },
  },
  plugins: [],
}

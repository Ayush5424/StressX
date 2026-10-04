/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          dark: '#090d16',
          card: '#0f172a',
          cardHover: '#17223b',
          border: '#1e293b',
          borderLight: '#334155',
          cyan: '#06b6d4',
          emerald: '#10b981',
          amber: '#f59e0b',
          crimson: '#ef4444',
          violet: '#8b5cf6',
          blue: '#3b82f6',
        }
      }
    },
  },
  plugins: [],
}

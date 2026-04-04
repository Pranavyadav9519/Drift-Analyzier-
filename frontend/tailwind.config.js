/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        sentinel: {
          dark: '#0f172a',
          card: '#1e293b',
          border: '#334155',
          accent: '#6366f1',
          green: '#22c55e',
          yellow: '#f59e0b',
          red: '#ef4444',
        },
      },
    },
  },
  plugins: [],
};

/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          950: '#090d16',
          900: '#0f172a',
          850: '#151e32',
          800: '#1e293b',
          700: '#334155',
        },
        soc: {
          bg: '#0B0F0D',
          card: '#121814',
          panel: '#090D0B',
          hover: '#16221c',
          black: '#060907'
        }
      }
    },
  },
  plugins: [],
}

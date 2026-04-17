/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#060912',
          bg2: '#0a0f1e',
          bg3: '#0d1320',
          bg4: '#111827',
          border: 'rgba(99,179,237,0.12)',
          cyan: '#00d4ff',
          red: '#ff4757',
          orange: '#ff6b35',
          yellow: '#ffd700',
          green: '#00ff88',
          purple: '#a855f7',
        },
      },
      fontFamily: {
        mono: ['SF Mono', 'Cascadia Code', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan': 'scan 8s linear infinite',
      },
      keyframes: {
        scan: {
          '0%': { top: '44px' },
          '100%': { top: '100vh' },
        },
      },
    },
  },
  plugins: [],
}

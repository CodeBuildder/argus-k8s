export default function ArgusLogo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        {/* Glow filter for the eye */}
        <filter id="eyeGlow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
        
        {/* Outer glow for hexagon */}
        <filter id="hexGlow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
        
        {/* Gradient for hexagon */}
        <linearGradient id="hexGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.3"/>
          <stop offset="50%" stopColor="#58a6ff" stopOpacity="0.2"/>
          <stop offset="100%" stopColor="#00d4ff" stopOpacity="0.3"/>
        </linearGradient>
      </defs>
      
      {/* Hexagon */}
      <path 
        d="M 50 5 L 86.6 27.5 L 86.6 72.5 L 50 95 L 13.4 72.5 L 13.4 27.5 Z" 
        fill="url(#hexGradient)"
        stroke="#00d4ff"
        strokeWidth="2"
        filter="url(#hexGlow)"
      />
      
      {/* Inner hexagon for depth */}
      <path 
        d="M 50 15 L 78 32 L 78 68 L 50 85 L 22 68 L 22 32 Z" 
        fill="none"
        stroke="#58a6ff"
        strokeWidth="1"
        opacity="0.4"
      />
      
      {/* Eye outer ellipse */}
      <ellipse 
        cx="50" 
        cy="50" 
        rx="20" 
        ry="28" 
        fill="rgba(0, 212, 255, 0.15)"
        stroke="#00d4ff"
        strokeWidth="1.5"
      />
      
      {/* Eye iris */}
      <ellipse 
        cx="50" 
        cy="50" 
        rx="12" 
        ry="18" 
        fill="rgba(88, 166, 255, 0.3)"
        stroke="#58a6ff"
        strokeWidth="1"
      />
      
      {/* Eye pupil - glowing */}
      <ellipse 
        cx="50" 
        cy="50" 
        rx="6" 
        ry="10" 
        fill="#00d4ff"
        filter="url(#eyeGlow)"
      />
      
      {/* Pupil highlight */}
      <ellipse 
        cx="48" 
        cy="45" 
        rx="2" 
        ry="3" 
        fill="#ffffff"
        opacity="0.8"
      />
      
      {/* Scanning line animation */}
      <line 
        x1="30" 
        y1="50" 
        x2="70" 
        y2="50" 
        stroke="#00d4ff"
        strokeWidth="1"
        opacity="0.6"
      >
        <animate 
          attributeName="y1" 
          values="35;65;35" 
          dur="3s" 
          repeatCount="indefinite"
        />
        <animate 
          attributeName="y2" 
          values="35;65;35" 
          dur="3s" 
          repeatCount="indefinite"
        />
        <animate 
          attributeName="opacity" 
          values="0.3;0.8;0.3" 
          dur="3s" 
          repeatCount="indefinite"
        />
      </line>
    </svg>
  )
}

// Made with Bob

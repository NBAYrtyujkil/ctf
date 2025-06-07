
    document.addEventListener('DOMContentLoaded', () => {
      const canvas = document.getElementById('matrix-rain');
      const ctx = canvas.getContext('2d');

      // Initialize canvas size
      function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        initDrops();
      }

      // Binary characters (customize as needed)
      const chars = "01█▓▒░║═╬";
      const fontSize = 18;
      let drops = [];

      // Initialize drops
      function initDrops() {
        const cols = Math.floor(canvas.width / fontSize);
        drops = Array(cols).fill(0).map(() => Math.random() * -100);
      }

      // Draw the animation frame
      function draw() {
        // Semi-transparent overlay (creates fade effect)
        ctx.fillStyle = 'rgba(10, 25, 47, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        // Set text style
        ctx.fillStyle = '#64ffda'; // Cyber teal
        ctx.font = `${fontSize}px monospace`;

        // Draw each column
        for (let i = 0; i < drops.length; i++) {
          const char = chars[Math.floor(Math.random() * chars.length)];
          const x = i * fontSize;
          const y = drops[i] * fontSize;

          ctx.fillText(char, x, y);

          // Reset drop if it reaches the bottom + random chance
          if (y > canvas.height && Math.random() > 0.975) {
            drops[i] = 0;
          }
          drops[i]+=0.3;
        }

        requestAnimationFrame(draw); // Smooth animation
      }

      // Start the animation
      window.addEventListener('resize', resizeCanvas);
      resizeCanvas();
      draw();
    });

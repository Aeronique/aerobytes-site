// ===================================
// SMOOTH SCROLL
// ===================================
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// ===================================
// NAVBAR SCROLL EFFECT
// ===================================
let lastScroll = 0;
const nav = document.querySelector('.nav');

window.addEventListener('scroll', () => {
    const currentScroll = window.pageYOffset;
    
    if (currentScroll > 100) {
        nav.style.background = 'rgba(10, 10, 15, 0.95)';
        nav.style.boxShadow = '0 5px 20px rgba(0, 217, 255, 0.1)';
    } else {
        nav.style.background = 'rgba(10, 10, 15, 0.8)';
        nav.style.boxShadow = 'none';
    }
    
    lastScroll = currentScroll;
});

// ===================================
// INTERSECTION OBSERVER FOR ANIMATIONS
// ===================================
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -100px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
        }
    });
}, observerOptions);

// Observe all sections and cards (but not writeup pages)
document.querySelectorAll('.section, .project-card, .writeup-item').forEach(el => {
    if (el.closest('.writeup-page')) return; // Skip animation on writeup pages
    el.style.opacity = '0';
    el.style.transform = 'translateY(30px)';
    el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(el);
});

// ===================================
// TYPING EFFECT (OPTIONAL)
// ===================================
const typingText = document.querySelector('.typing-text');
if (typingText) {
    const text = typingText.textContent;
    typingText.textContent = '';
    let i = 0;
    
    function typeWriter() {
        if (i < text.length) {
            typingText.textContent += text.charAt(i);
            i++;
            setTimeout(typeWriter, 50);
        }
    }
    
    // Start typing after a brief delay
    setTimeout(typeWriter, 500);
}

// ===================================
// GLITCH EFFECT ON HOVER (HERO TITLE)
// ===================================
const heroTitle = document.querySelector('.hero-title');
if (heroTitle) {
    heroTitle.addEventListener('mouseenter', () => {
        heroTitle.style.animation = 'none';
        setTimeout(() => {
            heroTitle.style.animation = 'glow-pulse 2s ease-in-out infinite';
        }, 10);
    });
}

// ===================================
// RANDOM MATRIX-STYLE BACKGROUND (OPTIONAL)
// ===================================
function createMatrixEffect() {
    const canvas = document.createElement('canvas');
    canvas.style.position = 'fixed';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.pointerEvents = 'none';
    canvas.style.zIndex = '0';
    canvas.style.opacity = '0.05';
    
    document.body.prepend(canvas);
    
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    
    const chars = '01';
    const fontSize = 14;
    const columns = canvas.width / fontSize;
    const drops = Array(Math.floor(columns)).fill(1);
    
    function draw() {
        ctx.fillStyle = 'rgba(10, 10, 15, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = '#00d9ff';
        ctx.font = fontSize + 'px monospace';
        
        for (let i = 0; i < drops.length; i++) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }
    
    setInterval(draw, 50);
    
    // Resize handler
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// Uncomment to enable matrix effect
// createMatrixEffect();

// ===================================
// CONSOLE EASTER EGG
// ===================================
console.log('%c[aerobytes]', 'color: #00d9ff; font-size: 24px; font-weight: bold;');
console.log('%cLooking at the source? Nice! ðŸ”', 'color: #a855f7; font-size: 14px;');
console.log('%cIf you found something interesting, let me know!', 'color: #9898b3; font-size: 12px;');
// ===================================
// ROTATING TEXT EFFECT FOR LANDING PAGE
// ===================================
document.addEventListener('DOMContentLoaded', function() {
    const rotatingTextElement = document.querySelector('.rotating-text');
    
    if (rotatingTextElement) {
        const roles = [
            'intelligence analyst',
            'security researcher',
            'cybersecurity'
        ];
        
        let currentIndex = 0;
        let charIndex = 0;
        let isDeleting = false;
        let typingSpeed = 100;
        
        function typeWriter() {
            const currentRole = roles[currentIndex];
            
            if (!isDeleting && charIndex <= currentRole.length) {
                // Typing
                rotatingTextElement.textContent = currentRole.substring(0, charIndex);
                charIndex++;
                typingSpeed = 100;
            } else if (isDeleting && charIndex >= 0) {
                // Deleting
                rotatingTextElement.textContent = currentRole.substring(0, charIndex);
                charIndex--;
                typingSpeed = 50;
            }
            
            // When done typing current word
            if (!isDeleting && charIndex > currentRole.length) {
                // Pause before deleting
                typingSpeed = 2000;
                isDeleting = true;
            }
            
            // When done deleting
            if (isDeleting && charIndex < 0) {
                isDeleting = false;
                currentIndex = (currentIndex + 1) % roles.length;
                typingSpeed = 500;
            }
            
            setTimeout(typeWriter, typingSpeed);
        }
        
        // Start typing effect after a brief delay
        setTimeout(typeWriter, 1000);
    }
});

// ===================================
// LIVE CLOCK FOR SYSTEM STATUS
// ===================================
function updateClock() {
    const clockElement = document.getElementById('current-time');
    if (clockElement) {
        const now = new Date();
        const hours = String(now.getUTCHours()).padStart(2, '0');
        const minutes = String(now.getUTCMinutes()).padStart(2, '0');
        const seconds = String(now.getUTCSeconds()).padStart(2, '0');
        clockElement.textContent = `${hours}:${minutes}:${seconds} UTC`;
    }
}

// Update clock every second
if (document.getElementById('current-time')) {
    updateClock();
    setInterval(updateClock, 1000);
}

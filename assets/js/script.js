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
    const cursorElement = document.querySelector('.cursor');
    
    if (rotatingTextElement && cursorElement) {
        const roles = [
            'intelligence analyst',
            'security researcher',
            'threat hunter',
            'ctf competitor'
        ];
        
        let currentIndex = 0;
        let charIndex = 0;
        let isDeleting = false;
        let typingSpeed = 100;
        
        // Hide the separate cursor element
        cursorElement.style.display = 'none';
        
        function typeWriter() {
            const currentRole = roles[currentIndex];
            
            if (!isDeleting && charIndex <= currentRole.length) {
                // Typing - add inline cursor
                rotatingTextElement.innerHTML = currentRole.substring(0, charIndex) + '<span class="cursor">_</span>';
                charIndex++;
                typingSpeed = 100;
            } else if (isDeleting && charIndex >= 0) {
                // Deleting - keep inline cursor
                rotatingTextElement.innerHTML = currentRole.substring(0, charIndex) + '<span class="cursor">_</span>';
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

// ===================================
// IMAGE LIGHTBOX FOR WRITEUPS
// ===================================
document.addEventListener('DOMContentLoaded', function() {
    if (!document.querySelector('.writeup-content')) return;
    
    const lightbox = document.createElement('div');
    lightbox.className = 'image-lightbox';
    lightbox.innerHTML = '<span class="image-lightbox-close">&times;</span><img src="" alt="">';
    document.body.appendChild(lightbox);
    
    const lightboxImg = lightbox.querySelector('img');
    const closeBtn = lightbox.querySelector('.image-lightbox-close');
    const images = document.querySelectorAll('.writeup-content img');
    
    images.forEach(img => {
        img.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            lightboxImg.src = this.src;
            lightbox.classList.add('active');
            document.body.style.overflow = 'hidden';
        });
    });
    
    closeBtn.addEventListener('click', closeLightbox);
    lightbox.addEventListener('click', function(e) {
        if (e.target === lightbox || e.target === closeBtn) {
            closeLightbox();
        }
    });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && lightbox.classList.contains('active')) {
            closeLightbox();
        }
    });
    
    function closeLightbox() {
        lightbox.classList.remove('active');
        document.body.style.overflow = '';
    }
});

// ===================================
// PROMPT HIGHLIGHTING FOR WRITEUPS
// ===================================
document.addEventListener('DOMContentLoaded', function() {
    if (!document.querySelector('.writeup-content')) return;

    document.querySelectorAll('.writeup-content pre code').forEach(function(block) {
        block.innerHTML = block.innerHTML.replace(
            /(aero@aerobytes:~\$)/g,
            '<span style="color: var(--cyber-pink); font-weight: 700;">$1</span>'
        );
    });
});

// ===================================
// SPA NAVIGATION (keeps Aerotunes alive)
// ===================================
(function() {
    var EXCLUDED_PATHS = ['/resume/'];
    var currentPath = window.location.pathname;

    function isExcluded(href) {
        // External links
        if (href.startsWith('http://') || href.startsWith('https://')) return true;
        // Hash-only links
        if (href.startsWith('#')) return true;
        // Excluded paths
        for (var i = 0; i < EXCLUDED_PATHS.length; i++) {
            if (href === EXCLUDED_PATHS[i] || href.startsWith(EXCLUDED_PATHS[i])) return true;
        }
        return false;
    }

    function getInternalHref(anchor) {
        var href = anchor.getAttribute('href');
        if (!href) return null;
        if (anchor.target === '_blank') return null;
        if (isExcluded(href)) return null;
        // Only intercept same-origin links
        if (href.startsWith('/') || href.startsWith('./') || href.startsWith('../')) return href;
        return null;
    }

    function updateActiveNavLink(path) {
        document.querySelectorAll('.nav-link').forEach(function(link) {
            var linkPath = link.getAttribute('href');
            link.classList.toggle('active', linkPath === path);
        });
    }

    function cleanupWriteupStyles() {
        // Remove any inline style blocks injected by writeup layout
        var existing = document.getElementById('spa-writeup-style');
        if (existing) existing.remove();

        // Reset scan-line and cyber-grid to default state
        var scanLine = document.querySelector('.scan-line');
        var cyberGrid = document.querySelector('.cyber-grid');
        if (scanLine) scanLine.style.display = '';
        if (cyberGrid) cyberGrid.style.opacity = '';
    }

    function applyWriteupStyles(doc) {
        // Find any <style> blocks in the fetched content
        var styles = doc.querySelectorAll('#spa-content style');
        styles.forEach(function(style) {
            var tag = document.createElement('style');
            tag.id = 'spa-writeup-style';
            tag.textContent = style.textContent;
            document.head.appendChild(tag);
            style.remove();
        });
    }

    function reinitPage() {
        // Intersection observer for fade-in animations
        var observerOpts = {
            threshold: 0.1,
            rootMargin: '0px 0px -100px 0px'
        };
        var obs = new IntersectionObserver(function(entries) {
            entries.forEach(function(entry) {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }
            });
        }, observerOpts);

        document.querySelectorAll('.section, .project-card, .writeup-item').forEach(function(el) {
            if (el.closest('.writeup-page')) return;
            el.style.opacity = '0';
            el.style.transform = 'translateY(30px)';
            el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
            obs.observe(el);
        });

        // Image lightbox
        if (document.querySelector('.writeup-content')) {
            var existing = document.querySelector('.image-lightbox');
            if (existing) existing.remove();

            var lightbox = document.createElement('div');
            lightbox.className = 'image-lightbox';
            lightbox.innerHTML = '<span class="image-lightbox-close">&times;</span><img src="" alt="">';
            document.body.appendChild(lightbox);

            var lightboxImg = lightbox.querySelector('img');
            var closeBtn = lightbox.querySelector('.image-lightbox-close');

            document.querySelectorAll('.writeup-content img').forEach(function(img) {
                img.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    lightboxImg.src = this.src;
                    lightbox.classList.add('active');
                    document.body.style.overflow = 'hidden';
                });
            });

            closeBtn.addEventListener('click', closeLb);
            lightbox.addEventListener('click', function(e) {
                if (e.target === lightbox || e.target === closeBtn) closeLb();
            });

            function closeLb() {
                lightbox.classList.remove('active');
                document.body.style.overflow = '';
            }

            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && lightbox.classList.contains('active')) closeLb();
            });
        }

        // Prompt highlighter
        if (document.querySelector('.writeup-content')) {
            document.querySelectorAll('.writeup-content pre code').forEach(function(block) {
                block.innerHTML = block.innerHTML.replace(
                    /(aero@aerobytes:~\$)/g,
                    '<span style="color: var(--cyber-pink); font-weight: 700;">$1</span>'
                );
            });
        }

        // Rotating text (index page only)
        var rotatingEl = document.querySelector('.rotating-text');
        var cursorEl = document.querySelector('.cursor');
        if (rotatingEl && cursorEl) {
            var roles = ['intelligence analyst', 'security researcher', 'threat hunter', 'ctf competitor'];
            var idx = 0, charIdx = 0, deleting = false, speed = 100;
            cursorEl.style.display = 'none';

            function typeIt() {
                var role = roles[idx];
                if (!deleting && charIdx <= role.length) {
                    rotatingEl.innerHTML = role.substring(0, charIdx) + '<span class="cursor">_</span>';
                    charIdx++;
                    speed = 100;
                } else if (deleting && charIdx >= 0) {
                    rotatingEl.innerHTML = role.substring(0, charIdx) + '<span class="cursor">_</span>';
                    charIdx--;
                    speed = 50;
                }
                if (!deleting && charIdx > role.length) { speed = 2000; deleting = true; }
                if (deleting && charIdx < 0) { deleting = false; idx = (idx + 1) % roles.length; speed = 500; }
                setTimeout(typeIt, speed);
            }
            setTimeout(typeIt, 1000);
        }

        // Live clock (index page only)
        var clockEl = document.getElementById('current-time');
        if (clockEl) {
            function tick() {
                var now = new Date();
                clockEl.textContent =
                    String(now.getUTCHours()).padStart(2,'0') + ':' +
                    String(now.getUTCMinutes()).padStart(2,'0') + ':' +
                    String(now.getUTCSeconds()).padStart(2,'0') + ' UTC';
            }
            tick();
            setInterval(tick, 1000);
        }

        // Smooth scroll for in-page hash links
        document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                var target = document.querySelector(this.getAttribute('href'));
                if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
        });

        // Re-attach SPA intercept to any new links in the swapped content
        attachLinkInterceptors();
    }

    function navigateTo(href, pushState) {
        fetch(href)
            .then(function(res) {
                if (!res.ok) throw new Error('fetch failed');
                return res.text();
            })
            .then(function(html) {
                var parser = new DOMParser();
                var doc = parser.parseFromString(html, 'text/html');

                var newMain = doc.querySelector('#spa-content');
                if (!newMain) {
                    // Fallback: just do a normal navigation
                    window.location.href = href;
                    return;
                }

                var newTitle = doc.title;

                // Clean up any writeup-specific styles from previous page
                cleanupWriteupStyles();

                // Swap content
                var currentMain = document.querySelector('#spa-content');
                currentMain.innerHTML = newMain.innerHTML;

                // Apply any styles from the new page (writeup layout injects a <style> block)
                applyWriteupStyles(currentMain);

                // Update browser history and title
                if (pushState) {
                    window.history.pushState({ path: href }, newTitle, href);
                }
                document.title = newTitle;
                currentPath = href;

                // Scroll to top
                window.scrollTo(0, 0);

                // Update active nav state
                updateActiveNavLink(href);

                // Re-initialize page scripts
                reinitPage();
            })
            .catch(function() {
                // Network error or something unexpected, fall back to normal navigation
                window.location.href = href;
            });
    }

    function attachLinkInterceptors() {
        // Nav links and logo
        document.querySelectorAll('.nav-link, .logo').forEach(function(anchor) {
            // Remove old listener by cloning (simplest approach for nav which is always present)
        });

        // Use event delegation on the whole document so we catch nav + any in-content links
        // (delegation is already set up once at init, so this function is a no-op after first run)
    }

    // Single delegated listener on document — handles all clicks, present and future
    document.addEventListener('click', function(e) {
        var anchor = e.target.closest('a');
        if (!anchor) return;

        var href = getInternalHref(anchor);
        if (!href) return;

        // Don't intercept if it's the same page
        if (href === currentPath || href === currentPath + '/') return;

        e.preventDefault();
        navigateTo(href, true);
    });

    // Handle browser back/forward buttons
    window.addEventListener('popstate', function(e) {
        var path = window.location.pathname;
        if (isExcluded(path)) {
            window.location.reload();
            return;
        }
        navigateTo(path, false);
    });

    // Set initial active nav link
    updateActiveNavLink(currentPath);

})();

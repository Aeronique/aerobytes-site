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
const ASCII_ART = [
  `:;;;i11LCLfLCLiLti;::,,:;:::::::::::;::;:;;::::;:;;;;:::;;;;`,
  `:;;iitiCCLfCLL:fL11ii;;ii;;i;;;;:::::::::::::::::;::::::i;;;`,
  `:::;ii1L;,,:tCiifL111ii11ii1iiii;;;::::::::::::::;::::::;:i;`,
  `::::;:;i:;;,1f;,LGi11i11t111iiiiii;;;:::::::;;;::ii::;;;;:ii`,
  `:,::;1,;;:::f1:;CGii11ii:..    ..,,;iii;;;;:;;;:;i1;:;;;;;;;`,
  `;:::;Lti;:;iC0fL08111:     ..        .,;iii;;;;:;1t;;;;;;;;i`,
  `;::;1CLi;:;1LCG880f1;         .,,.   ,.  ,1i;;;;;1fiiii;iiii`,
  `:;;f8G.::,,:;1888ti,.            ..:L88L. ,tiiiiitL1ii1ii111`,
  `:;i1tt,,:.,::ittLi,.            .ifG88@@t .it1iiifCfLCf11f11`,
  `;;;,,,:;;;;;i;,;i,.           :tLt11;1G01 ,itt1fLC0G8@Lttf1t`,
  `iii,:,,...,;;;:ii.      .,:. ,tC0GLLCG0C  .;tttLLfLL0@Cffftf`,
  `ii1::::;;;i;:i;11,      .;i,.iitL08@8GC0L .ittt1t11ftLLLLffL`,
  `111::::;ii;iitft:           :tLLfCCCGCLL;.;iCL1ifLt1;LLCLfLL`,
  `111:;,,.if1i1tti,            ,ifLC0CfLL; .:ii;;:;CCtt0LGCGGG`,
  `111:11;it111tffi.     :i:,.    .;tL080L  .:;:,..,ii1iGttttf0`,
  `;,,;;i1i1;i11ti:      .itft;, .;,  ,;i,   ,:ii;:;,;t1G1i1f1G`,
  `,:,;;i11fiittt:.       ..,;tt. ....       ::;ii;,:tLtC1;ittG`,
  `,:;;;;11ffL1;:,... .. .:;t;         .,  .;:i:i;:,,tCG0Cffft0`,
  `...;i;ttttf1::,.,.  .  ,,it1,       ,. ,.;iii;...:ffL0Cffff0`,
  `.  ;;;11ti;i11,.       ,,.,,;i:    ,   ,;i;11i,.,ifL00Cti1tC`,
  `...:;;11i11;:;.         .,.,.;::  ,    ,11ii1ii;;ttG00ftt1LG`,
  `.:::;itt;1: ,.    ....,:::;;:: :. :   .;;1i;ii;;ttLCCCfffLGG`,
  `.,,,:1ti1:  :.    .,:1ttt1ii1, .1 .:  .:iii;ii;;i;;1ffftfLCC`,
  `:,,:;111i     ..  .,:ttttftit; :t1.:;..,i11iiii;;;;1LCttCfff`,
  `:::;i111,    ;:    . ..,,,,;1:  :1t.:,..it1i11ii;itLCLfLCttG`,
  `.,,;1ii:.   ,,         .,:;:i:  .,ti ;.;i;ii;;:;;;1fffLLLLC8`,
  `,::it1;,,             .,::ii;.   ;,t.,;11t1i1iii1;i1i1ii1L8@`,
  `:;:ftt;..     .,       ,ii:;;,  :, ;i ttttt1t11111111t1;1tLf`,
  `:;it1i;       ..        1t:.,, ,.. .:.fi::::;:......,fCLfttt`,
  `;it;ii:                 ,ft,:.      .,;.        1t1;,:i;;;L0`,
  `i11,ii:        .,        ,:.,.       ,,;i11:,tfi,;t1;  ,..:C`,
];

console.log('%c[aerobytes]', 'color: #00d9ff; font-size: 24px; font-weight: bold; font-family: monospace;');
console.log('%c' + ASCII_ART.join('\n'), 'color: #a855f7; font-size: 10px; line-height: 1.1; font-family: monospace;');
console.log('%cLooking at the source? Nice! 🔍', 'color: #a855f7; font-size: 14px; font-family: monospace;');
console.log('%cIf you found something interesting, reach out:', 'color: #9898b3; font-size: 12px;');
console.log('%caeroni que@proton.me', 'color: #ff1493; font-size: 13px; font-weight: bold;');
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
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('current-time')) {
        updateClock();
        setInterval(updateClock, 1000);
    }
});

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

// ===================================
// AEROTUNES MUSIC PLAYER
// ===================================
(function() {
    var YT_VIDEO_ID = '0w80F8FffQ4';
    var BAR_COUNT = 32;
    var playing = false;
    var ytPlayer = null;
    var ytReady = false;
    var rafId = null;
    var bars = [];
    var barData = [];
    var volume = 80;

    function buildPlayer() {
        // Don't build twice
        if (document.getElementById('aerotunesBtn')) return;

        // Floating button
        var btn = document.createElement('button');
        btn.className = 'aerotunes-btn';
        btn.id = 'aerotunesBtn';
        btn.setAttribute('aria-label', 'Open Aerotunes music player');
        btn.innerHTML = '<i class="fas fa-music"></i>';
        btn.addEventListener('click', togglePanel);
        document.body.appendChild(btn);

        // Panel
        var panel = document.createElement('div');
        panel.className = 'aerotunes-panel';
        panel.id = 'aerotunesPanel';
        panel.innerHTML =
            '<div class="aerotunes-topbar">' +
                '<span>/bin/aerotunes</span>' +
                '<div class="aerotunes-dots">' +
                    '<div class="aerotunes-dot aerotunes-dot-1"></div>' +
                    '<div class="aerotunes-dot aerotunes-dot-2"></div>' +
                    '<div class="aerotunes-dot aerotunes-dot-3"></div>' +
                '</div>' +
            '</div>' +
            '<div class="aerotunes-body">' +
                '<div class="aerotunes-viz" id="aerotunesViz"></div>' +
                '<div class="aerotunes-np-label">NOW PLAYING</div>' +
                '<div class="aerotunes-np-title">lofi hip hop radio &mdash; beats to study to</div>' +
                '<div class="aerotunes-np-sub">&#9658; streaming via aerotunes</div>' +
                '<div class="aerotunes-controls">' +
                    '<button class="aerotunes-play-btn" id="aerotunesPlayBtn" aria-label="Play or pause">' +
                        '<i class="fas fa-play"></i>' +
                    '</button>' +
                    '<button class="aerotunes-close-btn" id="aerotunesCloseBtn" aria-label="Close player">&#x2715;</button>' +
                '</div>' +
                '<div class="aerotunes-vol-row">' +
                    '<span class="aerotunes-vol-label">vol</span>' +
                    '<div class="aerotunes-vol-track" id="aerotunesVolTrack">' +
                        '<div class="aerotunes-vol-fill" id="aerotunesVolFill"></div>' +
                    '</div>' +
                    '<span class="aerotunes-vol-label" id="aerotunesVolPct">80%</span>' +
                '</div>' +
            '</div>' +
            '<div class="aerotunes-footer">' +
                '<span class="aerotunes-footer-tag">&#9672; AEROTUNES</span>' +
                '<span id="aerotunesStatus">click &#9658; to begin</span>' +
            '</div>';
        document.body.appendChild(panel);

        // Hidden YouTube iframe container
        var ytWrap = document.createElement('div');
        ytWrap.className = 'aerotunes-yt';
        ytWrap.innerHTML = '<div id="aerotunesYT"></div>';
        document.body.appendChild(ytWrap);

        // Wire up controls
        document.getElementById('aerotunesPlayBtn').addEventListener('click', togglePlay);
        document.getElementById('aerotunesCloseBtn').addEventListener('click', closePanel);

        // Volume track click
        document.getElementById('aerotunesVolTrack').addEventListener('click', function(e) {
            var rect = this.getBoundingClientRect();
            var pct = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
            volume = Math.round(pct * 100);
            document.getElementById('aerotunesVolFill').style.width = volume + '%';
            document.getElementById('aerotunesVolPct').textContent = volume + '%';
            if (ytPlayer && ytReady) ytPlayer.setVolume(volume);
        });

        buildBars();
        loadYouTubeAPI();
    }

    function buildBars() {
        var viz = document.getElementById('aerotunesViz');
        for (var i = 0; i < BAR_COUNT; i++) {
            var bar = document.createElement('div');
            bar.className = 'aerotunes-bar';
            viz.appendChild(bar);
            bars.push(bar);
            barData.push({
                cur: 4 + Math.random() * 6,
                min: 4 + Math.random() * 6,
                max: 22 + Math.random() * 40,
                dir: 1,
                speed: 0.7 + Math.random() * 2.2
            });
        }
    }

    function animateBars() {
        barData.forEach(function(d, i) {
            d.cur += d.dir * d.speed * (0.4 + Math.random() * 1.4);
            if (d.cur >= d.max) { d.cur = d.max; d.dir = -1; }
            if (d.cur <= d.min) { d.cur = d.min; d.dir = 1; }
            bars[i].style.height = d.cur + 'px';
            bars[i].classList.add('playing');
        });
        rafId = requestAnimationFrame(animateBars);
    }

    function stopBars() {
        if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
        bars.forEach(function(bar, i) {
            bar.style.height = barData[i].min + 'px';
            bar.classList.remove('playing');
        });
    }

    function togglePanel() {
        var panel = document.getElementById('aerotunesPanel');
        var btn = document.getElementById('aerotunesBtn');
        if (panel.classList.contains('open')) {
            panel.classList.remove('open');
            btn.classList.remove('panel-open');
        } else {
            panel.classList.add('open');
            btn.classList.add('panel-open');
        }
    }

    function closePanel() {
        document.getElementById('aerotunesPanel').classList.remove('open');
        document.getElementById('aerotunesBtn').classList.remove('panel-open');
        if (playing) pauseAudio();
    }

    function togglePlay() {
        if (playing) { pauseAudio(); } else { playAudio(); }
    }

    function playAudio() {
        playing = true;
        var btn = document.getElementById('aerotunesPlayBtn');
        btn.innerHTML = '<i class="fas fa-pause"></i>';
        btn.classList.add('active');
        document.getElementById('aerotunesStatus').textContent = 'streaming...';
        if (ytPlayer && ytReady) { ytPlayer.setVolume(volume); ytPlayer.playVideo(); }
        animateBars();
    }

    function pauseAudio() {
        playing = false;
        var btn = document.getElementById('aerotunesPlayBtn');
        btn.innerHTML = '<i class="fas fa-play"></i>';
        btn.classList.remove('active');
        document.getElementById('aerotunesStatus').textContent = 'paused';
        if (ytPlayer && ytReady) ytPlayer.pauseVideo();
        stopBars();
    }

    function loadYouTubeAPI() {
        if (window.YT && window.YT.Player) { initYTPlayer(); return; }
        var existing = document.querySelector('script[src*="youtube.com/iframe_api"]');
        if (!existing) {
            var tag = document.createElement('script');
            tag.src = 'https://www.youtube.com/iframe_api';
            document.head.appendChild(tag);
        }
    }

    function initYTPlayer() {
        ytPlayer = new YT.Player('aerotunesYT', {
            videoId: YT_VIDEO_ID,
            playerVars: { autoplay: 0, controls: 0, disablekb: 1, fs: 0, modestbranding: 1, rel: 0 },
            events: {
                onReady: function() {
                    ytReady = true;
                    ytPlayer.setVolume(volume);
                },
                onStateChange: function(e) {
                    if (e.data === YT.PlayerState.ENDED) {
                        ytPlayer.seekTo(0);
                        ytPlayer.playVideo();
                    }
                }
            }
        });
    }

    // Called by YouTube API when ready
    var existingYTReady = window.onYouTubeIframeAPIReady;
    window.onYouTubeIframeAPIReady = function() {
        if (existingYTReady) existingYTReady();
        initYTPlayer();
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', buildPlayer);
    } else {
        buildPlayer();
    }
})();

// ===================================
// KONAMI CODE — MATRIX RAIN SPLASH
// ===================================
(function() {
    var KONAMI = [38,38,40,40,37,39,37,39,66,65];
    var pos = 0;

    document.addEventListener('keydown', function(e) {
        if (e.keyCode === KONAMI[pos]) {
            pos++;
            if (pos === KONAMI.length) {
                pos = 0;
                triggerMatrixSplash();
            }
        } else {
            pos = 0;
        }
    });

    function triggerMatrixSplash() {
        var existing = document.getElementById('konamiCanvas');
        if (existing) return;

        var canvas = document.createElement('canvas');
        canvas.id = 'konamiCanvas';
        canvas.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:99999;pointer-events:none;opacity:0;transition:opacity 0.3s ease;';
        document.body.appendChild(canvas);

        var ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        var colors = ['#00d9ff', '#a855f7', '#ff1493', '#ff00ff'];
        var fontSize = 14;
        var columns = Math.floor(canvas.width / fontSize);
        var drops = Array(columns).fill(0).map(function() { return Math.random() * -50; });

        requestAnimationFrame(function() { canvas.style.opacity = '1'; });

        var interval = setInterval(function() {
            ctx.fillStyle = 'rgba(10, 10, 15, 0.08)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            for (var i = 0; i < drops.length; i++) {
                var char = String.fromCharCode(0x30A0 + Math.floor(Math.random() * 96));
                ctx.fillStyle = colors[Math.floor(Math.random() * colors.length)];
                ctx.font = fontSize + 'px monospace';
                ctx.fillText(char, i * fontSize, drops[i] * fontSize);
                if (drops[i] * fontSize > canvas.height && Math.random() > 0.97) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }, 40);

        setTimeout(function() {
            canvas.style.opacity = '0';
            setTimeout(function() {
                clearInterval(interval);
                canvas.remove();
            }, 400);
        }, 4000);
    }
})();

// ===================================
// SUDO EASTER EGG
// ===================================
(function() {
    var buffer = '';
    document.addEventListener('keydown', function(e) {
        if (e.key.length === 1) {
            buffer += e.key;
            if (buffer.length > 10) buffer = buffer.slice(-10);
            if (buffer.toLowerCase().includes('sudo')) {
                buffer = '';
                console.log('%c$ sudo su', 'color: #00d9ff; font-family: monospace; font-size: 13px;');
                setTimeout(function() {
                    console.log('%cPassword:', 'color: #9898b3; font-family: monospace; font-size: 13px;');
                }, 400);
                setTimeout(function() {
                    console.log('%cPermission denied.', 'color: #ff1493; font-family: monospace; font-size: 13px;');
                }, 1200);
                setTimeout(function() {
                    console.log('%cNice try though. 😏', 'color: #a855f7; font-family: monospace; font-size: 13px;');
                }, 1800);
            }
        }
    });
})();

// ===================================
// FOOTER TERMINAL
// ===================================
(function() {
    var FILES = {
        'resume.pdf':          'file',
        'definitely_not_malware.sh': 'file',
        'todo.txt':            'file',
        'secret.txt':          'file',
        'flag.txt':            'file',
        '.bashrc':             'hidden',
        '.you_found_me.txt':   'hidden',
        '.flag.txt':           'hidden',
    };

    var FILE_CONTENTS = {
        'secret.txt':        'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
        'todo.txt':          '1. world domination\n2. get hired in threat intel\n3. touch grass\n4. repeat step 1',
        'definitely_not_malware.sh': '#!/bin/bash\n# totally normal script\necho "just vibing"',
        'flag.txt':          'FLAG{y0u_f0und_m3_n0w_h1r3_m3}',
        '.you_found_me.txt': 'okay fine. you\\'re good.\n\naeroni que@proton.me',
        '.flag.txt':         'FLAG{ls_-la_gang_represent}',
        '.bashrc':           'alias ls="ls --color=auto"\nalias cls="clear"\nalias hacker="echo \\"i am in\\""\nexport COFFEE_LEVEL=critical',
    };

    var PROCESSES = [
        'PID   USER       COMMAND',
        '1     root       /sbin/init',
        '42    aero       threat_hunting.py --target=all',
        '314   aero       coffee_dependency.service --level=critical',
        '420   aero       clarinet_practice.sh --scales --forever',
        '666   aero       definitely_not_hacking.exe (wine)',
        '1337  aero       ctf_solver.py --autopwn --plz',
        '2048  aero       wazuh_siem --watching_everything',
        '9000  root       its_over_9000.sh',
        '9001  aero       vim (not exiting, send help)',
    ];

    var history = [];
    var historyIdx = -1;
    var initialized = false;

    function initTerminal() {
        if (initialized) return;
        initialized = true;

        var prompt = document.getElementById('footerPrompt');
        var terminal = document.getElementById('footerTerminal');
        var input = document.getElementById('footerTerminalInput');
        var output = document.getElementById('footerTerminalOutput');

        if (!prompt || !terminal || !input || !output) return;

        prompt.addEventListener('click', function() {
            terminal.style.display = terminal.style.display === 'none' ? 'block' : 'none';
            if (terminal.style.display === 'block') {
                if (output.children.length === 0) {
                    addLine(output, 'Terminal initialized. Type "help" to get started.', '#00d9ff');
                }
                setTimeout(function() { input.focus(); }, 50);
            }
        });

        input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                var cmd = input.value.trim();
                if (!cmd) return;
                history.unshift(cmd);
                historyIdx = -1;
                addLine(output, 'aero@aerobytes:~$ ' + cmd, '#ff1493');
                handleCommand(cmd.toLowerCase(), output);
                input.value = '';
                terminal.scrollTop = terminal.scrollHeight;
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (historyIdx < history.length - 1) {
                    historyIdx++;
                    input.value = history[historyIdx];
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIdx > 0) {
                    historyIdx--;
                    input.value = history[historyIdx];
                } else {
                    historyIdx = -1;
                    input.value = '';
                }
            }
        });
    }

    function addLine(output, text, color) {
        var line = document.createElement('div');
        line.style.cssText = 'font-family: var(--font-mono); font-size: 0.8rem; line-height: 1.5; white-space: pre-wrap; word-break: break-all;';
        line.style.color = color || '#e8e8f0';
        line.textContent = text;
        output.appendChild(line);
    }

    function handleCommand(cmd, output) {
        if (cmd === 'help') {
            addLine(output, 'available commands:', '#00d9ff');
            addLine(output, '  whoami       find out who runs this place');
            addLine(output, '  ls           list files');
            addLine(output, '  ls -la       list all files (including hidden)');
            addLine(output, '  ps aux       check what\'s running');
            addLine(output, '  cat <file>   read a file');
            addLine(output, '  clear        clear terminal');
            addLine(output, '  exit         close terminal');

        } else if (cmd === 'whoami') {
            addLine(output, 'aeronique (michelle duell)', '#a855f7');
            addLine(output, 'intelligence analyst → cybersecurity');
            addLine(output, 'blue team | threat intel | CTF competitor');
            addLine(output, 'GFACT · GSEC · GCIH (98%) · TAISE');
            addLine(output, '1st place WiCyS 2026 CTF · 2nd place Target x WiCyS Cyber Defense');
            addLine(output, '5th place SANS Holiday Hack Challenge 2025');
            addLine(output, '');
            addLine(output, 'contact: aeroni que@proton.me', '#ff1493');

        } else if (cmd === 'ls') {
            var visible = Object.keys(FILES).filter(function(f) { return FILES[f] === 'file'; });
            addLine(output, visible.join('  '), '#00d9ff');

        } else if (cmd === 'ls -la') {
            addLine(output, 'total 48', '#9898b3');
            Object.keys(FILES).forEach(function(f) {
                var hidden = FILES[f] === 'hidden';
                var color = hidden ? '#a855f7' : '#e8e8f0';
                addLine(output, '-rw-r--r--  aero  aero  ' + f, color);
            });

        } else if (cmd === 'ps aux') {
            PROCESSES.forEach(function(p, i) {
                addLine(output, p, i === 0 ? '#00d9ff' : '#e8e8f0');
            });

        } else if (cmd.startsWith('cat ')) {
            var filename = cmd.slice(4).trim();
            if (FILE_CONTENTS[filename]) {
                var content = FILE_CONTENTS[filename];
                if (filename === 'secret.txt') {
                    addLine(output, content, '#ff1493');
                    addLine(output, '(you know what to do)', '#9898b3');
                } else {
                    addLine(output, content, '#e8e8f0');
                }
            } else if (Object.keys(FILES).indexOf(filename) !== -1) {
                addLine(output, 'cat: ' + filename + ': binary file, cannot display', '#9898b3');
            } else {
                addLine(output, 'cat: ' + filename + ': no such file or directory', '#ff4444');
            }

        } else if (cmd === 'clear') {
            document.getElementById('footerTerminalOutput').innerHTML = '';

        } else if (cmd === 'exit') {
            document.getElementById('footerTerminal').style.display = 'none';

        } else if (cmd.startsWith('sudo')) {
            addLine(output, 'Password:', '#9898b3');
            setTimeout(function() {
                addLine(output, 'Permission denied. Nice try though. 😏', '#ff4444');
                document.getElementById('footerTerminal').scrollTop = 99999;
            }, 800);

        } else if (cmd === 'rm -rf /') {
            addLine(output, 'lol no.', '#ff1493');

        } else {
            addLine(output, 'bash: ' + cmd + ': command not found', '#ff4444');
            addLine(output, 'try "help" for available commands', '#9898b3');
        }
    }

    // Wait for DOM, then init once
    document.addEventListener('DOMContentLoaded', function() {
        initTerminal();
    });
})();

/**
 * Velo Theme Manager
 * Handles Light/Dark mode transitions
 */

const ThemeManager = {
    init() {
        this.toggleBtn = document.getElementById('themeToggle');
        this.html = document.documentElement;
        this.iconSun = document.querySelector('.icon-sun');
        this.iconMoon = document.querySelector('.icon-moon');

        // Check local storage or system preference
        const savedTheme = localStorage.getItem('velo-theme');
        const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

        if (savedTheme) {
            this.setTheme(savedTheme);
        } else {
            this.setTheme(systemDark ? 'dark' : 'light');
        }

        if (this.toggleBtn) {
            this.toggleBtn.addEventListener('click', () => this.toggle());
        }
    },

    setTheme(theme) {
        this.html.setAttribute('data-theme', theme);
        localStorage.setItem('velo-theme', theme);
        this.updateIcons(theme);
    },

    toggle() {
        const current = this.html.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';

        // Add transition class to body temporarily for smooth color switch
        document.body.classList.add('theme-transition');
        this.setTheme(next);

        setTimeout(() => {
            document.body.classList.remove('theme-transition');
        }, 500);
    },

    updateIcons(theme) {
        if (!this.iconSun || !this.iconMoon) return;

        if (theme === 'dark') {
            this.iconSun.style.display = 'block';
            this.iconMoon.style.display = 'none';
        } else {
            this.iconSun.style.display = 'none';
            this.iconMoon.style.display = 'block';
        }
    }
};

document.addEventListener('DOMContentLoaded', () => ThemeManager.init());

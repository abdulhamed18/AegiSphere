/**
 * AegiSphere — Toast Notification System
 * Shows brief notifications in the top-right corner.
 * Auto-dismiss after 3 seconds with fade animation.
 */
(function () {
    'use strict';

    var TOAST_DURATION = 3000;
    var containerId = 'aegis-toast-container';

    function getContainer() {
        var c = document.getElementById(containerId);
        if (!c) {
            c = document.createElement('div');
            c.id = containerId;
            c.className = 'fixed top-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none';
            c.style.maxWidth = '380px';
            document.body.appendChild(c);
        }
        return c;
    }

    /**
     * Show a toast notification.
     * @param {string} message - The toast message
     * @param {string} type - 'success' | 'error' | 'info'
     */
    function showToast(message, type) {
        type = type || 'success';
        var container = getContainer();

        var toast = document.createElement('div');
        toast.className = 'pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-md border shadow-lg transition-all duration-300 transform translate-x-full opacity-0';

        // Style by type
        if (type === 'error') {
            toast.classList.add('bg-red-950/90', 'border-red-800', 'text-red-200');
        } else if (type === 'info') {
            toast.classList.add('bg-zinc-800/95', 'border-zinc-600', 'text-zinc-200');
        } else {
            toast.classList.add('bg-zinc-800/95', 'border-zinc-700', 'text-zinc-200');
        }

        // Icon
        var iconSvg = '';
        if (type === 'success') {
            iconSvg = '<svg class="w-4 h-4 text-emerald-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"/></svg>';
        } else if (type === 'error') {
            iconSvg = '<svg class="w-4 h-4 text-red-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z"/></svg>';
        } else {
            iconSvg = '<svg class="w-4 h-4 text-zinc-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="m11.25 11.25.041-.02a.75.75 0 0 1 1.063.852l-.708 2.836a.75.75 0 0 0 1.063.853l.041-.021M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-3.75h.008v.008H12V8.25Z"/></svg>';
        }

        toast.innerHTML = iconSvg + '<span class="text-sm">' + message + '</span>';
        container.appendChild(toast);

        // Animate in
        requestAnimationFrame(function () {
            requestAnimationFrame(function () {
                toast.classList.remove('translate-x-full', 'opacity-0');
                toast.classList.add('translate-x-0', 'opacity-100');
            });
        });

        // Auto dismiss
        setTimeout(function () {
            toast.classList.remove('translate-x-0', 'opacity-100');
            toast.classList.add('translate-x-full', 'opacity-0');
            setTimeout(function () {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        }, TOAST_DURATION);
    }

    // Expose
    window.AegisToast = { show: showToast };

    // Auto-convert Django messages to toasts on page load
    document.addEventListener('DOMContentLoaded', function () {
        var messagesDiv = document.getElementById('django-messages-data');
        if (messagesDiv) {
            var msgs;
            try {
                msgs = JSON.parse(messagesDiv.textContent);
            } catch (e) { return; }
            if (Array.isArray(msgs)) {
                msgs.forEach(function (m, i) {
                    setTimeout(function () {
                        showToast(m.message, m.tags === 'error' ? 'error' : 'success');
                    }, i * 200);
                });
            }
        }
    });
})();

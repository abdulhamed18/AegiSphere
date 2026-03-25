/**
 * AegiSphere — Modal Component
 * Reusable modal system with support for API key secure display and invite links.
 */
(function () {
    'use strict';

    /**
     * Open a modal by ID.
     */
    function openModal(modalId) {
        var modal = document.getElementById(modalId);
        if (!modal) return;
        modal.classList.remove('hidden');
        modal.classList.add('flex');
        // Fade in backdrop
        requestAnimationFrame(function () {
            modal.querySelector('.modal-backdrop')?.classList.add('opacity-100');
            modal.querySelector('.modal-content')?.classList.add('opacity-100', 'scale-100');
            modal.querySelector('.modal-content')?.classList.remove('opacity-0', 'scale-95');
        });
    }

    /**
     * Close a modal by ID.
     */
    function closeModal(modalId) {
        var modal = document.getElementById(modalId);
        if (!modal) return;
        var content = modal.querySelector('.modal-content');
        if (content) {
            content.classList.remove('opacity-100', 'scale-100');
            content.classList.add('opacity-0', 'scale-95');
        }
        setTimeout(function () {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }, 150);
    }

    /**
     * Show the secure API key modal with countdown timer.
     * @param {string} rawKey - The raw API key to display
     */
    function showSecureKeyModal(rawKey) {
        var modal = document.getElementById('secure-key-modal');
        if (!modal) return;

        var keyDisplay = modal.querySelector('#secure-key-display');
        var timerDisplay = modal.querySelector('#secure-key-timer');
        var copyBtn = modal.querySelector('#secure-key-copy-btn');

        if (keyDisplay) keyDisplay.textContent = rawKey;

        openModal('secure-key-modal');

        // Countdown
        var remaining = 60;
        if (timerDisplay) timerDisplay.textContent = remaining + 's';

        var interval = setInterval(function () {
            remaining--;
            if (timerDisplay) timerDisplay.textContent = remaining + 's';
            if (remaining <= 0) {
                clearInterval(interval);
                closeModal('secure-key-modal');
            }
        }, 1000);

        // Copy button
        if (copyBtn) {
            var handler = function () {
                navigator.clipboard.writeText(rawKey).then(function () {
                    window.AegisToast && window.AegisToast.show('API key copied to clipboard', 'success');
                    clearInterval(interval);
                    closeModal('secure-key-modal');
                });
                copyBtn.removeEventListener('click', handler);
            };
            // Remove old handlers by replacing node
            var newBtn = copyBtn.cloneNode(true);
            copyBtn.parentNode.replaceChild(newBtn, copyBtn);
            newBtn.addEventListener('click', handler);
        }

        // Store interval to clear on manual close
        modal._keyInterval = interval;
    }

    /**
     * Show the invite link modal.
     * @param {string} inviteUrl - The full invite URL
     */
    function showInviteModal(inviteUrl) {
        var modal = document.getElementById('invite-link-modal');
        if (!modal) return;

        var urlDisplay = modal.querySelector('#invite-url-display');
        var copyBtn = modal.querySelector('#invite-url-copy-btn');

        if (urlDisplay) urlDisplay.textContent = inviteUrl;

        openModal('invite-link-modal');

        if (copyBtn) {
            var handler = function () {
                navigator.clipboard.writeText(inviteUrl).then(function () {
                    window.AegisToast && window.AegisToast.show('Invite link copied to clipboard', 'success');
                });
            };
            var newBtn = copyBtn.cloneNode(true);
            copyBtn.parentNode.replaceChild(newBtn, copyBtn);
            newBtn.addEventListener('click', handler);
        }
    }

    // Close modal on backdrop click
    document.addEventListener('click', function (e) {
        if (e.target.classList.contains('modal-backdrop')) {
            var modal = e.target.closest('[data-modal]');
            if (modal) {
                if (modal._keyInterval) clearInterval(modal._keyInterval);
                closeModal(modal.id);
            }
        }
    });

    // Close on ESC
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            var modals = document.querySelectorAll('[data-modal]:not(.hidden)');
            modals.forEach(function (modal) {
                if (modal._keyInterval) clearInterval(modal._keyInterval);
                closeModal(modal.id);
            });
        }
    });

    // Expose
    window.AegisModal = {
        open: openModal,
        close: closeModal,
        showSecureKey: showSecureKeyModal,
        showInviteLink: showInviteModal
    };
})();

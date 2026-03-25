/**
 * AegiSphere — Tab Navigation Component
 * Lightweight vanilla JS tab system using Tailwind utility classes.
 */
(function () {
    'use strict';

    function initTabs(containerSelector) {
        var container = document.querySelector(containerSelector);
        if (!container) return;

        var buttons = container.querySelectorAll('[data-tab-btn]');
        var panels = container.querySelectorAll('[data-tab-panel]');

        if (!buttons.length || !panels.length) return;

        function activateTab(tabId) {
            // Deactivate all buttons
            buttons.forEach(function (btn) {
                btn.classList.remove('border-zinc-200', 'text-zinc-100');
                btn.classList.add('border-transparent', 'text-zinc-500');
            });

            // Hide all panels
            panels.forEach(function (panel) {
                panel.classList.add('hidden');
                panel.classList.remove('block');
            });

            // Activate target button
            var targetBtn = container.querySelector('[data-tab-btn="' + tabId + '"]');
            if (targetBtn) {
                targetBtn.classList.remove('border-transparent', 'text-zinc-500');
                targetBtn.classList.add('border-zinc-200', 'text-zinc-100');
            }

            // Show target panel
            var targetPanel = container.querySelector('[data-tab-panel="' + tabId + '"]');
            if (targetPanel) {
                targetPanel.classList.remove('hidden');
                targetPanel.classList.add('block');
            }

            // Store active tab in session (survives page within same session)
            try {
                sessionStorage.setItem('aegis_org_tab', tabId);
            } catch (e) { /* ignore */ }
        }

        // Bind click events
        buttons.forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                var tabId = btn.getAttribute('data-tab-btn');
                activateTab(tabId);
            });
        });

        // Restore last active tab or default to first
        var savedTab = null;
        try {
            savedTab = sessionStorage.getItem('aegis_org_tab');
        } catch (e) { /* ignore */ }

        var validTab = false;
        if (savedTab) {
            var panel = container.querySelector('[data-tab-panel="' + savedTab + '"]');
            if (panel) validTab = true;
        }

        if (validTab) {
            activateTab(savedTab);
        } else {
            var firstBtn = buttons[0];
            if (firstBtn) {
                activateTab(firstBtn.getAttribute('data-tab-btn'));
            }
        }
    }

    // Auto-init on DOMContentLoaded
    document.addEventListener('DOMContentLoaded', function () {
        initTabs('#org-tabs-container');
    });

    // Expose globally for manual init
    window.AegisTabs = { init: initTabs };
})();

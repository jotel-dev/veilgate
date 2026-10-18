/**
 * VeilGate Client Scripts
 * Privacy-first: no trackers, no external requests, no analytics.
 */

(function () {
    'use strict';

    // --- Theme Management ---
    function initTheme() {
        var stored = localStorage.getItem('veilgate-theme');
        var theme = stored;
        if (!theme) {
            theme = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
        }
        document.documentElement.setAttribute('data-theme', theme);

        var toggleBtn = document.getElementById('theme-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', function () {
                var current = document.documentElement.getAttribute('data-theme') || 'dark';
                var next = current === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', next);
                localStorage.setItem('veilgate-theme', next);
            });
        }
    }

    // --- Copy Buttons Helper ---
    function initCopyButtons() {
        var buttons = [
            document.getElementById('copy-address-btn'),
            document.getElementById('copy-link-btn')
        ];

        buttons.forEach(function (btn) {
            if (!btn) return;
            btn.addEventListener('click', function () {
                var text = btn.getAttribute('data-copy-text') || btn.getAttribute('data-address') || btn.getAttribute('data-uri');
                if (!text) return;

                navigator.clipboard.writeText(text).then(function () {
                    var originalHtml = btn.innerHTML;
                    btn.textContent = 'Copied!';
                    btn.classList.add('btn-success');
                    setTimeout(function () {
                        btn.innerHTML = originalHtml;
                        btn.classList.remove('btn-success');
                    }, 2000);
                }).catch(function () {
                    // Fallback selection if clipboard api fails
                    var addrElem = document.getElementById('shielded-address-text');
                    if (addrElem) {
                        var range = document.createRange();
                        range.selectNodeContents(addrElem);
                        var sel = window.getSelection();
                        sel.removeAllRanges();
                        sel.addRange(range);
                    }
                });
            });
        });
    }

    // --- Remaining Time Countdown Helper ---
    function updateRemainingTime() {
        var elem = document.getElementById('pay-expiry-remaining');
        if (!elem) return;
        var expiresAt = parseInt(elem.getAttribute('data-expires-at'), 10);
        if (!expiresAt) return;
        var nowSec = Math.floor(Date.now() / 1000);
        var diff = expiresAt - nowSec;
        if (diff <= 0) {
            elem.textContent = ' (expired)';
        } else {
            var hours = Math.floor(diff / 3600);
            var mins = Math.floor((diff % 3600) / 60);
            if (hours > 0) {
                elem.textContent = ' (expires in ' + hours + ' h ' + mins + ' min)';
            } else {
                elem.textContent = ' (expires in ' + mins + ' min)';
            }
        }
    }

    // --- Format Zatoshis to ZEC ---
    function formatZec(zatoshis) {
        var whole = Math.floor(zatoshis / 100000000);
        var frac = zatoshis % 100000000;
        if (frac === 0) {
            return whole + '.0 ZEC';
        }
        var s = ('00000000' + frac).slice(-8);
        s = s.replace(/0+$/, '');
        return whole + '.' + s + ' ZEC';
    }

    // --- Payment Status Polling ---
    function initPaymentPolling() {
        var container = document.getElementById('pay-container');
        if (!container) return;

        var publicId = container.getAttribute('data-public-id');
        if (!publicId) return;

        var statusBadge = document.getElementById('pay-status-badge');
        var statusDesc = document.getElementById('pay-status-desc');
        var receivedElem = document.getElementById('pay-received-amount');

        var pollInterval = 4000;
        var poller = null;

        function checkStatus() {
            fetch('/api/invoice/' + encodeURIComponent(publicId) + '/status', {
                headers: { 'Accept': 'application/json' }
            })
            .then(function (res) {
                if (!res.ok) throw new Error('Status request failed');
                return res.json();
            })
            .then(function (data) {
                if (!data || !statusBadge) return;

                var state = data.state;
                var amount = data.amount;
                var received = data.received;
                var confsRemaining = data.confirmations_remaining;

                if (receivedElem && typeof received === 'number') {
                    receivedElem.textContent = formatZec(received);
                }

                if (state === 'paid') {
                    statusBadge.className = 'status-pill status-paid';
                    statusBadge.textContent = 'Paid';
                    if (statusDesc) {
                        statusDesc.textContent = 'Payment confirmed on-chain. Invoice is complete.';
                    }
                    if (poller) clearInterval(poller);
                } else if (state === 'payment_detected') {
                    statusBadge.className = 'status-pill status-detected';
                    var confText = confsRemaining === 1 ? '1 confirmation remaining' : confsRemaining + ' confirmations remaining';
                    statusBadge.textContent = 'Payment detected (' + confText + ')';
                    if (statusDesc) {
                        statusDesc.textContent = 'Payment detected in recent blocks. Awaiting confirmation...';
                    }
                } else if (state === 'underpaid') {
                    statusBadge.className = 'status-pill status-underpaid';
                    var missing = amount > received ? amount - received : 0;
                    statusBadge.textContent = 'Underpaid (missing ' + formatZec(missing) + ')';
                    if (statusDesc) {
                        statusDesc.textContent = 'Partial payment received. Please send the remaining balance.';
                    }
                } else if (state === 'expired') {
                    statusBadge.className = 'status-pill status-expired';
                    statusBadge.textContent = 'Expired';
                    if (statusDesc) {
                        statusDesc.textContent = 'This invoice has expired. Do not send funds to this address.';
                    }
                    if (poller) clearInterval(poller);
                } else {
                    // awaiting_payment
                    statusBadge.className = 'status-pill status-awaiting';
                    statusBadge.textContent = 'Awaiting payment';
                }
                updateRemainingTime();
            })
            .catch(function () {
                // Silently ignore transient network poll errors
            });
        }

        poller = setInterval(checkStatus, pollInterval);
    }

    // --- DOM Ready Hook ---
    function onReady() {
        initTheme();
        initCopyButtons();
        updateRemainingTime();
        setInterval(updateRemainingTime, 5000);
        initPaymentPolling();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', onReady);
    } else {
        onReady();
    }
})();

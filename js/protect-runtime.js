/* global window, document, localStorage, crypto, TextEncoder, TextDecoder, Fluid, CONFIG */

(function() {
  'use strict';

  var STORAGE_KEY = 'eyeberry-protect-unlock-v1';
  var STORAGE_PLAIN_KEY = STORAGE_KEY + ':plain';
  var encoder = new TextEncoder();
  var decoder = new TextDecoder();

  function qs(selector) {
    return document.querySelector(selector);
  }

  function qsa(selector) {
    return Array.prototype.slice.call(document.querySelectorAll(selector));
  }

  function fromBase64(base64) {
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function toBase64(bytes) {
    var chars = [];
    for (var i = 0; i < bytes.length; i += 1) {
      chars.push(String.fromCharCode(bytes[i]));
    }
    return btoa(chars.join(''));
  }

  async function sha256Base64(text) {
    var digest = await crypto.subtle.digest('SHA-256', encoder.encode(text));
    return toBase64(new Uint8Array(digest));
  }

  async function deriveAesKey(password, saltBase64, iterations) {
    var passwordKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: fromBase64(saltBase64),
        iterations: iterations,
        hash: 'SHA-256'
      },
      passwordKey,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['decrypt']
    );
  }

  async function decryptPayload(payload, password) {
    var key = await deriveAesKey(password, payload.salt, payload.iterations);
    var decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: fromBase64(payload.iv)
      },
      key,
      fromBase64(payload.ciphertext)
    );
    return JSON.parse(decoder.decode(decrypted));
  }

  function setStatus(message, isError) {
    var status = qs('[data-protect-status]');
    if (!status) {
      return;
    }
    status.textContent = message || '';
    status.classList.toggle('protect-error', !!isError);
  }

  function revealProtectedNodes() {
    qsa('[data-protect-hide]').forEach(function(node) {
      node.removeAttribute('data-protect-hide');
    });
  }

  function restoreAssets(assetMap) {
    var keys = Object.keys(assetMap || {});
    keys.forEach(function(key) {
      qsa('[data-protect-asset="' + key + '"]').forEach(function(node) {
        if (node.tagName === 'IMG' || node.tagName === 'SOURCE') {
          node.setAttribute('src', assetMap[key]);
          node.removeAttribute('srcset');
          node.removeAttribute('lazyload');
        } else if (node.tagName === 'A') {
          node.setAttribute('href', assetMap[key]);
        }
      });
    });
  }

  function injectContent(payload) {
    var contentTarget = qs('[data-protect-content-target]');
    if (contentTarget) {
      contentTarget.innerHTML = payload.html || '';
    }

    restoreAssets(payload.assets || {});

    qsa('[data-protect-title]').forEach(function(node) {
      node.textContent = payload.title || node.textContent;
    });

    qsa('[data-protect-subtitle]').forEach(function(node) {
      node.setAttribute('title', payload.title || '');
      if (node.id !== 'subtitle') {
        node.textContent = payload.title || '';
      }
    });

    qsa('[data-protect-comments]').forEach(function(node) {
      node.removeAttribute('data-protect-comments');
    });

    revealProtectedNodes();
    var gate = qs('[data-protect-gate]');
    if (gate) {
      gate.classList.add('d-none');
    }
    if (window.tocbot) {
      window.tocbot.destroy();
    }
    if (window.Fluid && Fluid.plugins) {
      CONFIG.anchorjs.enable && Fluid.plugins.initAnchor();
      CONFIG.toc.enable && Fluid.plugins.initTocBot();
      CONFIG.image_zoom.enable && Fluid.plugins.initFancyBox();
      CONFIG.copy_btn && Fluid.plugins.initCopyCode();
    }
    document.body.classList.add('protect-unlocked');
  }

  function shouldReuseStoredHash(expectedHash) {
    try {
      return localStorage.getItem(STORAGE_KEY) === expectedHash;
    } catch (error) {
      return false;
    }
  }

  function persistHash(hash) {
    try {
      localStorage.setItem(STORAGE_KEY, hash);
    } catch (error) {
      // ignore storage failures
    }
  }

  function persistPassword(password) {
    try {
      localStorage.setItem(STORAGE_PLAIN_KEY, password);
    } catch (error) {
      // ignore storage failures
    }
  }

  function readStoredPassword() {
    try {
      return localStorage.getItem(STORAGE_PLAIN_KEY) || '';
    } catch (error) {
      return '';
    }
  }

  async function fetchPayload(url) {
    var response = await fetch(url, { credentials: 'same-origin' });
    if (!response.ok) {
      throw new Error('Failed to load protected payload.');
    }
    return response.json();
  }

  async function unlock(password, options) {
    var payload = await fetchPayload(options.payloadPath);
    var decrypted = await decryptPayload(payload, password);
    injectContent(decrypted);
    var hash = await sha256Base64(password + '::' + options.siteSalt);
    persistHash(hash);
    persistPassword(password);
    setStatus('');
  }

  function installPageGate() {
    var optionsNode = qs('script[data-protect-page-options]');
    if (!optionsNode) {
      return Promise.resolve();
    }

    var options = JSON.parse(optionsNode.textContent);
    var form = qs('[data-protect-form]');
    var input = qs('[data-protect-input]');

    async function tryStoredHash() {
      if (!shouldReuseStoredHash(options.passwordHash)) {
        return false;
      }

      var password = '';
      try {
        password = window.sessionStorage.getItem(STORAGE_PLAIN_KEY) || '';
      } catch (error) {
        password = '';
      }
      if (!password) {
        password = readStoredPassword();
      }
      if (!password) {
        return false;
      }

      try {
        await unlock(password, options);
        return true;
      } catch (error) {
        return false;
      }
    }

    return tryStoredHash().then(function(unlocked) {
      if (unlocked) {
        return;
      }

      form.addEventListener('submit', async function(event) {
        event.preventDefault();
        setStatus('Decrypting...', false);
        try {
          await unlock(input.value, options);
          try {
            window.sessionStorage.setItem(STORAGE_PLAIN_KEY, input.value);
          } catch (error) {
            // ignore session storage failures
          }
        } catch (error) {
          setStatus('Incorrect password.', true);
        }
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function() {
    installPageGate().catch(function(error) {
      setStatus('Failed to initialize protected content.', true);
    });
  });
})();

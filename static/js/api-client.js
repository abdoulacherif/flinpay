/**
 * api-client.js — Client fetch global avec gestion automatique
 * de l'expiration de session (401).
 */
"use strict";

(function() {
  const originalFetch = window.fetch;

  window.fetch = async function(...args) {
    const response = await originalFetch.apply(this, args);

    // Si 401 sur une route API → session expirée ou révoquée
    if (response.status === 401) {
      const url = typeof args[0] === 'string' ? args[0] : (args[0]?.url || '');
      
      // On ne redirige PAS si on est déjà sur /login ou si c'est un endpoint de login
      const isAuthEndpoint = url.includes('/api/login') || 
                             url.includes('/api/register') ||
                             url.includes('/api/forgot-password') ||
                             url.includes('/api/reset-password');
      const isAuthPage = window.location.pathname === '/login' || 
                         window.location.pathname === '/register';

      if (!isAuthEndpoint && !isAuthPage) {
        // Éviter les redirections multiples
        if (!window.__sessionExpiredHandled) {
          window.__sessionExpiredHandled = true;
          window.location.href = '/login?expired=1';
        }
      }
    }

    return response;
  };
})();